"""Exercise whole-tree formatting and braces, and changed-line advisory lint."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest


SOURCE, LLVM_BIN = (Path(arg).resolve() for arg in sys.argv[1:])
FORMATTED = 'int example() {\n    int Old = 3;\n    int Value = 4;\n    return Old + Value;\n}\n'


class StyleChecks(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name).resolve()
        self.env = dict(os.environ, LLVM_CONFIG=str(LLVM_BIN / 'llvm-config'), GIT_CONFIG_NOSYSTEM='1',
                        GIT_CONFIG_GLOBAL=os.devnull)
        for key in ('LLVM_DIR', 'FORGE_STYLE_BASE', 'CMAKE_ARGS', 'MAKEFLAGS', 'MFLAGS', 'MAKEOVERRIDES'):
            self.env.pop(key, None)
        for file in ('CMakeLists.txt', 'Makefile', '.clang-format', '.clang-tidy', '.gitignore'):
            shutil.copyfile(SOURCE / file, self.root / file)
        for folder in ('cmake', 'src'):
            shutil.copytree(SOURCE / folder, self.root / folder)
        self.file = self.root / 'src/legacy.cpp'
        self.file.write_text(FORMATTED)
        self.header = self.root / 'src/model.h'
        self.header.write_text('#pragma once\ninline int value() { return 3; }\n')
        self.caller = self.root / 'src/sample.cpp'
        self.caller.write_text('#include "model.h"\nint readValue() { return value(); }\n')
        self.run_command('git', 'init', '-q')
        self.run_command('git', 'add', '.')
        self.run_command('git', '-c', 'user.name=Test', '-c', 'user.email=test@localhost',
                         'commit', '-qm', 'baseline')
        self.run_command('git', 'update-ref', 'refs/remotes/origin/main', 'HEAD')

    def run_command(self, *args, success=True, env=None):
        p = subprocess.run(args, cwd=self.root, env=env or self.env, text=True,
                           stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        self.assertEqual(p.returncode == 0, success, f'{args}\n{p.stdout}')
        return p.stdout

    def test_whole_tree_formatting_and_entry_points(self):
        self.run_command('cmake', '-S', '.', '-B', 'build', '-DBUILD_TESTING=OFF')
        target = ('cmake', '--build', 'build', '--target')
        bad = FORMATTED.replace('    int Value', '  int Value')
        self.file.write_text(bad)
        self.run_command('git', '-c', 'user.name=Test', '-c', 'user.email=test@localhost',
                         'commit', '-qam', 'incorrect indentation')
        env = dict(self.env, FORGE_STYLE_BASE='unknown-base')
        for command in (('make',), target):
            with self.subTest(command=command):
                self.file.write_text(bad)
                for check in ('format-check', 'format-audit'):
                    output = self.run_command(*command, check, success=False, env=env)
                    self.assertIn('src/legacy.cpp:', output)
                    self.assertEqual(self.file.read_text(), bad)
                self.run_command(*command, 'format', env=env)
                self.assertEqual(self.file.read_text(), FORMATTED)
                changes = self.run_command('git', 'diff')
                self.run_command(*command, 'format', env=env)
                self.assertEqual(self.run_command('git', 'diff'), changes)
                self.run_command(*command, 'format-check', env=env)

    def test_file_selection(self):
        renamed = self.root / 'src/renamed file.cpp'
        self.run_command('git', 'mv', self.file, renamed)
        self.header.unlink()
        for directory in ('build', 'src/generated', 'src/third_party', 'tests/support/vendor'):
            folder = self.root / directory
            folder.mkdir(parents=True)
            (folder / 'ignored.cpp').write_text('int  x;\n')
        self.run_command('make', 'format-check')
        renamed.write_text(FORMATTED.replace('Value = 4', 'Value=5'))
        new = self.root / 'src/new.cpp'
        new.write_text('int  Other;\n')
        output = self.run_command('make', 'format-check', success=False)
        self.assertIn('src/new.cpp:1:', output)
        self.assertIn('src/renamed file.cpp:3:', output)
        self.run_command('make', 'format')
        self.assertEqual(new.read_text(), 'int Other;\n')
        self.assertEqual(renamed.read_text(), FORMATTED.replace('Value = 4', 'Value = 5'))
        self.assertEqual((self.root / 'src/third_party/ignored.cpp').read_text(), 'int  x;\n')

    def test_quality_commands_reject_wrong_tool_version(self):
        tools = self.root / 'decoy'
        tools.mkdir()
        config = tools / 'llvm-config'
        config.write_text(f'#!/bin/sh\nif [ "$1" = --bindir ]; then dirname "$0"; '
                          f'else exec "{LLVM_BIN / "llvm-config"}" "$@"; fi\n')
        config.chmod(0o755)
        for action, name in (('format-check', 'clang-format'), ('lint', 'clang-tidy')):
            tool = tools / name
            tool.write_text('#!/bin/sh\necho "LLVM version 23.1.50"\n')
            tool.chmod(0o755)
            output = self.run_command('make', action, f'LLVM_CONFIG={config}', success=False)
            self.assertIn('23.1.5', output)
            self.assertIn('23.1.50', output)

    def test_fixture_brace_probe(self):
        fixture = self.root / 'tests/differential/fixtures/example.c'
        fixture.parent.mkdir(parents=True)
        bodies = ('if (N) ++N;', 'if (N) { ++N; } else --N;', 'for (; N;) --N;',
                  'while (N) --N;', 'do --N; while (N);')
        for body in bodies:
            with self.subTest(body=body):
                fixture.write_text('int example(int N) {\n  ' + body + '\n  return N;\n}\n')
                self.run_command('make', 'format')
                before = fixture.read_bytes()
                self.assertIn('add braces', self.run_command('make', 'format-check', success=False))
                self.assertEqual(before, fixture.read_bytes())
        fixture.write_text('int example(int N) {\n    while (N) {\n        --N;\n    }\n    return N;\n}\n')
        self.run_command('make', 'format-check')

        legacy = 'void f(int N) {\n  if (N == 1 ||\n      N == 2)\n    --N;\n  ++N;\n}\n'
        fixture.write_text(legacy)
        self.run_command('make', 'format')
        self.run_command('git', 'add', fixture)
        self.run_command('git', '-c', 'user.name=Test', '-c', 'user.email=test@localhost',
                         'commit', '-qm', 'legacy multiline control flow')
        env = dict(self.env, FORGE_STYLE_BASE='HEAD')
        self.assertIn('add braces', self.run_command('make', 'format-check', env=env, success=False))

    def test_header_lint_and_full_analysis(self):
        # The lint driver receives validated translation units from quality.cmake.
        db = self.root / 'compile_commands.json'
        db.write_text(json.dumps([{'directory': str(self.root), 'file': str(self.caller),
                                   'arguments': [str(LLVM_BIN / 'clang++'), '-std=c++20',
                                                 '-c', str(self.caller)]}]))
        command = (sys.executable, '-B', 'cmake/lint.py', LLVM_BIN.parent / 'include',
                   LLVM_BIN / 'clang-tidy', '-p', self.root, self.caller)
        self.header.write_text('#pragma once\ninline int value(int lower = 3) { return lower ? 2 : lower ? 1 : 0; }\n')
        advisories = self.run_command(*command)
        for check in ('readability-identifier-naming', 'readability-avoid-nested-conditional-operator'):
            self.assertIn(check, advisories)
        self.run_command('git', '-c', 'user.name=Test', '-c', 'user.email=test@localhost',
                         'commit', '-qam', 'existing advisories')
        self.header.write_text(self.header.read_text() + 'inline int newValue(int new_name) { return new_name; }\n')
        advisories = self.run_command(*command, env=dict(self.env, FORGE_STYLE_BASE='HEAD'))
        self.assertIn('readability-identifier-naming', advisories)
        self.assertNotIn("parameter 'lower'", advisories)
        self.assertNotIn('readability-avoid-nested-conditional-operator', advisories)
        for body in ('if (N) --N;', 'if (N) { ++N; } else --N;', 'for (; N;) --N;',
                     'while (N) --N;', 'do --N; while (N);'):
            with self.subTest(body=body):
                self.header.write_text('#pragma once\ninline int value(int N = 3) {\n  ' + body + '\n  return N;\n}\n')
                self.assertIn('readability-braces-around-statements', self.run_command(*command, success=False))
        self.run_command('git', '-c', 'user.name=Test', '-c', 'user.email=test@localhost',
                         'commit', '-qam', 'existing unbraced body')
        self.assertIn('readability-braces-around-statements', self.run_command(*command, success=False,
                      env=dict(self.env, FORGE_STYLE_BASE='HEAD')))
        self.caller.write_text('#include "model.h"\nint readValue() { int *P = nullptr; return *P; }\n')
        self.run_command('git', 'add', self.caller)
        self.run_command('git', '-c', 'user.name=Test', '-c', 'user.email=test@localhost',
                         'commit', '-qm', 'existing diagnostic')
        self.header.write_text('#pragma once\ninline int value() { return 4; }\n')
        self.assertIn('clang-analyzer-core.NullDereference', self.run_command(*command, success=False,
                      env=dict(self.env, FORGE_STYLE_BASE='HEAD')))


if __name__ == '__main__':
    unittest.main(argv=[sys.argv[0]])
