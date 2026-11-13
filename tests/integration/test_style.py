"""Exercise the formatting and lint policies with the selected LLVM tools."""
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
        self.root = Path(temp.name).resolve() / 'src' / 'forge'
        self.root.mkdir(parents=True)
        self.env = dict(os.environ, LLVM_CONFIG=str(LLVM_BIN / 'llvm-config'), GIT_CONFIG_NOSYSTEM='1',
                        GIT_CONFIG_GLOBAL=os.devnull)
        for key in ('LLVM_DIR', 'FORGE_STYLE_BASE', 'CMAKE_ARGS', 'MAKEFLAGS', 'MFLAGS', 'MAKEOVERRIDES'):
            self.env.pop(key, None)
        for file in ('CMakeLists.txt', 'Makefile', '.clang-format', '.clang-tidy', '.gitignore'):
            shutil.copyfile(SOURCE / file, self.root / file)
        shutil.copytree(SOURCE / 'cmake', self.root / 'cmake')
        (self.root / 'src').mkdir()
        self.file = self.root / 'src/legacy.cpp'
        self.file.write_text(FORMATTED)
        self.header = self.root / 'src/model.h'
        self.header.write_text('#pragma once\n\ninline int value() { return 3; }\n')
        self.caller = self.root / 'src/sample.cpp'
        self.caller.write_text('#include "model.h"\n\nint readValue() { return value(); }\n')
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

    def fixture_lint_command(self):
        # Supply both native translation units to the real make lint entry point.
        flags = [str(LLVM_BIN / 'clang++'), '-std=c++20', '-I', str(self.root),
                 '-isystem', str(LLVM_BIN.parent / 'include')]
        if sys.platform == 'darwin':
            flags.extend(['-isysroot', self.run_command('xcrun', '--sdk', 'macosx', '--show-sdk-path').strip()])
        db = self.root / 'compile_commands.json'
        db.write_text(json.dumps([{'directory': str(self.root), 'file': str(path),
                                   'arguments': [*flags, '-c', str(path)]}
                                  for path in (self.file, self.caller)]))
        return ('make', 'lint', f'LINT_DATABASE={db}')

    def test_whole_function_and_lifetime_advisories(self):
        command = self.fixture_lint_command()
        self.header.write_text('inline int score(int Value) {\n    return Value;\n}\n')
        included = ('src/generated', 'src/third_party', 'tests/support/vendor',
                    'tests/differential/fixtures', 'tests/support', 'tests/unit')
        paths = []
        for index, directory in enumerate(included):
            path = self.root / directory / f'helper{index}.h'
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(f'inline void helper{index}() {{ return; }}\n')
            paths.append(path)
        self.caller.write_text(
            '#include "../src/model.h"\n' +
            ''.join(f'#include "{path.relative_to(self.root)}"\n' for path in paths) +
            '#include <llvm/ADT/Twine.h>\n'
            'std::string label(int Value) {\n'
            '    llvm::Twine Label = llvm::Twine("label") + llvm::Twine(Value);\n'
            '    return Label.str();\n}\n'
            'int choose(int Value) {\n'
            '    if (Value > 0) { return score(Value); } else { return 0; }\n}\n')
        self.run_command('git', 'add', 'src', 'tests')
        self.run_command('git', '-c', 'user.name=Test', '-c', 'user.email=test@localhost',
                         'commit', '-qm', 'baseline advisory fixtures')
        # Seven nested conditions score 28. Only the function body changes.
        body = ''.join('    ' * n + f'if (Value > {n}) {{\n' for n in range(1, 8))
        body += '    ' * 8 + 'return 1;\n'
        body += ''.join('    ' * n + '}\n' for n in reversed(range(1, 8)))
        self.header.write_text(self.header.read_text().replace('    return Value;', body + '    return Value;'))
        env = dict(self.env, FORGE_STYLE_BASE='HEAD')
        before = self.run_command('git', 'diff')
        output = self.run_command(*command, env=env)
        for check in ('readability-function-cognitive-complexity', 'readability-function-size'):
            self.assertRegex(output, rf'model\.h:1:\d+: warning: .*\[{check}\]')
        self.assertRegex(output, r'model\.h:\d+:\d+: note: \+\d')
        for check in ('llvm-twine-local', 'readability-else-after-return'):
            self.assertRegex(output, rf'sample\.cpp:\d+:\d+: warning: .*\[{check}\]')
        for path in paths[-2:]:
            self.assertRegex(output, rf'{path.name}:1:\d+: warning: .*\[readability-redundant-control-flow\]')
        for path in paths[:-2]:
            self.assertNotIn(f'{path.name}:1:', output)
        self.assertEqual(self.run_command('git', 'diff'), before)

        with self.caller.open('a') as stream:
            stream.write('int broken() { int *Pointer = nullptr; return *Pointer; }\n')
        output = self.run_command(*command, success=False, env=env)
        self.assertIn('[readability-function-cognitive-complexity]', output)
        self.assertIn('clang-analyzer-core.NullDereference', output)

    def test_constant_naming(self):
        self.caller.write_text("""\
struct Bounds {
    const int origin;
    const int Extent;
    static constexpr int maxWidth = 16;
};

constexpr int defaultWidth = Bounds::maxWidth;
const int DefaultHeight = defaultWidth;

int measure(const int start, const int End) {
    constexpr int UnitSize = 8;
    constexpr int extraUnits = 1;
    const int distance = End - start;
    const int Size = distance * UnitSize;
    return Size + extraUnits;
}
""")
        output = self.run_command(*self.fixture_lint_command())
        for kind, accepted, rejected in (
                ('constant member', 'origin', 'Extent'),
                ('constant parameter', 'start', 'End'),
                ('local constant', 'distance', 'Size'),
                ('constexpr variable', 'extraUnits', 'UnitSize')):
            with self.subTest(kind=kind):
                self.assertIn(f"invalid case style for {kind} '{rejected}' [readability-identifier-naming]", output)
                self.assertNotIn(f"'{accepted}' [readability-identifier-naming]", output)
        for name in ('maxWidth', 'defaultWidth', 'DefaultHeight'):
            self.assertNotIn(f"'{name}' [readability-identifier-naming]", output)

    def test_invalid_lint_configuration_fails(self):
        command = self.fixture_lint_command()
        config = self.root / '.clang-tidy'
        original = config.read_text()
        for valid, invalid, diagnostic in (
                ('readability-else-after-return', 'readability-misspelled-check', 'unknown check'),
                ("LineThreshold: '80'", "LineThreshold: 'invalid'", 'clang-tidy-config')):
            with self.subTest(invalid=invalid):
                config.write_text(original.replace(valid, invalid))
                output = self.run_command(*command, success=False)
                self.assertIn(diagnostic, output)
                self.assertIn(invalid.split(':')[0], output)

    def test_whole_tree_formatting_and_entry_points(self):
        shutil.copytree(SOURCE / 'src', self.root / 'src', dirs_exist_ok=True)
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

    def test_namespace_indentation_and_paragraphs(self):
        self.file.write_bytes(b"""\
namespace forge {
namespace {
void report() {
const auto range = findRuntimeFunctionContainingAddress(Analysis.ExceptionDirectory.RuntimeFunctions, Address);

if (range) {
    printRange(range);
}


if (Verbose) {
    printDetails();
}
}
void finish() {}
} // namespace
} // namespace forge
""")
        expected = b"""\
namespace forge {
    namespace {
        void report() {
            const auto range = findRuntimeFunctionContainingAddress(
                Analysis.ExceptionDirectory.RuntimeFunctions, Address);

            if (range) {
                printRange(range);
            }

            if (Verbose) {
                printDetails();
            }
        }

        void finish() {}
    } // namespace
} // namespace forge
"""
        self.run_command('make', 'format')
        self.assertEqual(self.file.read_bytes(), expected)
        self.run_command('make', 'format')
        self.assertEqual(self.file.read_bytes(), expected)

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
        self.header.write_text('#pragma once\ninline int value(int OldValue = 3, int newValue = 1) {\n'
                               '    return OldValue ? 2 : newValue ? 1 : 0;\n}\n')
        advisories = self.run_command(*command)
        self.assertIn("invalid case style for parameter 'OldValue' [readability-identifier-naming]", advisories)
        self.assertNotIn("parameter 'newValue'", advisories)
        self.assertIn('readability-avoid-nested-conditional-operator', advisories)
        self.run_command('git', '-c', 'user.name=Test', '-c', 'user.email=test@localhost',
                         'commit', '-qam', 'existing advisories')
        self.header.write_text(self.header.read_text() + 'inline int newValue(int new_name) { return new_name; }\n')
        advisories = self.run_command(*command, env=dict(self.env, FORGE_STYLE_BASE='HEAD'))
        self.assertIn("invalid case style for parameter 'new_name' [readability-identifier-naming]", advisories)
        self.assertNotIn("parameter 'OldValue'", advisories)
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
