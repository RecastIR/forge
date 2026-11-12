"""Exercise the Make wrapper in disposable source and build directories."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

CMAKE, LLVM_DIR = map(Path, sys.argv[1:])
SOURCE = Path(__file__).resolve().parents[1]


class BuildConfig(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.tmp = Path(tmp.name)
        self.env = dict(os.environ, CMAKE_GENERATOR="Unix Makefiles")
        for key in ("MAKEFLAGS", "MFLAGS", "MAKEOVERRIDES", "LLVM_DIR", "CMAKE_ARGS", "CONFIG",
                    "BUILD_TESTING", "SANITIZE", "CMAKE_GENERATOR_PLATFORM", "CMAKE_GENERATOR_TOOLSET"):
            self.env.pop(key, None)
        self.env["PATH"] = str(CMAKE.parent) + os.pathsep + self.env["PATH"]

    def test_in_source_configure_preserves_makefile(self):
        for name, command in [("make", ["make", "configure", "BUILD_DIR=."]),
                              ("cmake", [CMAKE, "-S", ".", "-B", "."])]:
            with self.subTest(command=name):
                src = self.tmp / name
                src.mkdir()
                for file in ("CMakeLists.txt", "Makefile"):
                    shutil.copyfile(SOURCE / file, src / file)
                p = subprocess.run(command, cwd=src, env=self.env, capture_output=True)
                self.assertNotEqual(p.returncode, 0)
                self.assertIn(b"cmake -S . -B build", p.stderr)
                self.assertEqual((src / "Makefile").read_bytes(), (SOURCE / "Makefile").read_bytes())

    def test_cached_llvm_and_build_type(self):
        build = self.tmp / "build"
        # A second package path for the same real LLVM installation.
        package = self.tmp / "llvm package"
        package.mkdir()
        (package / "LLVMConfig.cmake").write_text(f"include([[{LLVM_DIR}/LLVMConfig.cmake]])\n")

        def configure(*options):
            subprocess.run(["make", "configure", f"BUILD_DIR={build}", *options],
                           cwd=SOURCE, env=self.env, check=True)
            lines = (build / "CMakeCache.txt").read_text().splitlines()
            return {line.split(":", 1)[0]: line.split("=", 1)[1] for line in lines
                    if line and not line.startswith(("#", "//")) and "=" in line}

        cache = configure(f"LLVM_DIR={package}", "CONFIG=Release")
        readobj = cache["llvm-readobj"]
        pinned = self.tmp / "pinned-readobj"
        pinned.symlink_to(readobj)
        cache = configure(f'CMAKE_ARGS="-Dllvm-readobj:FILEPATH={pinned}"')
        self.assertEqual(cache["LLVM_DIR"], str(package))
        self.assertEqual(cache["CMAKE_BUILD_TYPE"], "Release")
        self.assertEqual(cache["llvm-readobj"], str(pinned))
        cache = configure(f"LLVM_DIR={LLVM_DIR}")
        self.assertEqual(cache["LLVM_DIR"], str(LLVM_DIR))
        self.assertEqual(cache["llvm-readobj"], readobj)

    def test_lint_requires_real_commands_in_external_database(self):
        build = self.tmp / "analysis build"
        subprocess.run([CMAKE, "-S", SOURCE, "-B", build, f"-DLLVM_DIR={LLVM_DIR}",
                        "-DBUILD_TESTING=OFF", "-DCMAKE_EXPORT_COMPILE_COMMANDS=ON"],
                       env=self.env, check=True)
        database = build / "compile_commands.json"
        contents = database.read_bytes()
        entries = json.loads(contents)
        harness = SOURCE / "tests/native_harness.cpp"
        self.assertIn(str(harness), [e["file"] for e in entries])

        # Exercise the wrapper even on machines without clang-tidy.
        config = self.tmp / "llvm-config"
        config.write_text('#!/bin/sh\ndirname "$0"\n')
        config.chmod(0o755)
        tidy = self.tmp / "clang-tidy"
        tidy.write_text('#!/bin/sh\nprintf "%s\\n" "$@" > "$0.args"\n')
        tidy.chmod(0o755)
        command = ["make", "lint", f"LLVM_CONFIG={config}", f"LINT_DATABASE={database}"]
        subprocess.run(command, cwd=SOURCE, env=self.env, check=True)
        args = (self.tmp / "clang-tidy.args").read_text().splitlines()
        self.assertEqual(args[:2], ["-p", str(build)])
        self.assertCountEqual(args[2:], [str(p) for p in (SOURCE / "src").glob("*.cpp")] + [str(harness)])
        self.assertEqual(database.read_bytes(), contents)

        database.write_text(json.dumps([e for e in entries if e["file"] != str(harness)]))
        failed = subprocess.run(command, cwd=SOURCE, env=self.env, capture_output=True, text=True)
        self.assertNotEqual(failed.returncode, 0)
        self.assertIn("Missing first-party compile commands", failed.stderr)
        self.assertIn("native_harness.cpp", failed.stderr)


if __name__ == "__main__":
    unittest.main(argv=[sys.argv[0]])
