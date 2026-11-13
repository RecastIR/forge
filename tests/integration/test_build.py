"""Exercise the Make wrapper in disposable source and build directories."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

SOURCE, CMAKE, LLVM_DIR, LLVM_BIN = map(Path, sys.argv[1:])


class BuildConfig(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.tmp = Path(tmp.name).resolve()
        self.env = dict(os.environ, CMAKE_GENERATOR="Unix Makefiles")
        for key in ("MAKEFLAGS", "MFLAGS", "MAKEOVERRIDES", "LLVM_DIR", "LLVM_CONFIG", "CMAKE_ARGS", "CONFIG",
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

    def run_configure(self, *options, env=None):
        return subprocess.run([CMAKE, "-S", SOURCE, "-B", self.tmp / "configure", *options],
                              env=env or self.env, capture_output=True, text=True)

    def test_config_selector_and_invalid_explicit_package(self):
        selected = self.run_configure("-DBUILD_TESTING=OFF", f"-DLLVM_CONFIG={LLVM_BIN / 'llvm-config'}")
        self.assertEqual(selected.returncode, 0, selected.stderr)
        self.assertIn(f"at {LLVM_DIR}", selected.stdout)
        failed = self.run_configure(f"-DLLVM_DIR={self.tmp / 'absent'}")
        self.assertNotEqual(failed.returncode, 0)
        self.assertIn("Invalid LLVM_DIR", " ".join(failed.stderr.split()))

    def test_rejects_unsupported_package(self):
        package = self.tmp / "old"
        package.mkdir()
        (package / "LLVMConfig.cmake").write_text('set(LLVM_PACKAGE_VERSION "17.0.6")\n')
        failed = self.run_configure(f"-DLLVM_DIR={package}")
        self.assertNotEqual(failed.returncode, 0)
        self.assertIn("requires stable LLVM 23.x", failed.stderr)
        self.assertIn("17.0.6", failed.stderr)

    def test_conflicting_selectors(self):
        other = self.tmp / "other"
        other.mkdir()
        (other / "LLVMConfig.cmake").touch()
        env = dict(self.env, LLVM_CONFIG=str(LLVM_BIN / "llvm-config"))
        for command in ([CMAKE, "-S", SOURCE, "-B", self.tmp / "configure", f"-DLLVM_DIR={other}"],
                        ["make", "format-check", f"LLVM_DIR={other}"]):
            with self.subTest(command=command[0]):
                failed = subprocess.run(command, env=env, cwd=SOURCE, capture_output=True, text=True)
                self.assertNotEqual(failed.returncode, 0)
                self.assertIn("Conflicting LLVM_DIR", " ".join(failed.stderr.split()))

    def test_rejects_unrelated_explicit_tool(self):
        decoy = self.tmp / "opt"
        decoy.write_text("#!/bin/sh\nexit 0\n")
        decoy.chmod(0o755)
        failed = self.run_configure(f"-DLLVM_DIR={LLVM_DIR}", f"-Dopt:FILEPATH={decoy}")
        self.assertNotEqual(failed.returncode, 0)
        self.assertIn("Conflicting opt", " ".join(failed.stderr.split()))

    def test_missing_differential_tool_ignores_path(self):
        if sys.platform != "darwin":
            self.skipTest("the differential harness configures on macOS")
        # Wrap the real package. Advertise a tool directory containing only
        # llvm-config, with the genuine opt available as a tempting PATH fallback.
        package = self.tmp / "package"
        package.mkdir()
        tools = self.tmp / "bin"
        tools.mkdir()
        (package / "LLVMConfig.cmake").write_text(
            f"include([[{LLVM_DIR}/LLVMConfig.cmake]])\nset(LLVM_TOOLS_BINARY_DIR [[{tools}]])\n")
        config = tools / "llvm-config"
        config.write_text(f'#!/bin/sh\nif [ "$1" = --bindir ]; then dirname "$0"; '
                          f'else exec "{LLVM_BIN / "llvm-config"}" "$@"; fi\n')
        config.chmod(0o755)
        env = dict(self.env, PATH=str(LLVM_BIN) + os.pathsep + self.env["PATH"])
        failed = self.run_configure(f"-DLLVM_DIR={package}", "-DBUILD_TESTING=OFF",
                                    f"-DFORGE_DIFFERENTIAL_IR={self.tmp / 'lift.ll'}", env=env)
        self.assertNotEqual(failed.returncode, 0)
        self.assertIn("Missing required LLVM tool 'opt'", " ".join(failed.stderr.split()))

    def test_lint_requires_real_commands_in_external_database(self):
        build = self.tmp / "analysis build"
        subprocess.run([CMAKE, "-S", SOURCE, "-B", build, f"-DLLVM_DIR={LLVM_DIR}",
                        "-DBUILD_TESTING=OFF", "-DCMAKE_EXPORT_COMPILE_COMMANDS=ON"],
                       env=self.env, check=True)
        database = build / "compile_commands.json"
        contents = database.read_bytes()
        entries = json.loads(contents)
        harness = SOURCE / "tests/support/native_harness.cpp"
        self.assertIn(str(harness), [e["file"] for e in entries])
        self.assertIn(str(SOURCE / "tests/unit/integer.cpp"), [e["file"] for e in entries])
        subprocess.run([CMAKE, "--build", build, "--parallel", "4"], env=self.env, check=True)
        self.assertTrue((build / "forge").is_file())
        self.assertFalse((build / "tests/integer_semantics").exists())

        # Exercise the wrapper even on machines without clang-tidy.
        config = self.tmp / "llvm-config"
        config.write_text(f'#!/bin/sh\nif [ "$1" = --bindir ]; then dirname "$0"; '
                          f'else exec "{LLVM_BIN / "llvm-config"}" "$@"; fi\n')
        config.chmod(0o755)
        tidy = self.tmp / "clang-tidy"
        tidy.write_text('#!/bin/sh\ncase "$1" in\n'
                        '  --version) echo "LLVM version 23.1.5" ;;\n'
                        '  *) case "$3" in --checks=-readability-*) printf "%s\\n" "$@" > "$0.args";; esac ;;\n'
                        'esac\n')
        tidy.chmod(0o755)
        command = ["make", "lint", f"LLVM_CONFIG={config}", f"LINT_DATABASE={database}"]
        env = dict(self.env, FORGE_STYLE_BASE="HEAD")
        subprocess.run(command, cwd=SOURCE, env=env, check=True)
        args = (self.tmp / "clang-tidy.args").read_text().splitlines()
        self.assertEqual(args[:2], ["-p", str(build)])
        expected = [str(p) for folder in ("src", "tests/support", "tests/unit")
                    for p in (SOURCE / folder).rglob("*.cpp")]
        self.assertTrue(args[-1].startswith("--vfsoverlay="))
        self.assertTrue(args[2].startswith("--checks=-readability-"))
        self.assertCountEqual(args[3:-1], expected)
        self.assertEqual(database.read_bytes(), contents)

        for missing in (harness, SOURCE / "src/pe/pe.cpp", SOURCE / "tests/unit/integer.cpp"):
            with self.subTest(missing=missing):
                database.write_text(json.dumps([e for e in entries if e["file"] != str(missing)]))
                failed = subprocess.run(command, cwd=SOURCE, env=self.env, capture_output=True, text=True)
                self.assertNotEqual(failed.returncode, 0)
                self.assertIn("Missing first-party compile commands", failed.stderr)
                self.assertIn(str(missing), failed.stderr)


if __name__ == "__main__":
    unittest.main(argv=[sys.argv[0]])
