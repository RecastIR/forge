"""Native regression runs using the genuine PE, Wine publication, Forge and native build."""
import os
from pathlib import Path
import re
import tempfile
import unittest
from unittest.mock import patch

import differential as diff

CASE = "arithmetic/add_i64"
WEIGHTED = "arithmetic/weighted_pair_i64"
OUTPUT = diff.OUTPUT.parent / "negative-tests"


class NativeDifferentialTests(unittest.TestCase):
    def negative(self, name, category, *, fixture=CASE, binaries=diff.BINARIES):
        output = OUTPUT / name
        self.assertEqual(diff.run("debug", fixture, binaries=binaries, output=output), 1)
        report = diff.read_json(output / "debug" / fixture / "result.json")
        self.assertEqual(report["failure_categories"], [category])
        return report

    def modified_ir(self, fixture, name, category, mutate, only=None):
        compile_native = diff.native.build

        def compile_copy(ir, harness, work, config, variant):
            if only and only != variant:
                return compile_native(ir, harness, work, config, variant)
            changed = work / (name + ".ll")
            changed.write_text(mutate(ir.read_text()))
            return compile_native(changed, harness, work, config, variant)

        with patch.object(diff.native, "build", compile_copy):
            return self.negative(name, category, fixture=fixture)

    def test_changed_return(self):
        def change_return(source):
            changed, count = re.subn(r"^  ret i64 (%\w+)$",
                                     r"  %nonzero = icmp ne i64 \1, 0\n  %delta = zext i1 %nonzero to i64\n"
                                     r"  %changed = add i64 \1, %delta\n  ret i64 %changed",
                                     source, flags=re.MULTILINE)
            self.assertEqual(count, 1, "expected one return in the native wrapper")
            return changed

        for fixture, pair_index, variant in ((CASE, 0, "baseline"), (WEIGHTED, 1, "o2")):
            with self.subTest(fixture=fixture):
                report = self.modified_ir(fixture, "changed-return", "stdout_mismatch", change_return, only=variant)
                other = "baseline" if variant == "o2" else "o2"
                self.assertEqual(report["variants"][other]["status"], "passed")
                self.assertEqual(report["status"], "behavioral_failure")
                self.assertEqual(report["stages"]["native_execution"], "passed")
                self.assertEqual(report["stages"]["comparison"], "failed")
                mismatch, = report["variants"][variant]["differences"]
                self.assertEqual(mismatch["field"], "stdout")
                manifest = next(m for m in diff.load_catalog() if m.case["id"] == fixture)
                self.assertEqual(mismatch["operands"], manifest.case["args"][2 * pair_index:2 * pair_index + 2])

    def test_signed_comparison_with_truncated_right_operand(self):
        def truncate_right(source):
            # Change the incoming RDX bits once. The weighted term already uses
            # only EDX, so the only behavior affected is the signed comparison.
            pattern = r"^(  store i64 )%1(, ptr %\w+, align \d+)$"
            changed, count = re.subn(pattern, r"  %low = trunc i64 %1 to i32\n"
                                     r"  %right = sext i32 %low to i64\n\1%right\2", source,
                                     flags=re.MULTILINE)
            self.assertEqual(count, 1, "expected the wrapper to initialize RDX once")
            return changed

        report = self.modified_ir(WEIGHTED, "truncated-right", "stdout_mismatch", truncate_right)
        self.assertEqual(report["stages"]["native_execution"], "passed")
        self.assertEqual(report["stages"]["comparison"], "failed")
        for evidence in report["variants"].values():
            mismatch, = evidence["differences"]
            self.assertEqual(mismatch["operands"], ["1", "4294967295"])

    def test_native_build_failures(self):
        def missing_wrapper(source):
            self.assertEqual(source.count("@forge_lifted("), 1)
            return source.replace("@forge_lifted(", "@missing_wrapper(")

        def invalid_ir(source):
            return source + "\ninvalid IR for the native build regression\n"

        for fixture, name, mutate, phase in (
                (CASE, "invalid-ir", invalid_ir, "object compilation"),
                (WEIGHTED, "invalid-ir", invalid_ir, "object compilation"),
                (WEIGHTED, "missing-wrapper", missing_wrapper, "linking")):
            with self.subTest(fixture=fixture, name=name):
                report = self.modified_ir(fixture, name, "native_compilation_failure", mutate)
                self.assertEqual(report["status"], "infrastructure_failure")
                self.assertIn(f"native {phase} failed", report["diagnostic"])
                if name == "missing-wrapper":
                    self.assertIn("_forge_lifted", report["diagnostic"])
                self.assertEqual(report["stages"]["native_execution"], "not_run")
                self.assertEqual(report["stages"]["comparison"], "not_run")

    def test_instrumented_harness_link(self):
        for generator in ("Unix Makefiles", "Xcode"):
            with self.subTest(generator=generator), tempfile.TemporaryDirectory() as tmp:
                output = Path(tmp).resolve()
                flags = "-fsanitize=undefined"
                link_map = output / "harness.map"
                # The Xcode generator takes link options separately from CXXFLAGS.
                ldflags = f'{flags} -Xlinker -map -Xlinker "{link_map}"' if generator == "Xcode" else ""
                with patch.dict(os.environ, CMAKE_GENERATOR=generator, CXXFLAGS=flags, LDFLAGS=ldflags):
                    self.assertEqual(diff.run("debug", WEIGHTED, output=output), 0)
                if generator == "Xcode":
                    self.assertIn("_forge_lifted", link_map.read_text())

    def test_weighted_repeatability(self):
        with tempfile.TemporaryDirectory() as tmp:
            observations = []
            for run in ("first", "second"):
                output = Path(tmp).resolve() / run
                self.assertEqual(diff.run("debug", WEIGHTED, output=output), 0)
                work = output / "debug" / WEIGHTED
                report = diff.read_json(work / "result.json")
                self.assertEqual(report["status"], "passed")
                observations.append((report["binary_sha256"], report["forge_sha256"], report["reference"],
                                     (work / "generated/lifted.ll").read_bytes(), report["variants"],
                                     [(work / v / file).read_bytes() for v in diff.VARIANTS
                                      for file in ("stdout.bin", "stderr.bin")]))
            self.assertEqual(observations[0], observations[1])

    def test_harness_failure(self):
        execute = diff.native.execute
        with patch.object(diff.native, "execute", lambda exe, args, work: execute(exe, ["invalid", "1"], work)):
            report = self.negative("invalid-operands", "native_execution_failure")
        self.assertIn("exited 2", report["diagnostic"])
        for evidence in report["variants"].values():
            self.assertEqual((evidence["execution_outcome"], evidence["native_process_status"]), ("harness_error", 2))
        self.assertEqual(report["stages"]["comparison"], "not_run")

    def test_stale_reference(self):
        manifest = next(m for m in diff.load_catalog() if m.case["id"] == CASE)
        binary = manifest.case["binary"]
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            (root / "debug").mkdir()
            release = (diff.BINARIES / "release" / binary).read_bytes()
            (root / "debug" / binary).write_bytes(release)
            (root / "debug/SHA256SUMS").write_text(f"{diff.sha256(release)}  {binary}\n")
            report = self.negative("stale-pe", "reference_validation_failure", binaries=root)
        self.assertIn("binary_sha256 mismatch", report["diagnostic"])
        self.assertEqual(report["stages"]["analysis"], "not_run")


if __name__ == "__main__":
    unittest.main()
