"""Native regression runs using the genuine PE, Wine publication, Forge and native build."""
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

    def modified_ir(self, fixture, name, category, mutate):
        compile_native = diff.native.build

        def compile_copy(ir, harness, work, config):
            changed = ir.with_name(name + ".ll")
            changed.write_text(mutate(ir.read_text()))
            return compile_native(changed, harness, work, config)

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

        for fixture, pair_index in ((CASE, 0), (WEIGHTED, 1)):
            with self.subTest(fixture=fixture):
                report = self.modified_ir(fixture, "changed-return", "stdout_mismatch", change_return)
                self.assertEqual(report["status"], "behavioral_failure")
                self.assertEqual(report["stages"]["native_execution"], "passed")
                self.assertEqual(report["stages"]["comparison"], "failed")
                mismatch, = report["differences"]
                self.assertEqual(mismatch["field"], "stdout")
                manifest = next(m for m in diff.load_catalog() if m.case["id"] == fixture)
                self.assertEqual(mismatch["operands"], manifest.case["args"][2 * pair_index:2 * pair_index + 2])

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
                                     (work / "generated/lifted.ll").read_bytes(), report["native_exit_code"],
                                     (work / "stdout.bin").read_bytes(), (work / "stderr.bin").read_bytes()))
            self.assertEqual(observations[0], observations[1])

    def test_harness_failure(self):
        execute = diff.native.execute
        with patch.object(diff.native, "execute", lambda exe, args, work: execute(exe, ["invalid", "1"], work)):
            report = self.negative("invalid-operands", "native_execution_failure")
        self.assertIn("exited 2", report["diagnostic"])
        self.assertEqual((report["execution_outcome"], report["native_process_status"]), ("harness_error", 2))
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
