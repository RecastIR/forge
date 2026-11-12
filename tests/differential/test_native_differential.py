"""Negative integration runs using the genuine PE, Wine publication, Forge and native build."""
from pathlib import Path
import re
import tempfile
import unittest
from unittest.mock import patch

import differential as diff

CASE = "arithmetic/add_i64"
OUTPUT = diff.OUTPUT.parent / "negative-tests"


class NativeDifferentialTests(unittest.TestCase):
    def negative(self, name, category, *, binaries=diff.BINARIES):
        output = OUTPUT / name
        self.assertEqual(diff.run("debug", CASE, binaries=binaries, output=output), 1)
        report = diff.read_json(output / "debug" / CASE / "result.json")
        self.assertEqual(report["failure_categories"], [category])
        return report

    def test_changed_return_and_invalid_ir(self):
        compile_native = diff.native.build
        for name, category in (("changed-return", "stdout_mismatch"), ("invalid-ir", "native_compilation_failure")):
            with self.subTest(name=name):
                def compile_copy(ir, harness, work, config):
                    source = ir.read_text()
                    if name == "changed-return":
                        source, count = re.subn(r"^  ret i64 (%\w+)$",
                                                r"  %changed = add i64 \1, 1\n  ret i64 %changed",
                                                source, flags=re.MULTILINE)
                        self.assertEqual(count, 1, "expected one return in the real native wrapper")
                    else:
                        source += "\ninvalid IR for the native build regression\n"
                    changed = ir.with_name(name + ".ll")
                    changed.write_text(source)
                    return compile_native(changed, harness, work, config)

                with patch.object(diff.native, "build", compile_copy):
                    report = self.negative(name, category)
                if name == "changed-return":
                    self.assertEqual(report["stages"]["native_execution"], "passed")
                    self.assertEqual(report["differences"][0]["field"], "stdout")
                    self.assertEqual(report["stages"]["comparison"], "failed")
                else:
                    self.assertEqual(report["stages"]["native_execution"], "not_run")
                    self.assertEqual(report["stages"]["comparison"], "not_run")

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
