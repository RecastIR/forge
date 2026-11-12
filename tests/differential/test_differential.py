"""Wine-free tests of the reference consumer, native supervisor, and suite outcomes."""
import contextlib
import io
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

import differential as diff
from artifacts import TASK3_PUBLISHER, reference
from comparison import Observation, differences
from protocol import Capture
from run import publish, runner_version, sha256


class ComparisonTests(unittest.TestCase):
    def test_matching_bytes(self):
        for data in (b"", b"\xff\0 \r\n"):
            observation = Observation(0, data, data)
            self.assertEqual(differences(observation, observation), [])

    def test_exact_fields_and_offsets(self):
        for wanted, got, offset in ((b"x\r\n", b"x\n", 1), (b"x ", b"x", 1),
                                    (b"\xff", b"\xfe", 0), (b"", b"\n", 0)):
            for field in ("stdout", "stderr"):
                with self.subTest(field=field, wanted=wanted):
                    streams = {"stdout": b"", "stderr": b""}
                    before = Observation(0, **dict(streams, **{field: wanted}))
                    after = Observation(0, **dict(streams, **{field: got}))
                    self.assertEqual(differences(before, after),
                                     [dict(field=field, offset=offset, expected=repr(wanted),
                                           actual=repr(got), expected_size=len(wanted), actual_size=len(got))])
        errors = differences(Observation(4660, b"a", b"b"), Observation(52, b"A", b"B"))
        self.assertEqual([e["field"] for e in errors], ["exit_code", "stdout", "stderr"])
        self.assertEqual(errors[0], dict(field="exit_code", expected=4660, actual=52))


class ArtifactTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name).resolve()
        self.config = "debug"
        self.catalog = diff.load_catalog()
        self.manifest = next(m for m in self.catalog if m.case["id"] == "arithmetic/add_i64")
        self.case = diff.enabled_cases(self.catalog, diff.SUITE / "cases.json")[self.manifest.case["id"]]
        self.binaries = self.root / "binaries"
        bins = self.binaries / self.config
        bins.mkdir(parents=True)
        self.image = bins / self.manifest.case["binary"]
        self.image.write_bytes(b"unit test PE snapshot")
        self.digest = sha256(self.image.read_bytes())
        (bins / "SHA256SUMS").write_text(f"{self.digest}  {self.image.name}\n")
        self.references = self.root / "references"
        self.folder = self.references / self.config / self.manifest.case["id"]
        self.record = self.folder / "result.json"
        self.wanted = Observation.from_manifest(self.manifest.case["expected"])
        capture = Capture(self.wanted.exit_code, self.wanted.stdout, self.wanted.stderr, "wine-test")
        publish(self.root, self.folder, self.manifest, self.config, capture, self.digest,
                dict(runner_version=runner_version(), container_image_id="sha256:" + "a" * 64,
                     container_platform="linux/amd64", docker_host_arch="x86_64"))

    def reference(self):
        return reference(self.references, self.manifest, self.config, self.digest)

    def test_reference_identity(self):
        for version in (runner_version(), TASK3_PUBLISHER):
            meta = diff.read_json(self.record)
            diff.write_json(self.record, dict(meta, runner_version=version))
            observed, identity = self.reference()
            self.assertEqual(observed, self.wanted)
            self.assertEqual(identity["runner_version"], version)
            self.assertEqual(identity["result_sha256"], sha256(self.record.read_bytes()))

    def test_invalid_metadata(self):
        meta = diff.read_json(self.record)
        for field, value in (("schema_version", True), ("status", "failed"), ("build_config", "release"),
                             ("fixture_id", "other/case"), ("manifest_file", "moved"),
                             ("manifest_sha256", "0" * 64), ("binary_sha256", "0" * 64),
                             ("execution_backend", "other"), ("container_platform", "linux/arm64"),
                             ("runner_version", "1+sha256." + "1" * 64), ("container_image_id", "latest"),
                             ("docker_host_arch", ""), ("wine_version", ""), ("exit_code", 1 << 32),
                             ("exit_code", 1), ("stdout_size", True), ("stderr_size", 4),
                             ("stdout_file", "../stdout.bin"), ("stderr_sha256", "1" * 64)):
            with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                diff.write_json(self.record, dict(meta, **{field: value}))
                self.reference()
        self.record.write_text('{"status":"passed","status":"failed"}')
        with self.assertRaisesRegex(ValueError, "duplicate"):
            self.reference()
        self.record.unlink()
        with self.assertRaises(FileNotFoundError):
            self.reference()

    def test_substituted_payload(self):
        path = self.folder / "stdout.bin"
        path.write_bytes(b"substituted")
        with self.assertRaisesRegex(ValueError, "SHA-256"):
            self.reference()
        diff.write_json(self.record, dict(diff.read_json(self.record), stdout_sha256=sha256(path.read_bytes()),
                                          stdout_size=path.stat().st_size))
        with self.assertRaisesRegex(ValueError, "stdout mismatch"):
            self.reference()
        path.unlink()
        with self.assertRaises(FileNotFoundError):
            self.reference()
        path.symlink_to(self.image)
        with self.assertRaises(OSError):
            self.reference()
        parent = self.folder.parent
        parent.rename(parent.with_name("moved"))
        parent.symlink_to(parent.with_name("moved"), target_is_directory=True)
        with self.assertRaisesRegex(ValueError, "symbolic link"):
            self.reference()

    def invoke(self, selection=None):
        output = self.root / "output"
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            status = diff.run(self.config, selection, binaries=self.binaries, references=self.references,
                              output=output, forge=self.image)
        return status, diff.read_json(output / self.config / "suite.json")

    def test_statuses_and_stale_pass_rejection(self):
        name = self.manifest.case["id"]
        report = self.root / "output" / self.config / name / "result.json"
        with patch.object(diff, "analyze", return_value="0x1234") as analyze, patch.object(diff, "lift") as lift, \
                patch.object(diff.native, "build") as build, patch.object(diff.native, "execute") as execute:
            execute.return_value = self.wanted
            status, suite = self.invoke()
            self.assertEqual((status, suite["executed"], suite["uncovered"]), (0, 1, len(self.catalog) - 1))
            self.assertEqual(diff.read_json(report)["scope"], "function")
            self.assertEqual(execute.call_args.args[1], self.manifest.case["args"])
            execute.return_value = Observation(0, b"divergent", b"")
            status, suite = self.invoke(name)
            self.assertEqual((status, suite["executed"]), (1, 1))
            self.assertEqual(diff.read_json(report)["failure_categories"], ["stdout_mismatch"])
            for mock, error, category in (
                    (execute, ValueError("harness failed"), "native_execution_failure"),
                    (build, ValueError("compiler failed"), "native_compilation_failure"),
                    (analyze, ValueError("ambiguous export"), "analysis_failure"),
                    (lift, ValueError("write failed"), "lifting_failure"),
                    (lift, diff.Unsupported("unsupported opcode"), "unsupported_lifting_capability")):
                mock.side_effect = error
                status, suite = self.invoke(name)
                result = diff.read_json(report)
                self.assertEqual((status, suite["executed"], result["stages"]["comparison"]), (1, 0, "not_run"))
                self.assertEqual(result["failure_categories"], [category])
                self.assertEqual(result["status"], "blocked" if isinstance(error, diff.Unsupported)
                                 else "infrastructure_failure")
                mock.side_effect = None
        self.image.write_bytes(b"stale")
        status, suite = self.invoke(name)
        self.assertEqual((status, suite["passed"]), (1, 0))
        self.assertEqual(diff.read_json(report)["failure_categories"], ["reference_validation_failure"])
        self.assertFalse((report.parent / "generated").exists())

    def test_zero_coverage(self):
        status, suite = self.invoke("runner/exit_and_stderr")
        self.assertEqual((status, suite["executed"], suite["uncovered"]), (1, 0, 1))
        self.assertIn("zero differential cases", suite["diagnostic"])
        path = self.root / "empty.json"
        diff.write_json(path, [])
        self.assertEqual(diff.enabled_cases(self.catalog, path), {})
        diff.write_json(path, [self.case, self.case])
        with self.assertRaisesRegex(ValueError, "duplicate"):
            diff.enabled_cases(self.catalog, path)

    def test_input_root_cannot_be_used_as_output(self):
        original = self.record.read_bytes()
        with self.assertRaisesRegex(ValueError, "overlaps input"):
            diff.run(self.config, binaries=self.binaries, references=self.references, output=self.references)
        self.assertEqual(self.record.read_bytes(), original)


class AnalysisTests(unittest.TestCase):
    def test_lifting_error_classification(self):
        case = {"signature": "i64(i64,i64)"}
        for detail, blocked in (("PUSH64 [55]: unsupported instruction or operand width", True),
                                ("LLVM verifier: malformed module", False)):
            with patch.object(diff.native, "command", side_effect=ValueError("input: LIFT_ERROR: 0x10: " + detail)):
                with self.assertRaises(ValueError) as failure:
                    diff.lift("forge", "image.exe", case, "0x10", Path("generated/lifted.ll"))
                self.assertEqual(isinstance(failure.exception, diff.Unsupported), blocked)

    def test_range_and_export_identity(self):
        item = dict(names=["sum"], rva="0x10")
        row = dict(start_rva="0x10", status="valid", liftable=True)
        def resolve(exports, rows):
            inspection = dict(schema_version=1, inspection=dict(status="completed", root_module=0),
                              modules=[dict(exports=exports)])
            return diff.resolve_export(inspection, dict(schema_version=1, functions=rows), "sum")
        self.assertEqual(resolve([item], [row]), "0x10")
        for exports, rows in (([], [row]), ([item, item], [row]), ([dict(item, forwarder="other")], [row]),
                              ([item], [row, row]), ([item], [dict(row, status="invalid")])):
            with self.assertRaises(ValueError) as failure:
                resolve(exports, rows)
            self.assertNotIsInstance(failure.exception, diff.Unsupported)
        for rows in ([], [dict(row, liftable=False, status="unsupported")]):
            with self.assertRaises(diff.Unsupported):
                resolve([item], rows)


class NativeTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.work = Path(tmp.name).resolve()

    def python(self, code, **options):
        return diff.native.execute(sys.executable, ["-c", code], self.work, **options)

    def test_streams_and_execution_failures(self):
        actual = self.python(r'import sys; print(len(sys.stdin.buffer.read())); sys.stderr.buffer.write(b"\xff\0")')
        self.assertEqual(actual, Observation(0, b"0\n", b"\xff\0"))
        for code, message in (("raise SystemExit(7)", "exited 7"), ("import os; os.kill(os.getpid(), 15)", "signal")):
            with self.assertRaisesRegex(ValueError, message):
                self.python(code)
        with self.assertRaises(FileNotFoundError):
            diff.native.execute(self.work / "absent", [], self.work)

    def test_output_limits_and_timeout(self):
        for fd, name in ((1, "stdout"), (2, "stderr")):
            self.python(f"import os; os.write({fd}, b'x' * 32)", limit=32)
            with self.assertRaisesRegex(ValueError, name + " output-size limit"):
                self.python(f"import os; os.write({fd}, b'x' * 33)", limit=32)
            self.assertEqual((self.work / (name + ".bin")).read_bytes(), b"x" * 32)
        # The original process exits while its sleeping child retains the pipes.
        code = "import subprocess,sys; subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(20)'])"
        with self.assertRaisesRegex(ValueError, "timeout"):
            self.python(code, timeout=0.3)


if __name__ == "__main__":
    unittest.main()
