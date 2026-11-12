"""Wine-free tests of the reference consumer, native supervisor, and suite outcomes."""
import contextlib
import errno
import fcntl
import io
import os
from pathlib import Path
import signal
import subprocess
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
        self.suite = self.root / "suite"
        (self.suite / "manifests").mkdir(parents=True)
        (self.suite / "fixtures").mkdir()
        for name, code in (("enabled", 0), ("uncovered", 4660)):
            source = f"fixtures/{name}.c"
            (self.suite / source).touch()
            diff.write_json(self.suite / "manifests" / f"{name}.json", dict(
                schema_version=1, id=f"unit/{name}", description=name, source=source,
                binary=f"{name}.exe", args=["2", "3"], expected=dict(exit_code=code, stdout="5\n", stderr="")))
        self.case = dict(fixture_id="unit/enabled", scope="function", export="sum",
                         signature="i64(i64,i64)", harness="decimal_pairs")
        diff.write_json(self.suite / "cases.json", [self.case])
        self.catalog = diff.load_catalog(self.suite)
        self.manifest = next(m for m in self.catalog if m.case["id"] == self.case["fixture_id"])
        self.forge = self.root / "selected forge"
        self.forge.write_bytes(b"unit test Forge")
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

    def test_directory_record_releases_descriptor(self):
        self.record.unlink()
        self.record.mkdir()
        for _ in range(8):
            fd = os.open(self.record, os.O_RDONLY)
            with patch("artifacts.os.open", return_value=fd), self.assertRaisesRegex(ValueError, "artifact type"):
                self.reference()
            with self.assertRaises(OSError) as closed:
                os.fstat(fd)
            self.assertEqual(closed.exception.errno, errno.EBADF)

    def invoke(self, selection=None, *, forge=None):
        output = self.root / "output"
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            status = diff.run(self.config, selection, binaries=self.binaries, references=self.references,
                              output=output, forge=self.forge if forge is None else forge, suite=self.suite)
        return status, diff.read_json(output / self.config / "suite.json")

    def test_statuses_and_stale_pass_rejection(self):
        name = self.manifest.case["id"]
        report = self.root / "output" / self.config / name / "result.json"
        with patch.object(diff, "analyze", return_value="0x1234") as analyze, patch.object(diff, "lift") as lift, \
                patch.object(diff.native, "build") as build, patch.object(diff.native, "execute") as execute:
            execute.return_value = self.wanted
            status, suite = self.invoke()
            self.assertEqual((status, suite["executed"], suite["uncovered"]), (0, 1, 1))
            passed = diff.read_json(report)
            self.assertEqual(passed["scope"], "function")
            self.assertEqual(passed["forge_sha256"], sha256(self.forge.read_bytes()))
            self.assertEqual(analyze.call_args.args[0], self.forge)
            self.assertEqual(lift.call_args.args[0], self.forge)
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
        status, suite = self.invoke("unit/uncovered")
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
            diff.run(self.config, binaries=self.binaries, references=self.references,
                     output=self.references, suite=self.suite)
        self.assertEqual(self.record.read_bytes(), original)

    def test_overlap_through_case_alias_preserves_inputs_and_report(self):
        if not (self.root / "SUITE").exists() or not (self.root / "SUITE").samefile(self.suite):
            self.skipTest("requires a case-insensitive volume")
        for kind in ("binaries", "references"):
            for input_inside_output in (True, False):
                with self.subTest(kind=kind, input_inside_output=input_inside_output):
                    base = self.root / f"{kind}-{input_inside_output}"
                    (base / "debug").mkdir(parents=True)
                    nested = base / "DEBUG" / "nested"
                    source, output = (nested, base) if input_inside_output else (base, nested)
                    inputs = dict(binaries=self.binaries, references=self.references)
                    inputs[kind] = source
                    if kind == "references" and input_inside_output:
                        nested.mkdir()
                        downloads = self.root / "downloads"
                        downloads.symlink_to(nested, target_is_directory=True)
                        source = nested / "wine"
                        inputs[kind] = downloads / "wine"
                    marker = source / "debug/input.bin"
                    summary = output / "debug/suite.json"
                    for path, data in ((marker, b"input"), (summary, b"previous report")):
                        path.parent.mkdir(parents=True, exist_ok=True)
                        path.write_bytes(data)
                    with self.assertRaisesRegex(ValueError, "overlaps input"):
                        diff.run("debug", output=output, suite=self.suite, **inputs)
                    self.assertEqual(marker.read_bytes(), b"input")
                    self.assertEqual(summary.read_bytes(), b"previous report")

    def test_cli_selects_forge(self):
        args = ["--all", "--config", self.config]
        with patch.object(diff, "run", return_value=0) as run:
            self.assertEqual(diff.main(args), 0)
            self.assertEqual(run.call_args.kwargs["forge"], diff.DEFAULT_FORGE)
            relative = os.path.relpath(self.forge)
            self.assertEqual(diff.main([*args, "--forge", relative]), 0)
            self.assertEqual(run.call_args.kwargs["forge"], self.forge)
        absent = self.root / "missing forge"
        status, _ = self.invoke(self.case["fixture_id"], forge=absent)
        report = diff.read_json(self.root / "output/debug/unit/enabled/result.json")
        self.assertEqual(status, 1)
        self.assertEqual(report["failure_categories"], ["analysis_failure"])
        self.assertIn(str(absent), report["diagnostic"])
        self.assertEqual(report["stages"]["lifting"], "not_run")

    def test_cleanup_preserves_selected_forge(self):
        output = self.root / "output"
        folder = output / self.config
        folder.mkdir(parents=True)
        selected = folder / "custom-forge"
        selected.write_bytes(b"selected executable")
        with self.assertRaisesRegex(ValueError, "overlaps selected Forge"):
            self.invoke(forge=selected)
        self.assertEqual(selected.read_bytes(), b"selected executable")

    def test_successful_commands_without_product_fail_compilation(self):
        with patch.object(diff, "analyze", return_value="0x1234"), patch.object(diff, "lift"), \
                patch.object(diff.native, "command"), patch.object(diff.platform, "system", return_value="Darwin"), \
                patch.object(diff.platform, "machine", return_value="arm64"):
            status, _ = self.invoke(self.case["fixture_id"])
        report = diff.read_json(self.root / "output/debug/unit/enabled/result.json")
        self.assertEqual(status, 1)
        self.assertEqual(report["failure_categories"], ["native_compilation_failure"])
        self.assertIn("executable harness", report["diagnostic"])
        self.assertEqual(report["stages"]["native_execution"], "not_run")
        self.assertEqual(report["stages"]["comparison"], "not_run")


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

    def test_command_stops_descendants_before_returning(self):
        # The child holds a lock until exit. Opening the gate after command returns
        # would let a surviving writer modify the next build's output.
        child = """
import fcntl, os, signal, sys, time
from pathlib import Path
work = Path(sys.argv[1])
with (work / 'ready').open('w') as locked:
    fcntl.flock(locked, fcntl.LOCK_EX)
    print('ready', flush=True)
    if sys.argv[2] == 'interrupt':
        os.kill(int(sys.argv[3]), signal.SIGUSR1)
    for _ in range(500):
        if (work / 'gate').exists():
            (work / 'late').touch()
            break
        time.sleep(0.01)
"""
        parent = "import subprocess, sys; subprocess.run([sys.executable, '-c', *sys.argv[1:]], check=True)"
        previous = signal.signal(signal.SIGUSR1, diff.interrupt)
        self.addCleanup(signal.signal, signal.SIGUSR1, previous)
        for mode, error in (("timeout", subprocess.TimeoutExpired), ("interrupt", KeyboardInterrupt)):
            with self.subTest(mode=mode):
                work = self.work / mode
                work.mkdir()
                log = work / "build.log"
                args = [sys.executable, "-c", parent, child, str(work), mode, str(os.getpid())]
                with self.assertRaises(error):
                    diff.native.command(args, log, timeout=1 if mode == "timeout" else 5)
                self.assertIn("ready", log.read_text())
                (work / "gate").touch()
                with (work / "ready").open() as lock:
                    fcntl.flock(lock, fcntl.LOCK_SH)
                    self.assertFalse((work / "late").exists())

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
