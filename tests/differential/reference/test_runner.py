import contextlib
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

import docker_wine
from protocol import Capture, READY, STREAM_LIMIT, decode
import run
import fixture_images


class CaptureTests(unittest.TestCase):
    def test_prepared_image_is_local_and_matches_inputs(self):
        def inspect(args, **kwargs):
            self.assertEqual(args[:3], ["docker", "image", "inspect"])
            return subprocess.CompletedProcess(args, 1, stdout="", stderr="image absent")

        with patch.object(subprocess, "run", side_effect=inspect):
            with self.assertRaisesRegex(ValueError, "make provision-fixtures"):
                fixture_images.local_image(run.SUITE, "reference")

        with tempfile.TemporaryDirectory() as tmp:
            suite = Path(tmp)
            for name in ("toolchain/Dockerfile", "reference/capture.c", "build.py", "manifests.py",
                         "reference/guest.py", "reference/protocol.py"):
                path = suite / name
                path.parent.mkdir(exist_ok=True)
                path.write_text(name)
            compiler = fixture_images.image_tag(suite, "toolchain")
            wine = fixture_images.image_tag(suite, "reference")
            (suite / "reference/capture.c").write_text("updated capture")
            self.assertNotEqual(fixture_images.image_tag(suite, "reference"), wine)
            self.assertEqual(fixture_images.image_tag(suite, "toolchain"), compiler)
            (suite / "toolchain/Dockerfile").write_text("updated toolchain")
            self.assertNotEqual(fixture_images.image_tag(suite, "toolchain"), compiler)

    def test_stream_mismatches(self):
        expected = dict(exit_code=4660, stdout="résult\n", stderr="end\n")
        observation = Capture(52, "résult\r\n".encode(), b"end\n\xff", "wine-test")
        with self.assertRaises(ValueError) as caught:
            run.compare(expected, observation)
        report = str(caught.exception)
        for detail in ("expected 4660, actual 52", "stdout mismatch at byte 7", "stderr mismatch at byte 4",
                       "expected (8 bytes)", "actual   (9 bytes)", r"\r\n", r"\xff"):
            self.assertIn(detail, report)
        with self.assertRaisesRegex(ValueError, "byte 2"):
            run.compare(dict(exit_code=0, stdout="ab\n", stderr=""), Capture(0, b"ab", b"", "wine"))

    def test_wire_records(self):
        header = dict(exit_code=0xffffffff, stdout_size=0, stderr_size=2, wine_version="wine-test")
        def record(changes):
            return READY + json.dumps(dict(header, **changes)).encode() + b"\n\0\xff"
        self.assertEqual(decode(record({})), Capture(0xffffffff, b"", b"\0\xff", "wine-test"))
        for data in (b"", READY, record({})[:-1], record({}) + b"\0", record(dict(stdout_size=True)),
                     record(dict(stderr_size=STREAM_LIMIT + 1)), record(dict(exit_code=2**32)),
                     record(dict(wine_version=None))):
            with self.subTest(data=data), self.assertRaises(ValueError):
                decode(data)

    def supervise(self, script, startup=5, execution=5):
        with subprocess.Popen([sys.executable, "-c", script], stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE) as child:
            try:
                return docker_wine.supervise(child, startup, execution)
            finally:
                child.kill()

    def test_phase_deadlines(self):
        sleeper = "import time; time.sleep(15)"
        with self.assertRaisesRegex(ValueError, "startup timeout"):
            self.supervise(sleeper, startup=0.15)
        with self.assertRaisesRegex(ValueError, "execution timeout"):
            self.supervise("print('READY', flush=True);" + sleeper, execution=0.15)

    def test_oversized_capture_and_emulator_failure(self):
        with self.assertRaisesRegex(ValueError, "output-size limit"):
            self.supervise("import sys; sys.stdout.buffer.write(b'A' * 3000000)")
        with self.assertRaisesRegex(ValueError, "Rosetta"):
            self.supervise("import sys; print('assertion failed [x86_avx_state_ptr', file=sys.stderr)")

    def test_selection(self):
        self.assertEqual(run.selection(["--all"]), (["debug", "release"], None))
        self.assertEqual(run.selection(["--fixture", "a/b", "--config", "release"]), (["release"], "a/b"))
        for args in ([], ["--fixture", "a/b", "--all"], ["--config", "debug", "--fixture", "../b"]):
            with self.subTest(args=args), contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                run.selection(args)


class PublicationTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name).resolve()
        self.output = self.root / "references/wine"
        self.target = self.output / "debug/a/b"
        (self.root / "fixtures").mkdir()
        (self.root / "fixtures/b.c").touch()
        manifests = self.root / "manifests/a"
        manifests.mkdir(parents=True)
        self.manifest = manifests / "b.json"
        self.manifest.write_text(json.dumps(dict(schema_version=1, id="a/b", source="fixtures/b.c",
                                  binary="b.exe", description="Example", args=[],
                                  expected=dict(stdout="", stderr="err\n", exit_code=4660))))
        self.binaries = self.root / "bins"
        config = self.binaries / "debug"
        config.mkdir(parents=True)
        self.binary = config / "b.exe"
        self.binary.write_bytes(b"test image")
        self.hash = run.sha256(self.binary.read_bytes())
        (config / "SHA256SUMS").write_text(f"{self.hash}  b.exe\n")
        image = patch.object(run, "reference_environment", return_value=dict(container_image_id="sha256:test"))
        image.start()
        self.addCleanup(image.stop)
        execution = patch.object(run, "execute", return_value=Capture(4660, b"", b"err\n", "wine-test"))
        self.execute = execution.start()
        self.addCleanup(execution.stop)

    def invoke(self, status):
        log = io.StringIO()
        with contextlib.redirect_stderr(log), contextlib.redirect_stdout(log):
            actual = run.run(["debug"], "a/b", suite=self.root, output=self.output, binaries=self.binaries)
        self.assertEqual(actual, status, log.getvalue())
        return log.getvalue()

    def test_integrity_and_failed_rerun(self):
        self.invoke(0)
        result = json.loads((self.target / "result.json").read_bytes())
        self.assertEqual(result["fixture_id"], "a/b")
        self.assertEqual(result["manifest_sha256"], run.sha256(self.manifest.read_bytes()))
        self.assertEqual(result["binary_sha256"], self.hash)
        self.assertEqual(result["execution_backend"], "wine")
        self.assertEqual(result["exit_code"], 4660)
        for name, expected in (("stdout", b""), ("stderr", b"err\n")):
            self.assertEqual((self.target / result[name + "_file"]).read_bytes(), expected)
            self.assertEqual(result[name + "_size"], len(expected))
            self.assertEqual(result[name + "_sha256"], run.sha256(expected))
        self.execute.return_value = Capture(52, b"", b"err\r\n", "wine-test")
        self.assertIn("stderr mismatch", self.invoke(1))
        self.assertFalse(self.target.exists())
        failure = self.output.parent / "failures/debug/a/b"
        self.assertEqual((failure / "stderr.bin").read_bytes(), b"err\r\n")
        detail = json.loads((failure / "failure.json").read_bytes())
        self.assertEqual((detail["observed_exit_code"], detail["binary_sha256"]), (52, self.hash))
        self.execute.return_value = Capture(4660, b"", b"err\n", "wine-test")
        self.invoke(0)
        self.assertFalse(failure.exists())

    def test_invalid_manifest_withdraws_results(self):
        self.invoke(0)
        self.manifest.write_text("{}")
        with self.assertRaisesRegex(ValueError, "invalid fixture manifest"):
            self.invoke(1)
        self.assertFalse(self.target.exists())

    def test_missing_or_changed_binary(self):
        self.binary.write_bytes(b"changed")
        self.assertIn("checksum failure", self.invoke(1))
        self.binary.unlink()
        self.assertIn("missing executable", self.invoke(1))
        self.execute.assert_not_called()
        self.assertFalse(self.target.exists())

    def test_write_failure(self):
        self.invoke(0)
        with patch.object(Path, "write_text", side_effect=OSError("disk full")):
            self.assertIn("reference artifact write failure", self.invoke(1))
        self.assertFalse(self.target.exists())

    def test_unconfirmed_cleanup_aborts_suite(self):
        self.execute.side_effect = docker_wine.CleanupFailure("container still running")
        with self.assertRaisesRegex(docker_wine.CleanupFailure, "container still running"):
            run.run(["debug", "release"], "a/b", suite=self.root, binaries=self.binaries, output=self.output)
        self.assertEqual(self.execute.call_count, 1)
        self.assertFalse(self.target.exists())

    def test_snapshot_rejects_symlinks(self):
        self.binary.unlink()
        self.binary.symlink_to(self.manifest)
        self.assertIn("regular fixture export", self.invoke(1))
        self.execute.assert_not_called()


if __name__ == "__main__":
    unittest.main()
