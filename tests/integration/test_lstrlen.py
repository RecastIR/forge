"""Execute the real pointer-taking import, including rebasing and terminal faults."""
import json
from pathlib import Path
import platform
import signal
import struct
import subprocess
import sys
import tempfile
import unittest

from pe_layout import Layout

FORGE, IMAGE, OPT, LLC, HARNESS, RUNTIME, CONTRACT, *LINKER = sys.argv[1:]


def run(*args):
    return subprocess.check_output(args, timeout=30)


class StringService(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.work = Path(self.tmp.name)
        self.module = json.loads(run(FORGE, "inspect", IMAGE, "--format", "json"))["modules"][0]
        self.exports = {name: int(e["rva"], 16) for e in self.module["exports"] for name in e["names"]}
        self.base = int(self.module["image_base_va"], 16)
        self.original = Path(IMAGE).read_bytes()
        self.layout = Layout(self.original)

    def lift(self, image=IMAGE, *, entry="string_length", checked=True, reason=None):
        ir = self.work / "lifted.ll"
        args = [FORGE, "lift", str(image), "--rva", hex(self.exports[entry]), "--signature", "i64(i64,i64)",
                "--checked-memory" if checked else "--runtime", "--diagnostics-format", "json", "--output", str(ir)]
        if reason:
            ir.write_bytes(b"previous output")
        result = subprocess.run(args, capture_output=True, timeout=30)
        if reason:
            self.assertEqual(result.returncode, 1, result.stderr)
            diagnostic = json.loads(result.stderr)
            self.assertIn(reason, diagnostic["message"])
            self.assertEqual(diagnostic["context"]["import_symbol"], "lstrlenA")
            self.assertIn("instruction_rva", diagnostic["context"])
            self.assertEqual(ir.read_bytes(), b"previous output")
            return diagnostic
        self.assertEqual(result.returncode, 0, result.stderr)
        return ir

    def variants(self, ir):
        optimized = ir.with_suffix(".o2.ll")
        run(OPT, "-passes=default<O2>", "-S", ir, "-o", optimized)
        for source in (ir, optimized):
            run(OPT, "-passes=verify", "-disable-output", source)
            obj, exe = source.with_suffix(".o"), source.with_suffix(".exe")
            run(LLC, "-filetype=obj", source, "-o", obj)
            run(*LINKER, HARNESS, obj, RUNTIME, "-o", exe)
            yield exe

    def test_results_and_rebasing(self):
        manifest = json.loads((Path(__file__).resolve().parents[1] /
                               "differential/manifests/imports_lstrlen.json").read_text())
        ir = self.lift()
        self.assertIn("@forge_rt_lstrlen_a(", ir.read_text())
        for base in (self.base, self.base + 0x1000000, 0x10000000):
            with self.subTest(base=hex(base)):
                ir = self.work / f"base-{base:x}.ll"
                ir.write_bytes(run(CONTRACT, "--emit-rebased-checked", IMAGE,
                                   hex(self.exports["string_length"]), hex(base)))
                for exe in self.variants(ir):
                    self.assertEqual(run(exe, *manifest["args"]), manifest["expected"]["stdout"].encode())

    def test_failure_precedes_continuation(self):
        ir = self.lift()
        ir.write_text(ir.read_text().replace("@forge_rt_get_last_error(", "@marker_get_last_error("))
        for exe in self.variants(ir):
            self.assertEqual(run(exe, "2", "0"), b"M6\n")
            result = subprocess.run([exe, "9", "0"], capture_output=True, timeout=10)
            self.assertEqual((result.returncode, result.stdout), (-signal.SIGTRAP, b""), result.stderr)

    def test_rejections(self):
        self.lift(checked=False, reason="--checked-memory")
        self.lift(entry="string_length_helper", reason="proven image/stack provenance")
        # Replace the root prefix with a fixed pointer CALL while preserving its recorded extent.
        root = self.exports["string_length"]
        offset = self.layout.file_offset(root)
        helper = self.exports["string_length_helper"]
        call = self.layout.file_offset(helper) + 4
        slot = helper + 10 + struct.unpack_from("<i", self.original, call + 2)[0]
        for va, reason in ((1, "readable non-executable"),
                           (self.base + root, "readable non-executable"),
                           (self.base + slot, "protected loader-written")):
            data = bytearray(self.original)
            prefix = bytes.fromhex("4883ec28 48b9") + struct.pack("<Q", va)
            encoded = prefix + bytes.fromhex("ff15") + struct.pack("<i", slot - (root + len(prefix) + 6))
            encoded += bytes.fromhex("4883c428 c3")
            data[offset:offset + len(encoded)] = encoded
            image = self.work / "invalid.exe"
            image.write_bytes(data)
            self.lift(image, reason=reason)


if __name__ == "__main__":
    if platform.system() != "Darwin" or platform.machine() != "arm64":
        sys.exit(77)
    unittest.main(argv=[__file__], verbosity=2)
