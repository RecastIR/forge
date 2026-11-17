"""Execute SDK-free Windows x64 calls against statically bound test adapters."""
import json
from pathlib import Path
import platform
import signal
import subprocess
import sys
import tempfile
import unittest


FORGE, PE, OPT, LLC, LIFT, DRIVER, ADAPTERS, RUNTIME, *LINKER = sys.argv[1:]


def run(*command):
    return subprocess.check_output(command, timeout=30)


class ServiceAbi(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        module = json.loads(run(FORGE, "inspect", PE, "--format", "json"))["modules"][0]
        cls.base = module["image_base_va"]
        cls.exports = {name: entry["rva"] for entry in module["exports"] for name in entry["names"]}

    def command(self, entry, checked):
        return [LIFT, "--emit-abi-checked" if checked else "--emit-abi", PE, self.exports[entry], self.base]

    def execute(self, entry, cases, checked=False):
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / "module.ll"
            source.write_bytes(run(*self.command(entry, checked)))
            optimized = source.with_suffix(".o2.ll")
            run(OPT, "-S", "-passes=default<O2>", source, "-o", optimized)
            for ir in (source, optimized):
                run(OPT, "-passes=verify", "-disable-output", ir)
                obj, exe = ir.with_suffix(".o"), ir.with_suffix(".exe")
                run(LLC, "-filetype=obj", ir, "-o", obj)
                run(*LINKER, DRIVER, ADAPTERS, obj, RUNTIME, "-o", exe)
                for a, b, expected in cases:
                    with self.subTest(entry=entry, args=(a, b), ir=ir.name):
                        child = subprocess.run([exe, str(a), str(b)], capture_output=True, timeout=10)
                        status = -signal.SIGTRAP if expected is None else 0
                        self.assertEqual((child.returncode, child.stdout), (status, expected or b""), child.stderr)

    def test_registers_and_returns(self):
        for entry, answer in (("pair", -7 * 2**32 + 0xfffffffe), ("triple", 0x6000000000000000 - 4 + 21),
                              ("four", 0xfffffff9), ("echo_bits", -81985529216486896)):
            self.execute(entry, [(0, 0, f"{answer}\n".encode())])

    def test_stack(self):
        total = 23 + 3*29 - 5 + 7*13 - 11*17 + 13*0x7000000000000013
        signed = (total + 2**63) % 2**64 - 2**63
        self.execute("six", [(23, 29, f"S{signed}\n".encode()), (0, 29, None)])
        self.execute("bad_stack", [(1, 2, None)])

    def test_buffers_and_effects(self):
        self.execute("write_call", [(0, 0, b"W201\n"), (1, 0, b"W410\n"), (5, 0, b"W198\n"),
                                    (2, 0, None), (3, 0, None), (6, 0, None)], True)
        self.execute("write_nested", [(0, 0, b"W205\n")], True)
        self.execute("disjoint_spill", [(0, 0, b"W5\n")], True)
        self.execute("image_output", [(0, 0, b"W3\n")], True)
        self.execute("unmapped", [(1, 0, None)], True)

    def test_rejections(self):
        for entry, checked, reason in (("bad_sig", False, b"vector values"),
                                       ("stale_spill", True, b"proven image/stack provenance"),
                                       ("readonly_output", True, b"requires writable PE data"),
                                       ("void_result", False, b"undefined RAX"),
                                       ("write_call", False, b"--checked-memory")):
            with self.subTest(entry=entry):
                child = subprocess.run(self.command(entry, checked), capture_output=True, timeout=10)
                self.assertEqual((child.returncode, child.stdout), (1, b""))
                self.assertIn(reason, child.stderr)
        with tempfile.TemporaryDirectory() as tmp:
            child = subprocess.run([FORGE, "lift", PE, "--rva", self.exports["six"], "--runtime",
                                    "--signature", "i64(i64,i64)", "--output", Path(tmp) / "lifted.ll"],
                                   capture_output=True, timeout=10)
        self.assertEqual(child.returncode, 1)
        self.assertIn(b"unsupported import ForgeAbi.dll!Six", child.stderr)


if __name__ == "__main__":
    if platform.system() != "Darwin" or platform.machine() != "arm64":
        sys.exit(77)
    unittest.main(argv=[__file__], verbosity=2)
