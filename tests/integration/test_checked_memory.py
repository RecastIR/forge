"""Exercise checked guest memory across native service calls in linked ARM64 code."""
import json
from pathlib import Path
import platform
import signal
import subprocess
import sys
import tempfile
import unittest


FORGE, IMAGE, OPT, LLC, HARNESS, RUNTIME, *LINKER = sys.argv[1:]


def run(*args):
    return subprocess.check_output(args, timeout=30)


def compile_object(ir, prefix=None):
    if prefix:
        # Each independently linked artifact needs distinct public entry and image symbols.
        renamed = ir.with_suffix(f".{prefix}.ll")
        renamed.write_text(ir.read_text().replace("@forge_lifted_", f"@{prefix}_lifted_"))
        ir = renamed
    obj = ir.with_suffix(".o")
    run(LLC, "-filetype=obj", ir, "-o", obj)
    return obj


class CheckedMemory(unittest.TestCase):
    def lift_variants(self, rva, ir, getter):
        run(FORGE, "lift", IMAGE, "--signature", "i64(i64,i64)", "--checked-memory",
            "--rva", hex(rva), "--output", ir)
        source = ir.read_text()
        self.assertNotIn("@forge_lifted_artifact(", source)
        self.assertEqual(source.count("call i32 @forge_rt_enter("), 1)
        self.assertEqual(source.count("call i32 @forge_rt_leave("), 1)
        self.assertNotIn("@forge_rt_read_guest(", source)
        self.assertNotIn("@forge_rt_write_guest(", source)

        self.assertEqual(source.count("call i32 @forge_rt_get_last_error("), 1)
        ir.write_text(source.replace("@forge_rt_get_last_error(", f"@{getter}("))
        optimized = ir.with_suffix(".o2.ll")
        run(OPT, "-passes=verify", "-disable-output", ir)
        run(OPT, "-S", "-passes=default<O2>", ir, "-o", optimized)
        run(OPT, "-passes=verify", "-disable-output", optimized)
        return ir, optimized

    def check_guard(self, exe):
        for offset, status, markers in ((0, 0, b"G"), (8, -signal.SIGTRAP, b"")):
            with self.subTest(offset=offset):
                child = subprocess.run([exe, "--guard", str(offset)], capture_output=True, timeout=10)
                self.assertEqual((child.returncode, child.stdout), (status, markers), child.stderr)

    def test_linked_services(self):
        module = json.loads(run(FORGE, "inspect", IMAGE, "--format", "json"))["modules"][0]
        exports = {name: int(entry["rva"], 16) for entry in module["exports"] for name in entry["names"]}
        base = int(module["image_base_va"], 16)
        data = next(section for section in module["sections"] if section["name"] == ".data")
        self.assertGreater(data["virtual_size"], data["raw_size"])
        with tempfile.TemporaryDirectory() as directory:
            work = Path(directory)
            bridges = self.lift_variants(exports["entry"], work / "bridge.ll", "probe_get_last_error")
            guards = self.lift_variants(exports["guard_then_service"], work / "guard.ll", "marker_get_last_error")
            for bridge, guard in zip(bridges, guards):
                with self.subTest(variant=guard.name):
                    # The second guest process needs fresh bridge globals at the identical guest VA.
                    exe = bridge.with_suffix(".exe")
                    run(*LINKER, HARNESS, compile_object(bridge), compile_object(bridge, "second"),
                        compile_object(guard, "guard"), RUNTIME, "-o", exe)
                    run(exe, str(base + exports["bridge_value"]), str(base + exports["bridge_constant"]))
                    self.check_guard(exe)


if __name__ == "__main__":
    if platform.system() != "Darwin" or platform.machine() != "arm64":
        sys.exit(77)
    unittest.main(argv=[__file__], verbosity=2)
