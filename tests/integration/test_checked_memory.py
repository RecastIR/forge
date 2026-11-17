"""Exercise guest and service access to the same backing in linked ARM64 code."""
import json
from pathlib import Path
import platform
import subprocess
import sys
import tempfile
import unittest


FORGE, IMAGE, OPT, LLC, HARNESS, RUNTIME, *LINKER = sys.argv[1:]


def run(*args):
    return subprocess.check_output(args, timeout=30)


class CheckedMemory(unittest.TestCase):
    def test_suspended_service(self):
        module = json.loads(run(FORGE, "inspect", IMAGE, "--format", "json"))["modules"][0]
        exports = {name: int(entry["rva"], 16) for entry in module["exports"] for name in entry["names"]}
        base = int(module["image_base_va"], 16)
        data = next(section for section in module["sections"] if section["name"] == ".data")
        self.assertGreater(data["virtual_size"], data["raw_size"])
        with tempfile.TemporaryDirectory() as directory:
            ir = Path(directory) / "bridge.ll"
            run(FORGE, "lift", IMAGE, "--signature", "i64(i64,i64)", "--checked-memory",
                "--rva", hex(exports["entry"]), "--output", ir)
            source = ir.read_text()
            self.assertEqual(source.count("call i32 @forge_rt_enter("), 1)
            self.assertEqual(source.count("call i32 @forge_rt_leave("), 1)
            self.assertNotIn("@forge_rt_read_guest(", source)
            self.assertNotIn("@forge_rt_write_guest(", source)

            # Interpose only this import. The real shim uses the public bridge and
            # forwards to GetLastError while the guest frame and return slot are live.
            self.assertEqual(source.count("call i32 @forge_rt_get_last_error("), 1)
            ir.write_text(source.replace("@forge_rt_get_last_error(", "@probe_get_last_error("))
            optimized = ir.with_suffix(".o2.ll")
            run(OPT, "-passes=verify", "-disable-output", ir)
            run(OPT, "-S", "-passes=default<O2>", ir, "-o", optimized)
            for variant in (ir, optimized):
                with self.subTest(variant=variant.name):
                    run(OPT, "-passes=verify", "-disable-output", variant)
                    # A second native artifact supplies fresh image globals at
                    # the identical guest VA for the second guest process.
                    other = variant.with_suffix(".second.ll")
                    other.write_text(variant.read_text().replace("@forge_lifted_with_runtime(",
                                                                 "@second_lifted_with_runtime(")
                                     .replace("@forge_lifted_image(", "@second_lifted_image("))
                    objects = []
                    for source in (variant, other):
                        obj = source.with_suffix(".o")
                        run(LLC, "-filetype=obj", source, "-o", obj)
                        objects.append(obj)
                    exe = variant.with_suffix(".exe")
                    run(*LINKER, HARNESS, *objects, RUNTIME, "-o", exe)
                    run(exe, str(base + exports["bridge_value"]), str(base + exports["bridge_constant"]))


if __name__ == "__main__":
    if platform.system() != "Darwin" or platform.machine() != "arm64":
        sys.exit(77)
    unittest.main(argv=[__file__], verbosity=2)
