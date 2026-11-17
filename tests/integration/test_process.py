"""Run the single compiled process artifact against fresh, simultaneously registered instances."""
import json
from pathlib import Path
import platform
import subprocess
import sys
import tempfile
import unittest


FORGE, FIXTURES, OPT, LLC, LIFT, DRIVER, ADAPTERS, RUNTIME, *LINKER = sys.argv[1:]
ENTRY_RSP = 0x70001000 - 40
READ, WRITE = 1, 2
UNMAPPED, PERMISSION, STACK = 2, 3, 4


def run(*args):
    return subprocess.check_output(args, text=True, timeout=30)


def memory(address, access, reason):
    return f"memory {address} {access} {reason}"


class ProcessExecution(unittest.TestCase):
    def exercise(self, image, entry, cases, *, base=None, imports=(), probe=False, fail_get=False):
        pe = Path(FIXTURES) / f"{image}.exe"
        module = json.loads(run(FORGE, "inspect", pe, "--format", "json"))["modules"][0]
        pe_entry = int(module["entry_point_rva"], 16)
        exports = {n: int(e["rva"], 16) for e in module.get("exports", []) for n in e["names"]}
        rva = pe_entry if entry is None else exports[entry]
        base = int(module["image_base_va"], 16) if base is None else base
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / "process.ll"
            ir = run(LIFT, "--emit-process", pe, hex(rva), hex(base))
            self.assertNotIn("llvm.trap", ir)
            if probe:
                self.assertIn("call i32 @forge_rt_get_last_error(", ir)
                ir = ir.replace("@forge_rt_get_last_error(", "@probe_process_get(")
            source.write_text(ir)
            optimized = source.with_suffix(".o2.ll")
            run(OPT, "-S", "-passes=default<O2>", source, "-o", optimized)
            for variant in (source, optimized):
                with self.subTest(image=image, entry=entry, mode=variant.name):
                    run(OPT, "-passes=verify", "-disable-output", variant)
                    obj, exe = variant.with_suffix(".o"), variant.with_suffix(".exe")
                    run(LLC, "-filetype=obj", variant, "-o", obj)
                    run(*LINKER, DRIVER, ADAPTERS, obj, RUNTIME, "-o", exe)
                    args = [str(v) for a, b, _ in cases for v in (a, b)]
                    lines = run(exe, "fail-get" if fail_get else "run", *args).splitlines()
                    self.assertEqual(lines[0], f"entry {base} {rva} {pe_entry}")
                    actual_imports = []
                    for line in lines[1:]:
                        if not line.startswith("import "):
                            break
                        _, dll, symbol = line.split()
                        actual_imports.append((dll.lower(), symbol))
                    self.assertCountEqual(actual_imports, imports)
                    self.assertEqual(lines[1 + len(imports):], [answer for _, _, answer in cases])

    def test_header_entry(self):
        self.exercise("add", None, [(23, 47, "return 70"), (0, 0, "return 0"),
                                    (-1, 0, f"return {2**64-1}")])
        pe = Path(FIXTURES) / "add.exe"
        module = json.loads(run(FORGE, "inspect", pe, "--format", "json"))["modules"][0]
        # Even an addition with no stack operations reserves the whole PE in managed mode.
        invalid = subprocess.run([LIFT, "--emit-process", pe, module["entry_point_rva"], "0x70000000"],
                                 capture_output=True, text=True, timeout=10)
        self.assertEqual((invalid.returncode, invalid.stdout), (1, ""))
        self.assertIn("overlaps the guest stack", invalid.stderr)

    def test_rebased_writable_alias(self):
        # Each run reads the same initial counter through a relocated PE pointer.
        self.exercise("image", "update_alias", [(3, 0, "return 4663"), (11, 0, "return 4671"),
                                                (0, 0, "return 4660")], base=0x10000000)

    def test_scalar_faults(self):
        pe = Path(FIXTURES) / "image.exe"
        module = json.loads(run(FORGE, "inspect", pe, "--format", "json"))["modules"][0]
        literal = next(s for s in module["sections"] if s["name"] == ".literal")
        start = int(module["image_base_va"], 16) + int(literal["rva"], 16)
        end = start + literal["virtual_size"]
        self.exercise("image", "load32", [(start, 0, "return 2018915346"),
                                           (end-1, 0, memory(end, READ, UNMAPPED)),
                                           (1, 0, memory(1, READ, UNMAPPED))])
        self.exercise("image", "write32", [(start, 123, memory(start, WRITE, PERMISSION))])

    def test_stack_guard_and_service_failures(self):
        getter = [("kernel32.dll", "GetLastError")]
        self.exercise("checked-memory", "guard_then_service",
                      [(0, 17, "Greturn 0"), (8, 17, memory(ENTRY_RSP, WRITE, STACK))],
                      imports=getter, probe=True)
        self.exercise("checked-memory", "guard_then_service", [(0, 17, "Gruntime 4")],
                      imports=getter, probe=True, fail_get=True)
        self.exercise("stack", "call_misaligned", [(0, 0, "guard 3")])
        self.exercise("stack", "call_bad_teardown", [(0, 0, "guard 2")])

    def test_pointer_service_and_fault_order(self):
        imports = [("kernel32.dll", n) for n in ("SetLastError", "GetLastError", "lstrlenA")]
        cases = [(8, 0, "Greturn 6"), (4, 0, "Greturn 4"),
                 (9, 0, memory(ENTRY_RSP - 8 - 64 + 40, READ, STACK)), (5, 0, "Greturn 6")]
        self.exercise("lstrlen", "string_length", cases, imports=imports, probe=True)

    def test_generalized_service_abi(self):
        total = (23 + 3*29 - 5 + 7*13 - 11*17 + 13*0x7000000000000013) % 2**64
        self.exercise("service-abi", "six",
                      [(23, 29, f"Sreturn {total}"), (0, 29, memory(ENTRY_RSP - 56 + 40, READ, STACK))],
                      imports=[("forgeabi.dll", "Six")])
        imports = [("kernel32.dll", n) for n in ("SetLastError", "GetLastError")]
        imports.append(("forgeabi.dll", "WriteProbe"))
        self.exercise("service-abi", "write_call", [(0, 0, "WGreturn 201"), (1, 0, "WGreturn 410"),
                      (3, 0, memory(ENTRY_RSP, WRITE, STACK))], imports=imports, probe=True)


if __name__ == "__main__":
    if platform.system() != "Darwin" or platform.machine() != "arm64":
        sys.exit(77)
    unittest.main(argv=[__file__], verbosity=2)
