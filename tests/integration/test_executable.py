"""Compile a PE header entry and execute the linked program as its own native process."""
import json
import os
from pathlib import Path
import platform
import shutil
import struct
import subprocess
import sys
import tempfile
import unittest

from pe_layout import Layout

MODE, FORGE, fixture_dir, CONTRACT, OPT, LLC, READOBJ, *LINK = sys.argv[1:]
if MODE == "native":
    INVALID_ARTIFACT, PROCESS_HARNESS, *LINK = LINK
FIXTURES = Path(fixture_dir)
NAMES = ("return", "call", "data", "fault", "last-error")


def run(*args, **options):
    return subprocess.run(args, capture_output=True, text=True, timeout=30, **options)


def image(name):
    return FIXTURES / f"executable-{name}.exe"


def entry(data):
    layout = Layout(data)
    return layout.u32(layout.opt + 16)


def direct_call(data):
    root = entry(data)
    start = Layout(data).file_offset(root)
    # The entry reserves shadow space and passes 40 before its rel32 CALL.
    if not data.startswith(bytes.fromhex("4883ec28 b928000000 e8"), start):
        raise AssertionError("direct call missing from the linked fixture")
    site = root + 9
    target = site + 5 + struct.unpack_from("<i", data, start + 10)[0]
    return {"caller_rva": hex(root), "instruction_rva": hex(site), "target_rva": hex(target)}


class Workspace(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.dir = Path(directory.name).resolve()
        self.output = self.dir / "guest program"

    def compile(self, pe, *, success=True):
        result = run(FORGE, "lift", pe, "--executable", "--output", self.output,
                     "--diagnostics-format", "json")
        self.assertEqual(result.stdout, "")
        self.assertEqual(result.returncode, 0 if success else 1, result.stderr)
        return json.loads(result.stderr)


class Readiness(Workspace):
    def test_reachable_callee_unwind_handler(self):
        pe = FIXTURES / "stack.exe"
        module = json.loads(run(FORGE, "inspect", pe, "--format", "json", check=True).stdout)["modules"][0]
        exports = {name: item["rva"] for item in module["exports"] for name in item["names"]}
        callee = exports["call_result"]
        unwind = next(item["unwind_info_rva"] for item in module["exceptions"]["functions"]
                      if item["begin_rva"] == callee)
        data = bytearray(pe.read_bytes())
        layout = Layout(data)
        struct.pack_into("<I", data, layout.opt + 16, int(exports["call_released"], 16))
        data[layout.file_offset(int(unwind, 16))] |= 2 << 3  # UNW_FLAG_UHANDLER
        diagnostic = self.reject(data)
        self.assertEqual(diagnostic["code"], "EXECUTABLE_UNSUPPORTED_STARTUP")
        self.assertEqual(diagnostic["context"]["function_rva"], callee)
        self.assertTrue(diagnostic["context"]["recovery_complete"])

    def test_contradictory_layout(self):
        for field, value in ((36, 0), (36, 8192), (56, 0x4001)):
            with self.subTest(field=field, value=value):
                data = bytearray(image("return").read_bytes())
                layout = Layout(data)
                struct.pack_into("<I", data, layout.opt + field, value)
                diagnostic = self.reject(data)
                self.assertEqual(diagnostic["code"], "EXECUTABLE_UNSUPPORTED_STARTUP")
                self.assertIn("alignment", diagnostic["message"])

    def test_portable_codegen(self):
        for name in NAMES:
            with self.subTest(name=name):
                pe = image(name)
                compiled = run(CONTRACT, pe, check=True).stdout
                self.assertIn("define dso_local ptr @forge_lifted_artifact(", compiled)
                if name == "call":
                    call = direct_call(pe.read_bytes())
                    target = int(call["target_rva"], 16)
                    self.assertLess(target, int(call["caller_rva"], 16))
                    self.assertIn(f"call i1 @forge_guest_{target:x}(", compiled)
                obj = self.dir / "artifact.o"
                run(CONTRACT, pe, "--object", obj, OPT, LLC, check=True)
                headers = run(READOBJ, "--file-headers", obj, check=True).stdout
                self.assertIn("Format: Mach-O arm64", headers)
                self.assertIn("FileType: Relocatable", headers)

    def test_fixture_sections(self):
        data = image("data").read_bytes()
        layout = Layout(data)
        self.assertEqual(layout.directory(0), (0, 0))  # unexported PE entry
        root = entry(data)
        offset = layout.file_offset(root)
        self.assertEqual(data[offset + 7:offset + 9], b"\x83\x05")
        zero_rva = root + 14 + struct.unpack_from("<i", data, offset + 9)[0]
        header = layout.section_header(zero_rva)
        self.assertGreaterEqual(zero_rva - layout.u32(header + 12), layout.u32(header + 16))

    def test_shared_writable_data(self):
        data = bytearray(image("data").read_bytes())
        layout = Layout(data)
        headers = (layout.section_table + i * 40 for i in range(len(layout.sections)))
        header = next(h for h in headers if data[h:h + 8].rstrip(b"\0") == b".data")
        flags = layout.u32(header + 36)
        self.assertTrue(flags & 0x80000000)  # IMAGE_SCN_MEM_WRITE
        struct.pack_into("<I", data, header + 36, flags | 0x10000000)  # IMAGE_SCN_MEM_SHARED
        diagnostic = self.reject(data)
        self.assertEqual(diagnostic["code"], "EXECUTABLE_UNSUPPORTED_STARTUP")
        self.assertIn("shared writable section .data", diagnostic["message"])

    def test_object_failure_preserves_destination(self):
        self.output.write_bytes(b"previous object")
        for opt, llc, name in ((self.dir / "absent", LLC, "NATIVE_TOOL_UNAVAILABLE"),
                               ("/usr/bin/false", LLC, "NATIVE_OPTIMIZATION_FAILED"),
                               (OPT, "/usr/bin/false", "NATIVE_CODEGEN_FAILED")):
            with self.subTest(opt=opt, llc=llc):
                result = run(CONTRACT, image("return"), "--object", self.output, opt, llc)
                self.assertEqual(result.returncode, 1)
                self.assertIn(name, result.stderr)
                self.assertEqual(self.output.read_bytes(), b"previous object")
                self.assertEqual(list(self.dir.iterdir()), [self.output])

    def reject(self, data):
        source = self.dir / "bad.exe"
        source.write_bytes(data)
        self.output.write_bytes(b"previous output")
        diagnostic = self.compile(source, success=False)
        self.assertEqual(self.output.read_bytes(), b"previous output")
        return diagnostic

    def test_invalid_roots(self):
        for root in (0, entry(image("return").read_bytes()) + 1):
            with self.subTest(root=root):
                data = bytearray(image("return").read_bytes())
                struct.pack_into("<I", data, Layout(data).opt + 16, root)
                diagnostic = self.reject(data)
                self.assertEqual(diagnostic["context"]["entry_rva"], hex(root))
                self.assertFalse(diagnostic["context"]["entry_recovered"])

    def test_partial_runtime_function_directory(self):
        data = bytearray(image("return").read_bytes())
        layout = Layout(data)
        pdata, size = layout.directory(3)
        self.assertEqual(size, 12)
        struct.pack_into("<I", data, layout.section_header(pdata) + 8, size + 1)
        struct.pack_into("<II", data, layout.directories + 3 * 8, pdata, size + 1)
        diagnostic = self.reject(data)
        self.assertEqual(diagnostic["code"], "EXECUTABLE_UNSUPPORTED_STARTUP")
        self.assertIn("partial PE runtime function record", diagnostic["message"])
        self.assertFalse(diagnostic["context"]["entry_recovered"])
        self.assertFalse(diagnostic["context"]["recovery_complete"])

    def test_entry_arguments_and_instructions(self):
        for code, expected in (("89 c8 c3", "LIFT_UNDEFINED_REGISTER"),
                               ("c3", "LIFT_UNDEFINED_REGISTER"),
                               ("0f a2 c3", "LIFT_UNSUPPORTED_INSTRUCTION")):
            with self.subTest(code=code):
                data = bytearray(image("return").read_bytes())
                start = Layout(data).file_offset(entry(data))
                replacement = bytes.fromhex(code)
                data[start:start + len(replacement)] = replacement
                diagnostic = self.reject(data)
                self.assertEqual(diagnostic["code"], expected, diagnostic)
                self.assertTrue(diagnostic["context"]["entry_recovered"])

    def test_unknown_call(self):
        data = bytearray(image("call").read_bytes())
        call = direct_call(data)
        site = int(call["instruction_rva"], 16)
        invalid = 0x400000
        struct.pack_into("<i", data, Layout(data).file_offset(site) + 1, invalid - site - 5)
        diagnostic = self.reject(data)
        self.assertEqual(diagnostic["code"], "LIFT_INVALID_CALL_TARGET")
        context = diagnostic["context"]
        self.assertTrue(context["entry_recovered"])
        self.assertFalse(context["recovery_complete"])
        self.assertEqual(context["calls"], [])
        self.assertEqual(context["unresolved_calls"], [dict(call, target_rva=hex(invalid))])

    def test_unsupported_image_startup(self):
        data = bytearray(image("return").read_bytes())
        layout = Layout(data)
        pdata = layout.file_offset(layout.directory(3)[0])
        unwind = layout.file_offset(layout.u32(pdata + 8))
        for label in ("TLS", "CLR", "SEH", "align"):
            with self.subTest(requirement=label):
                changed = data.copy()
                if label == "TLS":
                    # A real PE TLS directory with callbacks and a data template.
                    changed = (FIXTURES / "metadata.exe").read_bytes()
                elif label == "CLR":
                    struct.pack_into("<II", changed, layout.directories + 14 * 8, entry(data), 72)
                elif label == "SEH":
                    changed[unwind] |= 1 << 3  # UNW_FLAG_EHANDLER
                else:
                    struct.pack_into("<I", changed, layout.opt + 32, 0x1800)
                diagnostic = self.reject(changed)
                self.assertRegex(diagnostic["message"].lower(),
                                 {"TLS": "tls", "CLR": "managed|clr", "SEH": "exception|unwind",
                                  "align": "align"}[label])

    def test_eager_unknown_import(self):
        data = bytearray((FIXTURES / "import-call.exe").read_bytes())
        start = Layout(data).file_offset(entry(data))
        data[start:start + 6] = bytes.fromhex("b82a000000 c3")
        diagnostic = self.reject(data)
        self.assertIn({"dll": "physics.dll", "name": "Named"},
                      [dict(item, dll=item["dll"].lower()) for item in diagnostic["context"]["imports"]])


class Native(Workspace):
    def test_full_process_result_and_isolation(self):
        # A shell status cannot expose the full DWORD, and separate host launches
        # cannot reveal accidentally shared mutable globals. Use the existing
        # two-process host for these additional observations of the same artifact.
        _, runtime, sdk, *flags = LINK
        data = bytearray(image("return").read_bytes())
        dword = 0xCAFE002A
        struct.pack_into("<I", data, Layout(data).file_offset(entry(data)) + 1, dword)
        high = self.dir / "dword.exe"
        high.write_bytes(data)
        for pe, expected in ((high, f"return {dword}"), (image("data"), "return 42"),
                             (image("fault"), "memory 1 1 2")):
            with self.subTest(pe=pe.name):
                obj = self.dir / "guest.o"
                run(CONTRACT, pe, "--object", obj, OPT, LLC, check=True)
                run("/usr/bin/xcrun", "--sdk", sdk, "clang++", "-arch", "arm64", *flags,
                    PROCESS_HARNESS, obj, runtime, "-o", self.output, check=True)
                result = run(self.output, "run", "0", "0", "0", "0", check=True)
                self.assertEqual(result.stderr, "")
                self.assertEqual(result.stdout.splitlines()[1:], [expected, expected])

    def test_startup_failures(self):
        for mode, expected in (("registration", "runtime failure stage=register"),
                               ("mismatch", "differs from PE entry"),
                               ("zero", "PE image has no entry point")):
            with self.subTest(mode=mode):
                result = run(INVALID_ARTIFACT, env=dict(os.environ, FORGE_TEST_ARTIFACT=mode))
                self.assertEqual((result.returncode, result.stdout), (125, ""))
                self.assertIn(expected, result.stderr)

    def test_compiled_programs(self):
        deployed = self.dir / "standalone" / "translated"
        deployed.parent.mkdir()
        # Keep the sanitizer's symbolizer available while testing an empty program search path.
        standalone_env = dict(os.environ, PATH="", ASAN_SYMBOLIZER_PATH="/usr/bin/atos",
                              UBSAN_SYMBOLIZER_PATH="/usr/bin/atos")
        for name in NAMES:
            for optimized in (False, True):
                with self.subTest(name=name, optimized=optimized):
                    pe = self.dir / "source.exe"
                    shutil.copyfile(image(name), pe)
                    original = pe.read_bytes()
                    if optimized:
                        diagnostic = self.compile(pe)
                        self.assertEqual(diagnostic["code"], "EXECUTABLE_READY")
                        context = diagnostic["context"]
                        self.assertEqual(context["architecture"], "AMD64")
                        self.assertEqual(context["entry_rva"], hex(entry(original)))
                        self.assertTrue(context["entry_recovered"] and context["recovery_complete"])
                        imports = ({("kernel32.dll", "SetLastError"), ("kernel32.dll", "GetLastError")}
                                   if name == "last-error" else set())
                        self.assertEqual({(s["dll"].lower(), s["name"]) for s in context["imports"]}, imports)
                        self.assertEqual(context["unresolved_calls"], [])
                        self.assertEqual(context["calls"], [direct_call(original)] if name == "call" else [])
                    else:
                        run(CONTRACT, pe, self.output, OPT, LLC, "/usr/bin/xcrun", *LINK, check=True)
                    pe.unlink()
                    self.output.replace(deployed)
                    headers = run(READOBJ, "--file-headers", deployed, check=True).stdout
                    self.assertIn("Format: Mach-O arm64", headers)
                    self.assertIn("FileType: Executable", headers)
                    dylibs = run("/usr/bin/otool", "-L", deployed, check=True).stdout.splitlines()[1:]
                    self.assertNotRegex("\n".join(dylibs).lower(), r"wine|rosetta|libforge")
                    expected = ((125, "", "forge: guest memory fault address=0x1 access=1 reason=2\n")
                                if name == "fault" else (42, "", ""))
                    for _ in range(2):
                        result = run(deployed, cwd=deployed.parent, env=standalone_env)
                        self.assertEqual((result.returncode, result.stdout, result.stderr), expected)

    def test_dword_exit(self):
        data = bytearray(image("return").read_bytes())
        offset = Layout(data).file_offset(entry(data))
        self.assertEqual(data[offset:offset + 6], bytes.fromhex("b82a000000 c3"))
        for dword in (0, 0xCAFE002A, 0xFFFF007D):
            with self.subTest(dword=dword):
                pe = self.dir / "return.exe"
                struct.pack_into("<I", data, offset + 1, dword)
                pe.write_bytes(data)
                self.compile(pe)
                result = run(self.output)
                self.assertEqual((result.returncode, result.stdout, result.stderr), (dword & 255, "", ""))

    def test_publication_failures(self):
        pe = image("return")
        args = [OPT, LLC, "/usr/bin/xcrun", *LINK]
        self.output.write_bytes(b"previous output")
        for index in (1, 2, 3, 4):
            with self.subTest(tool=args[index]):
                broken = args.copy()
                broken[index] = self.dir / "missing"
                result = run(CONTRACT, pe, self.output, *broken)
                self.assertEqual(result.returncode, 1, result.stderr)
                self.assertIn("NATIVE_TOOL_UNAVAILABLE", result.stderr)
                self.assertIn(str(broken[index]), result.stderr)
                self.assertEqual(self.output.read_bytes(), b"previous output")
                self.assertEqual(list(self.dir.iterdir()), [self.output])
        # A tool that exits zero without publishing an executable cannot replace a good file.
        no_link = args.copy()
        no_link[2] = "/usr/bin/true"
        failure = run(CONTRACT, pe, self.output, *no_link)
        self.assertEqual(failure.returncode, 1)
        self.assertIn("NATIVE_LINK_FAILED", failure.stderr)
        self.assertEqual(self.output.read_bytes(), b"previous output")

        self.output.write_bytes(pe.read_bytes())
        self.assertEqual(self.compile(self.output, success=False)["code"], "OUTPUT_ALIAS")
        self.assertEqual(self.output.read_bytes(), pe.read_bytes())


if __name__ == "__main__":
    if MODE == "native" and (platform.system(), platform.machine()) != ("Darwin", "arm64"):
        sys.exit(77)
    unittest.main(argv=[__file__, "Native" if MODE == "native" else "Readiness"], verbosity=2)
