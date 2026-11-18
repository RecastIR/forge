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

MODE, fixture_dir, *tools = sys.argv[1:]
if MODE == "compiler":
    CONTRACT, = tools
elif MODE == "object":
    CONTRACT, OPT, LLC, READOBJ = tools
elif MODE == "readiness":
    FORGE, = tools
elif MODE == "native":
    FORGE, CONTRACT, OPT, LLC, READOBJ, INVALID_ARTIFACT, PROCESS_HARNESS, *LINK = tools
FIXTURES = Path(fixture_dir)
NAMES = ("return", "call", "data", "fault", "last-error")
GREETING = b"Hello from Windows!\n"
BINARY = b"A\x00\xff\n"


def run(*args, **options):
    return subprocess.run(args, capture_output=True, text=True, timeout=30, **options)


def image(name):
    return FIXTURES / f"executable-{name}.exe"


def console_image(name):
    return FIXTURES / ("hello.exe" if name == "hello" else f"console-{name}.exe")


def entry(data):
    layout = Layout(data)
    return layout.u32(layout.opt + 16)


def header_result(data):
    # The PE entry combines its DOS string length, DOS/NT signatures, preferred
    # ImageBase and first section name. Read the expected DWORD from the source file.
    layout = Layout(data)
    dos_and_nt = data.index(0) + layout.u32(0) + layout.u32(layout.pe)
    return ((dos_and_nt ^ layout.u32(layout.opt + 24)) + layout.u32(layout.section_table)) & 0xffffffff


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


class Portable(Workspace):
    def test_artifact_ir(self):
        for name in (*NAMES, "headers"):
            with self.subTest(name=name):
                pe = image(name)
                compiled = run(CONTRACT, pe, check=True).stdout
                self.assertIn("define dso_local ptr @forge_lifted_artifact(", compiled)
                if name == "call":
                    call = direct_call(pe.read_bytes())
                    target = int(call["target_rva"], 16)
                    self.assertLess(target, int(call["caller_rva"], 16))
                    self.assertIn(f"call i1 @forge_guest_{target:x}(", compiled)

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


class Object(Workspace):
    def test_arm64_object(self):
        for name in (*NAMES, "headers"):
            with self.subTest(name=name):
                pe = image(name)
                obj = self.dir / "artifact.o"
                run(CONTRACT, pe, "--object", obj, OPT, LLC, check=True)
                headers = run(READOBJ, "--file-headers", obj, check=True).stdout
                self.assertIn("Format: Mach-O arm64", headers)
                self.assertIn("FileType: Relocatable", headers)

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


class StartupAdmission(Workspace):
    def test_fixed_header_access(self):
        data = bytearray(image("headers").read_bytes())
        layout = Layout(data)
        start = layout.file_offset(entry(data))
        length = layout.u32(layout.opt + 60)
        # Read a DWORD at the last byte, or store AL at RVA zero.
        for opcode, rva, message in ((b"\x8b\x05", length - 1, "image access"),
                                     (b"\x88\x05", 0, "immutable")):
            with self.subTest(rva=rva):
                code = b"\x31\xc0" + opcode + struct.pack("<i", rva - (entry(data) + 8)) + b"\xc3"
                data[start:start + len(code)] = code
                self.reject(data, "LIFT_IMAGE_MEMORY", message)

    def test_header_counts_toward_image_budget(self):
        data = bytearray(image("fault").read_bytes())
        layout = Layout(data)
        _, rva, _, _ = layout.sections[-1]
        section = layout.section_header(rva)
        self.assertTrue(data.startswith(b".pdata\0", section))
        # The unknown load selects the large zero tail. Its extent alone fits the
        # immutable image budget, but the header backing puts the image over it.
        length = (32 << 20) - 8
        struct.pack_into("<I", data, section + 8, length)
        struct.pack_into("<I", data, layout.opt + 56, (rva + length + 4095) & ~4095)
        self.reject(data, "LIFT_IMAGE_MEMORY", "module limit for immutable extent")

    def test_conflicting_or_malformed_headers(self):
        original = image("headers").read_bytes()
        layout = Layout(original)
        reloc = layout.file_offset(layout.directory(5)[0])
        for offset, patch, code, message in (
            (layout.opt + 60, struct.pack("<I", len(original) + 512), "INVALID_PE", "SizeOfHeaders"),
            (layout.section_table + 12, struct.pack("<I", 8), "INVALID_PE", "overlaps image headers"),
            (reloc, struct.pack("<IIH", 0, layout.u32(reloc + 4), 0xa040),
             "EXECUTABLE_UNSUPPORTED_STARTUP", "relocation in PE headers at RVA 0x40"),
            (layout.directories + 12 * 8, struct.pack("<II", 0x48, 8),
             "EXECUTABLE_UNSUPPORTED_STARTUP", "loader write in PE headers at RVA 0x48"),
        ):
            with self.subTest(reason=message):
                data = bytearray(original)
                data[offset:offset + len(patch)] = patch
                self.reject(data, code, message)

    def reject(self, data, code, reason, *, guest_base=None):
        source = self.dir / "candidate.exe"
        source.write_bytes(data)
        self.output.write_bytes(b"previous object")
        selection = [] if guest_base is None else ["--guest-base", hex(guest_base)]
        result = run(CONTRACT, *selection, source, "--object", self.output, self.dir / "unused-opt",
                     self.dir / "unused-llc")
        self.assertEqual(result.returncode, 1)
        self.assertIn(code, result.stderr)
        self.assertIn(reason, result.stderr)
        self.assertEqual(self.output.read_bytes(), b"previous object")

    def test_zero_selected_base(self):
        data = bytearray(image("headers").read_bytes())
        self.reject(data, "EXECUTABLE_UNSUPPORTED_STARTUP", "null guest address", guest_base=0)
        struct.pack_into("<Q", data, Layout(data).opt + 24, 0)
        self.reject(data, "EXECUTABLE_UNSUPPORTED_STARTUP", "null guest address")

    def test_loader_requirements(self):
        for name, reason in (("manifest", "manifest"), ("integrity", "signature verification")):
            with self.subTest(name=name):
                self.reject(image(name).read_bytes(), "EXECUTABLE_UNSUPPORTED_STARTUP", reason)

    def test_resource_directory(self):
        data = bytearray(image("manifest").read_bytes())
        layout = Layout(data)
        rva, size = layout.directory(2)
        root = layout.file_offset(rva)
        self.assertEqual(struct.unpack_from("<HHI", data, root + 12), (0, 1, 24))
        # Resource data directories are addressed by RVA even with a custom section name.
        section = layout.section_header(rva)
        data[section:section + 8] = b".assets\0"
        self.reject(data, "EXECUTABLE_UNSUPPORTED_STARTUP", "manifest")

        # FindResourceW resolves this numeric type as RT_MANIFEST on the Wine reference.
        struct.pack_into("<I", data, root + 16, 0x10018)
        self.reject(data, "EXECUTABLE_UNSUPPORTED_STARTUP", "manifest")

        # Keep the same well-formed tree and payload under the opaque RCDATA type.
        struct.pack_into("<I", data, root + 16, 10)
        source = self.dir / "ordinary-resource.exe"
        source.write_bytes(data)
        run(CONTRACT, source, check=True)

        named = data.copy()
        name_offset = (size - 4) & ~1
        struct.pack_into("<HHI", named, root + 12, 1, 0, 0x80000000 | name_offset)
        struct.pack_into("<HH", named, root + name_offset, 1, ord("T"))
        source.write_bytes(named)
        run(CONTRACT, source, check=True)

        for field, value in ((0, 0), (4, 0), (4, 15), (4, 20), (4, size + len(data))):
            with self.subTest(field=field, value=value):
                malformed = data.copy()
                struct.pack_into("<I", malformed, layout.directories + 2 * 8 + field, value)
                self.reject(malformed, "INVALID_PE", "resource directory")

        for field, value in ((16, 10), (16, 0x80000000 | size), (20, 24), (20, 0x80000000 | size)):
            with self.subTest(root_field=field, value=value):
                malformed = named.copy()
                struct.pack_into("<I", malformed, root + field, value)
                self.reject(malformed, "INVALID_PE", "resource directory")

    def test_section_order_and_gap(self):
        data = bytearray(image("return").read_bytes())
        layout = Layout(data)
        left = layout.section_table + 40
        right = left + 40
        data[left:right], data[right:right + 40] = data[right:right + 40], data[left:right]
        self.reject(data, "EXECUTABLE_UNSUPPORTED_STARTUP", "expected adjacent section")

        data = bytearray(image("data").read_bytes())
        layout = Layout(data)
        # Shorten the multi-page zero tail, leaving the following .pdata RVA intact.
        header = next(layout.section_header(start) for size, start, raw, _ in layout.sections
                      if size > raw)
        struct.pack_into("<I", data, header + 8, layout.u32(header + 16))
        self.reject(data, "EXECUTABLE_UNSUPPORTED_STARTUP", "expected adjacent section")

    def test_raw_data_with_zero_virtual_size(self):
        data = bytearray(image("fault").read_bytes())
        layout = Layout(data)
        count = len(layout.sections)
        header = layout.section_table + 40 * count
        self.assertLessEqual(header + 40, layout.u32(layout.opt + 60))
        start = layout.u32(layout.opt + 56)
        file_alignment = layout.u32(layout.opt + 36)
        self.assertEqual(len(data) % file_alignment, 0)
        struct.pack_into("<H", data, layout.pe + 6, count + 1)
        struct.pack_into("<8sIIIIIIHHI", data, header, b".extra", 0, start, file_alignment,
                         len(data), 0, 0, 0, 0, 0x40000040)
        data.extend(bytes(file_alignment))
        data[-file_alignment] = 42

        root = entry(data)
        instruction = layout.file_offset(root)
        self.assertTrue(data.startswith(bytes.fromhex("488b0d"), instruction))
        pointer = root + 7 + struct.unpack_from("<i", data, instruction + 3)[0]
        base = struct.unpack_from("<Q", data, layout.opt + 24)[0]
        struct.pack_into("<Q", data, layout.file_offset(pointer), base + start)
        struct.pack_into("<I", data, layout.opt + 56, start + layout.u32(layout.opt + 32))
        self.reject(data, "EXECUTABLE_UNSUPPORTED_STARTUP", ".extra has raw data with zero virtual size")


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

    def test_manifest_and_integrity_diagnostics(self):
        for requirement in ("manifest", "integrity"):
            with self.subTest(requirement=requirement):
                diagnostic = self.reject(image(requirement).read_bytes())
                self.assertEqual(diagnostic["code"], "EXECUTABLE_UNSUPPORTED_STARTUP")
                context = diagnostic["context"]
                self.assertTrue(context["entry_recovered"] and context["recovery_complete"])

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


class Reference(Workspace):
    def capture(self, source):
        suite = Path(__file__).resolve().parents[1] / "differential"
        sys.path.insert(0, str(suite))
        sys.path.insert(0, str(suite / "reference"))
        from docker_wine import execute
        from fixture_images import reference_environment

        pe = self.dir / source.name
        shutil.copyfile(source, pe)
        result = execute(reference_environment(suite)["container_image_id"], pe, [])
        return result.exit_code, result.stdout, result.stderr

    def test_header_result(self):
        pe = image("headers")
        self.assertEqual(self.capture(pe), (header_result(pe.read_bytes()), b"", b""))

    def test_console_results(self):
        for name, expected in (("hello", (0, GREETING, b"")), ("binary_stdout", (4, BINARY, b"")),
                               ("binary_stderr", (4, b"", BINARY)),
                               ("nested_exit", (0xcafe002a, b"", b""))):
            with self.subTest(name=name):
                self.assertEqual(self.capture(console_image(name)), expected)


class Console(Workspace):
    def program(self, **streams):
        options = dict(stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.DEVNULL)
        return subprocess.run([self.output], timeout=10, **(options | streams))

    def test_hello(self):
        diagnostic = self.compile(console_image("hello"))
        self.assertEqual(diagnostic["code"], "EXECUTABLE_READY")
        self.assertEqual({(row["dll"].lower(), row["name"]) for row in diagnostic["context"]["imports"]},
                         {("kernel32.dll", name) for name in ("GetStdHandle", "WriteFile", "ExitProcess")})
        self.assertIn("Format: Mach-O arm64", run(READOBJ, "--file-headers", self.output, check=True).stdout)
        result = self.program()
        self.assertEqual((result.returncode, result.stdout, result.stderr), (0, GREETING, b""))

        # Changing only the guest .rdata bytes must change native output byte for byte.
        changed = self.dir / "changed.exe"
        contents = console_image("hello").read_bytes()
        self.assertEqual(contents.count(GREETING), 1)
        replacement = GREETING[:-2] + b"?\x00"
        changed.write_bytes(contents.replace(GREETING, replacement))
        self.compile(changed)
        result = self.program()
        self.assertEqual((result.returncode, result.stdout, result.stderr), (0, replacement, b""))

    def test_binary_redirection_and_count(self):
        for name, stream in (("binary_stdout", "stdout"), ("binary_stderr", "stderr")):
            with self.subTest(name=name):
                self.compile(console_image(name))
                result = self.program()
                expected = (BINARY, b"") if stream == "stdout" else (b"", BINARY)
                self.assertEqual((result.returncode, result.stdout, result.stderr), (len(BINARY), *expected))
                path = self.dir / "redirected.bin"
                with path.open("wb") as redirected:
                    result = self.program(**{stream: redirected})
                other = result.stderr if stream == "stdout" else result.stdout
                self.assertEqual((result.returncode, other, path.read_bytes()), (len(BINARY), b"", BINARY))

        self.compile(console_image("large_output"))
        result = self.program()
        self.assertEqual((result.returncode, result.stdout, result.stderr), (0, b"a" * 65537, b""))

    def test_api_results(self):
        for name, code in (("bad_handle", 6), ("stdin_write", 5), ("bad_selector", 6),
                           ("stdin_handle", 0), ("null_count", 87), ("overlapped", 50),
                           ("zero_length", 0)):
            with self.subTest(name=name):
                self.compile(console_image(name))
                result = self.program()
                self.assertEqual((result.returncode, result.stdout, result.stderr), (code, b"", b""))

    def test_preflight_before_output(self):
        for name in ("bad_buffer", "bad_count"):
            with self.subTest(name=name):
                pe = console_image(name)
                if name == "bad_buffer":
                    data = pe.read_bytes()
                    layout = Layout(data)
                    size, rva, _, _ = next(s for s in layout.sections
                                          if data.startswith(b".badbuf\0", layout.section_header(s[1])))
                    self.assertEqual(size, 65537)
                    base = struct.unpack_from("<Q", data, layout.opt + 24)[0]
                    address, access, reason = base + rva + size, 1, 2
                else:
                    address, access, reason = 0x70001000 - 40, 2, 4
                self.compile(pe)
                result = self.program()
                expected = f"forge: guest memory fault address={address:#x} access={access} reason={reason}\n"
                self.assertEqual((result.returncode, result.stdout, result.stderr), (125, b"", expected.encode()))

    def test_host_failures(self):
        self.compile(console_image("host_failure"))
        reader, writer = os.pipe()
        os.close(reader)
        with os.fdopen(writer, "wb") as broken:
            result = self.program(stdout=broken)
        self.assertEqual((result.returncode, result.stderr), (109, b""))
        with console_image("host_failure").open("rb") as read_only:
            result = self.program(stdout=read_only)
        self.assertEqual((result.returncode, result.stderr), (6, b""))

    def test_file_size_limit(self):
        import resource
        import signal

        def limit_output_file():
            signal.signal(signal.SIGXFSZ, signal.SIG_DFL)
            resource.setrlimit(resource.RLIMIT_FSIZE, (2, 2))

        self.compile(console_image("limited_file"))
        path = self.dir / "limited.bin"
        with path.open("wb") as stream:
            result = self.program(stdout=stream, preexec_fn=limit_output_file)
        # The guest checks FALSE and a count of two, then returns GetLastError().
        self.assertEqual((result.returncode, result.stderr, path.read_bytes()), (112, b"", BINARY[:2]))

    def test_termination(self):
        for name, status, stderr in (("direct_exit", 42, b""), ("nested_exit", 42, b""),
                                     ("alternate_edge", 9, BINARY)):
            with self.subTest(name=name):
                self.compile(console_image(name))
                result = self.program()
                self.assertEqual((result.returncode, result.stdout, result.stderr), (status, b"", stderr))

    def test_same_artifact_in_two_processes(self):
        _, runtime, sdk, *flags = LINK
        obj = self.dir / "isolation.o"
        run(CONTRACT, console_image("isolation"), "--object", obj, OPT, LLC, check=True)
        run("/usr/bin/xcrun", "--sdk", sdk, "clang++", "-arch", "arm64", *flags,
            PROCESS_HARNESS, obj, runtime, "-o", self.output, check=True)
        captured = self.dir / "stderr.bin"
        with captured.open("wb") as stream:
            result = subprocess.run([self.output, "console", "0", "0", "0", "0"], input=b"ss",
                                    stdout=subprocess.PIPE, stderr=stream, timeout=10)
        self.assertEqual((result.returncode, captured.read_bytes()), (0, (BINARY + b"!") * 2))
        self.assertEqual(result.stdout.splitlines()[-2:], [f"exit {0xcafe002a}".encode()] * 2)


class Native(Workspace):
    def test_header_reads_and_rebase(self):
        pe = image("headers")
        data = pe.read_bytes()
        expected = header_result(data)
        base = struct.unpack_from("<Q", data, Layout(data).opt + 24)[0]
        _, runtime, sdk, *flags = LINK
        for chosen in (base, base + 0x50000000):
            with self.subTest(guest_base=hex(chosen)):
                args = [CONTRACT, "--guest-base", hex(chosen), pe]
                obj = self.dir / "headers.o"
                run(*args, "--object", obj, OPT, LLC, check=True)
                run("/usr/bin/xcrun", "--sdk", sdk, "clang++", "-arch", "arm64", *flags,
                    PROCESS_HARNESS, obj, runtime, "-o", self.output, check=True)
                process = run(self.output, "run", "0", "0", check=True)
                self.assertEqual(process.stdout.splitlines()[-1], f"return {expected}")
                self.assertEqual(process.stderr, "")
                run(*args, self.output, OPT, LLC, "/usr/bin/xcrun", *LINK, check=True)
                program = run(self.output)
                self.assertEqual((program.returncode, program.stdout, program.stderr),
                                 (expected & 255, "", ""))
        self.compile(pe)
        program = run(self.output)
        self.assertEqual((program.returncode, program.stdout, program.stderr), (expected & 255, "", ""))

    def test_header_permissions_and_bounds(self):
        pe = self.dir / "bounds.exe"
        data = bytearray(image("headers").read_bytes())
        layout = Layout(data)
        root = entry(data)
        start = layout.file_offset(root)
        base = struct.unpack_from("<Q", data, layout.opt + 24)[0]
        length = layout.u32(layout.opt + 60)
        pointer = next(rva for _, rva, _, _ in layout.sections
                       if data.startswith(b".data\0", layout.section_header(rva)))
        pointer_offset = layout.file_offset(pointer)
        self.assertEqual(struct.unpack_from("<Q", data, pointer_offset)[0], base)
        data[length - 1] = 87
        # mov rcx,[rip+pointer]; xor eax,eax; execute the checked load/store; ret
        load_pointer = bytes.fromhex("488b0d") + struct.pack("<i", pointer - root - 7) + bytes.fromhex("31c0")
        for offset, operation, status, detail in (
            (length - 1, "0fb601", 87, ""),
            (length - 1, "8b01", 125, f"address={hex(base + length)} access=1 reason=2"),
            (0, "8901", 125, f"address={hex(base)} access=2 reason=3"),
            (0, "0101", 125, f"address={hex(base)} access=3 reason=3"),
        ):
            with self.subTest(offset=offset, operation=operation):
                code = load_pointer + bytes.fromhex(operation) + b"\xc3"
                data[start:start + len(code)] = code
                struct.pack_into("<Q", data, pointer_offset, base + offset)
                pe.write_bytes(data)
                self.compile(pe)
                result = run(self.output)
                expected_error = f"forge: guest memory fault {detail}\n" if detail else ""
                self.assertEqual((result.returncode, result.stdout, result.stderr),
                                 (status, "", expected_error))

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
    suites = {"compiler": ("Portable", "StartupAdmission"), "object": ("Object",),
              "readiness": ("Readiness",), "native": ("Native", "Console"), "reference": ("Reference",)}
    unittest.main(argv=[__file__, *suites[MODE]], verbosity=2)
