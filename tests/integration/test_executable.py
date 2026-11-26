"""Compile a PE header entry and execute the linked program as its own native process."""
import hashlib
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
from zipfile import ZipFile

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
# SETO and LAHF byte pairs for the five memory comparisons in the linked PE.
CMP16MI = (42, bytes.fromhex("00 46 01 12 01 87 00 12 00 86"), b"")
# Pairs of (GetLastError, *_errno()) captured after six returning setter calls.
APP_TYPE_RECORD = b"".join(struct.pack("<II", 700 + offset, 100 + offset) for offset in range(0, 48, 8))
APP_TYPE_RETURN = (42, APP_TYPE_RECORD, b"")
AMSG_CASES = ("31", "8", "-1", "-2147483648", "unused")
AMSG_MARKERS = ("marker-control", "marker-fatal")


def run(*args, **options):
    return subprocess.run(args, capture_output=True, text=True, timeout=30, **options)


def image(name):
    return FIXTURES / f"executable-{name}.exe"


def console_image(name):
    return FIXTURES / ("hello.exe" if name == "hello" else f"console-{name}.exe")


def amsg_observations(reference, cases=AMSG_CASES):
    directory = Path(__file__).resolve().parents[1] / "differential/fixtures/startup/amsg-exit"
    with ZipFile(directory / f"{reference}-raw.zip") as archive:
        evidence = json.loads(archive.read("results.json"))
    observations = {}
    for case in cases:
        filename = f"crt-amsg-{case}.exe" if case in AMSG_MARKERS else f"crt-amsg-exit-{case}.exe"
        if hashlib.sha256((FIXTURES / filename).read_bytes()).hexdigest() != evidence["pe_sha256"][filename]:
            raise ValueError(f"{filename} differs from the {reference} reference PE")
        observations[filename] = evidence["cases"][case]
    return observations


def captured_streams(row):
    return row["exit_code"], bytes.fromhex(row["stdout_hex"]), bytes.fromhex(row["stderr_hex"])


def legacy_observations(backend, prefix, mode="captured"):
    suite = Path(__file__).resolve().parents[1] / "differential"
    with ZipFile(suite / f"fixtures/startup/termination/{backend}-raw.zip") as archive:
        evidence = json.loads(archive.read("results.json"))
    cases = {}
    for name in (suite / "reference/termination/inputs.txt").read_text().splitlines():
        if name.startswith(prefix):
            if hashlib.sha256((FIXTURES / name).read_bytes()).hexdigest() != evidence["pe_sha256"][name]:
                raise ValueError(f"{name} differs from the {backend} reference PE")
            cases[name] = evidence["observations"][name[:-4] + "-" + mode]
    return cases


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


def initializer_calls_at_image_end(counts, cross_block=False):
    """Run repeated _initterm calls over a zero-filled final PE section."""
    data = bytearray((FIXTURES / "crt-initterm.exe").read_bytes())
    layout = Layout(data)
    root = entry(data)
    offset = layout.file_offset(root)
    first_lea = data.index(bytes.fromhex("488d0d"), offset)
    site = root + first_lea - offset + 14
    assert data[first_lea + 14] == 0xe8
    thunk = site + 5 + struct.unpack_from("<i", data, first_lea + 15)[0]

    start = layout.u32(layout.opt + 56)
    end = (start // 65536 + 1) * 65536
    section = layout.section_table + len(layout.sections) * 40
    assert section + 40 <= layout.u32(layout.opt + 60)
    struct.pack_into("<H", data, layout.pe + 6, len(layout.sections) + 1)
    struct.pack_into("<8sIIIIIIHHI", data, section, b".zero", end - start, start, 0, 0, 0, 0,
                     0, 0, 0xc0000080)
    struct.pack_into("<I", data, layout.opt + 56, end)

    assert data.startswith(bytes.fromhex("534883ec30"), offset)
    code = bytearray(data[offset:offset + 5])
    for count in counts:
        assert 8 * count <= end - start
        for opcode, dest in (("488d0d", end - 8 * count), ("488d15", end), ("e8", thunk)):
            if cross_block and opcode == "e8":
                # Both sides of this diamond reach the CALL with the same two LEAs.
                code.extend(bytes.fromhex("31c0 7401 90"))
            code.extend(bytes.fromhex(opcode))
            code.extend(struct.pack("<i", dest - (root + len(code) + 4)))
    code.extend(bytes.fromhex("31c04883c4305bc3"))
    pdata = layout.file_offset(layout.directory(3)[0])
    assert layout.u32(pdata) == root and root + len(code) <= layout.u32(pdata + 4)
    data[offset:offset + len(code)] = code
    return data, end


def initializer_zero_tail():
    data = bytearray((FIXTURES / "crt-initterm-spill.exe").read_bytes())
    layout = Layout(data)
    headers = (layout.section_table + 40 * i for i in range(len(layout.sections)))
    refs = next(h for h in headers if data[h:h + 8].rstrip(b"\0") == b".refs")
    assert (layout.u32(refs + 8), layout.u32(refs + 16)) == (516, 1024)
    struct.pack_into("<I", data, refs + 16, 512)
    return data, refs


class Workspace(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.dir = Path(directory.name).resolve()
        self.output = self.dir / "guest program"

    def program(self, **streams):
        options = dict(stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.DEVNULL)
        return subprocess.run([self.output], timeout=10, **(options | streams))

    def compile(self, pe, *, success=True):
        result = run(FORGE, "lift", pe, "--executable", "--output", self.output,
                     "--diagnostics-format", "json")
        self.assertEqual(result.stdout, "")
        self.assertEqual(result.returncode, 0 if success else 1, result.stderr)
        return json.loads(result.stderr)


class Portable(Workspace):
    def test_empty_initializer_refptrs_can_name_image_end(self):
        data = bytearray((FIXTURES / "crt-initterm.exe").read_bytes())
        layout = Layout(data)
        root = entry(data)
        start = layout.file_offset(root)
        first = data.index(bytes.fromhex("488b0d"), start)
        self.assertEqual(data[first + 7:first + 10], bytes.fromhex("488b15"))
        base, = struct.unpack_from("<Q", data, layout.opt + 24)
        image_end = base + layout.u32(layout.opt + 56)
        for load in (first, first + 7):
            cell = root + load - start + 7 + struct.unpack_from("<i", data, load + 3)[0]
            struct.pack_into("<Q", data, layout.file_offset(cell), image_end)
        source = self.dir / "empty-at-end.exe"
        source.write_bytes(data)
        self.assertIn("call i32 @forge_rt_msvcrt_initterm", run(CONTRACT, source, check=True).stdout)

    def test_crt_fatal_call_lowering(self):
        for variant, service, skipped in (("fatal", "msvcrt_amsg_exit", "write_file"),
                                          ("control", "write_file", "msvcrt_amsg_exit")):
            with self.subTest(variant=variant):
                ir = run(CONTRACT, FIXTURES / f"crt-amsg-marker-{variant}.exe", check=True).stdout
                self.assertIn(f"call i32 @forge_rt_{service}(", ir)
                self.assertNotIn(f"call i32 @forge_rt_{skipped}(", ir)
                if variant == "fatal":
                    self.assertIn("declare i32 @forge_rt_msvcrt_amsg_exit(ptr, i64, i32)", ir)

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
    def test_initializer_endpoint_at_rebased_address_limit(self):
        data, end = initializer_calls_at_image_end([1])
        # Every actual image byte, including the last table slot, fits at this base.
        # The exclusive endpoint would be 2**64 and cannot be passed to MSVCRT.
        self.reject(data, "LIFT_IMAGE_MEMORY", "initializer", guest_base=(1 << 64) - end)

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
    def test_function_lift_rejects_initializer_before_callback_recovery(self):
        sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "differential"))
        from lift_diagnostics import SelectedFunction, parse_diagnostic
        sys.path.pop(0)
        data = bytearray((FIXTURES / "crt-initterm-terminal.exe").read_bytes())
        layout = Layout(data)
        root = entry(data)
        offset = layout.file_offset(root)
        records = layout.file_offset(layout.directory(3)[0])
        self.assertEqual(layout.u32(records), root)
        selected = SelectedFunction(root, layout.u32(records + 4), offset, "exe", False)
        first = root + 11 + struct.unpack_from("<i", data, offset + 7)[0]
        base, = struct.unpack_from("<Q", data, layout.opt + 24)
        struct.pack_into("<Q", data, layout.file_offset(first), base + first)
        site = root + 18
        thunk = site + 5 + struct.unpack_from("<i", data, offset + 19)[0]
        iat = thunk + 6 + struct.unpack_from("<i", data, layout.file_offset(thunk) + 2)[0]

        for opcode, call in (("CALL64pcrel32", data[offset + 18:offset + 23]),
                             ("CALL64m", b"\xff\x15" + struct.pack("<i", iat - site - 6))):
            with self.subTest(opcode=opcode):
                edited = data.copy()
                replacement = call + bytes.fromhex("31c04883c428c3")
                edited[offset + 18:offset + 18 + len(replacement)] = replacement
                source = self.dir / "function.exe"
                source.write_bytes(edited)
                ir = self.dir / "function.ll"
                result = run(FORGE, "lift", source, "--rva", hex(root), "--signature", "i64(i64,i64)",
                             "--checked-memory", "--output", ir, "--diagnostics-format", "json")
                self.assertEqual(result.returncode, 1, result.stderr)
                diagnostic = parse_diagnostic(result.stderr.encode(), source, selected, ir)
                self.assertEqual(diagnostic["code"], "LIFT_UNSUPPORTED_CONTROL_FLOW")
                self.assertIn("_initterm requires a managed process artifact", diagnostic["message"])
                context = diagnostic["context"]
                self.assertEqual((context["instruction_rva"], context["opcode"]), (hex(site), opcode))
                self.assertFalse(ir.exists())
                failure = self.reject(edited)
                self.assertEqual(failure["code"], "LIFT_INVALID_CALL_TARGET")
                evidence = failure["context"]
                self.assertEqual(evidence["initializer_target_rva"], hex(first))
                if opcode == "CALL64pcrel32":
                    self.assertEqual(evidence["branch_target"], thunk)
                else:
                    self.assertNotIn("branch_target", evidence)
                self.assertEqual(evidence["unresolved_calls"], [
                    {"caller_rva": hex(root), "instruction_rva": hex(site), "target_rva": hex(first)}])

        # PE-entry recovery also accepts a proven IAT load followed by a register CALL.
        call = bytes.fromhex("4c8b1d") + struct.pack("<i", iat - site - 7) + bytes.fromhex("41ffd3")
        replacement = call + bytes.fromhex("31c04883c428c3")
        data[offset + 18:offset + 18 + len(replacement)] = replacement
        evidence = self.reject(data)["context"]
        self.assertEqual((evidence["opcode"], evidence["initializer_target_rva"]), ("CALL64r", hex(first)))
        self.assertNotIn("branch_target", evidence)
        self.assertEqual(evidence["unresolved_calls"], [
            {"caller_rva": hex(root), "instruction_rva": hex(site + 7), "target_rva": hex(first)}])

    def test_initializer_spill_with_reachable_callback(self):
        data = bytearray((FIXTURES / "crt-initterm-spill.exe").read_bytes())
        layout = Layout(data)
        offset = data.index(bytes.fromhex("488d15"), layout.file_offset(entry(data)))
        # Extend the first empty range over the NULL and the relocated callback.
        struct.pack_into("<i", data, offset + 3, struct.unpack_from("<i", data, offset + 3)[0] + 16)
        diagnostic = self.reject(data)
        self.assertEqual(diagnostic["code"], "LIFT_IMAGE_MEMORY")
        self.assertIn("argument 1 to strlen requires proven", diagnostic["message"])

    def test_initializer_refptr_requires_complete_virtual_qword(self):
        data, refs = initializer_zero_tail()
        struct.pack_into("<I", data, refs + 8, 512)
        diagnostic = self.reject(data)
        self.assertIn("relocation target outside a single mapped section", diagnostic["message"])

    def test_initializer_budget_counts_overlapping_ranges(self):
        data, _ = initializer_calls_at_image_end([1024, 1024, 1024, 1024, 1])
        diagnostic = self.reject(data)
        self.assertEqual(diagnostic["code"], "LIFT_UNSUPPORTED_CONTROL_FLOW")
        self.assertIn("function initializer table recovery budget", diagnostic["message"])
        self.assertEqual(len(diagnostic["context"]["initializer_tables"]), 4)

    def test_initializer_exclusive_end_above_preferred_address_space(self):
        data, end = initializer_calls_at_image_end([0])
        layout = Layout(data)
        struct.pack_into("<Q", data, layout.opt + 24, (1 << 64) - end)
        diagnostic = self.reject(data)
        self.assertEqual(diagnostic["code"], "LIFT_IMAGE_MEMORY")
        self.assertIn("initializer table range", diagnostic["message"])

    def test_initializer_range_and_relocation_proof(self):
        data = bytearray((FIXTURES / "crt-initterm-terminal.exe").read_bytes())
        layout = Layout(data)
        root = entry(data)
        offset = layout.file_offset(root)
        # Two RIP-relative LEAs followed by the linker-thunk call.
        self.assertEqual((data[offset + 4:offset + 7], data[offset + 11:offset + 14], data[offset + 18]),
                         (bytes.fromhex("48 8d 0d"), bytes.fromhex("48 8d 15"), 0xe8))
        first = root + 11 + struct.unpack_from("<i", data, offset + 7)[0]
        last = root + 18 + struct.unpack_from("<i", data, offset + 14)[0]
        self.assertEqual(last - first, 16)
        thunk = root + 23 + struct.unpack_from("<i", data, offset + 19)[0]
        for begin, end, reason in ((first + 1, last, "range"), (first, last - 1, "range"),
                                   (last, first, "range"), (first, first + 8200, "range"),
                                   (first, last + 16, "outside readable PE data")):
            with self.subTest(begin=begin, end=end):
                edited = data.copy()
                struct.pack_into("<i", edited, offset + 7, begin - root - 11)
                struct.pack_into("<i", edited, offset + 14, end - root - 18)
                diagnostic = self.reject(edited)
                self.assertEqual(diagnostic["code"], "LIFT_IMAGE_MEMORY")
                self.assertIn(reason, diagnostic["message"])
                self.assertEqual(diagnostic["context"]["branch_target"], thunk)
                self.assertNotIn("initializer_target_rva", diagnostic["context"])

        slot = layout.file_offset(first)
        base, = struct.unpack_from("<Q", data, layout.opt + 24)
        for address, reason in ((base + first, "executable"), (1, "outside the image")):
            with self.subTest(address=address):
                edited = data.copy()
                struct.pack_into("<Q", edited, slot, address)
                diagnostic = self.reject(edited)
                self.assertIn(reason, diagnostic["message"])

        # This fixture has exactly one relocation block, containing both callback pointers.
        reloc = layout.file_offset(layout.directory(5)[0])
        page, size = struct.unpack_from("<II", data, reloc)
        records = struct.unpack_from(f"<{(size - 8) // 2}H", data, reloc + 8)
        index = records.index(0xa000 | (first - page))
        edited = data.copy()
        struct.pack_into("<H", edited, reloc + 8 + 2 * index, 0)
        diagnostic = self.reject(edited)
        self.assertIn("DIR64", diagnostic["message"])

        other = records.index(0xa000 | (first + 8 - page))
        edited = data.copy()
        struct.pack_into("<H", edited, reloc + 8 + 2 * other, records[index])
        diagnostic = self.reject(edited)
        self.assertEqual(diagnostic["code"], "INVALID_PE")
        self.assertIn("overlapping base relocations", diagnostic["message"])
        self.assertEqual(diagnostic["context"]["import_symbol"], "_initterm")

        # Zero bits with a live DIR64 are not a stable NULL after rebasing.
        edited = data.copy()
        struct.pack_into("<Q", edited, slot, 0)
        self.assertIn("outside the image", self.reject(edited)["message"])

        edited = data.copy()
        edited[offset + 4:offset + 11] = bytes.fromhex("b9 00 00 00 00 90 90")
        diagnostic = self.reject(edited)
        self.assertIn("endpoint", diagnostic["message"])

        # An alternate predecessor enters after the RCX producer. Its linear
        # proximity to the CALL does not establish a value on this path.
        bypass = data.copy()
        bypass[offset:offset + 4] = bytes.fromhex("31 c0 74 07")
        diagnostic = self.reject(bypass)
        self.assertEqual(diagnostic["code"], "LIFT_UNSUPPORTED_CONTROL_FLOW")
        self.assertIn("unproven incoming value", diagnostic["message"])

        # Redirect the RCX endpoint load to a writable, relocated table slot.
        # Its initial contents cannot prove a stable bound for this call site.
        edited = data.copy()
        edited[offset + 5] = 0x8b  # lea rcx, [rip+disp32] -> mov rcx, [rip+disp32]
        diagnostic = self.reject(edited)
        self.assertIn("read-only pointer", diagnostic["message"])

    def test_owned_c_specific_handler(self):
        for dll in ("KERNEL32.dll", "msvcrt.dll"):
            with self.subTest(dll=dll):
                source = image("seh-" + dll.split(".")[0].lower())
                data = source.read_bytes()
                layout = Layout(data)
                root = entry(data)
                records = layout.file_offset(layout.directory(3)[0])
                begin, end, unwind = struct.unpack_from("<III", data, records)
                self.assertEqual(begin, root)
                filter_rva = layout.u32(records + 12)
                # The SDK-free fixture has an empty prologue, then its language trailer.
                trailer = layout.file_offset(unwind) + 4
                thunk = layout.u32(trailer)
                thunk_bytes = layout.file_offset(thunk)
                self.assertEqual(data[thunk_bytes:thunk_bytes + 2], b"\xff\x25")
                slot = thunk + 6 + struct.unpack_from("<i", data, thunk_bytes + 2)[0]
                diagnostic = self.reject(data)
                self.assertEqual(diagnostic["code"], "EXECUTABLE_UNSUPPORTED_STARTUP")
                self.assertTrue(diagnostic["context"]["recovery_complete"])
                handler = diagnostic["context"]["entry_unwind_handler"]
                self.assertEqual(handler["handler_rva"], hex(thunk))
                self.assertEqual(handler["unwind_rva"], hex(unwind))
                proven = handler["c_specific_handler"]
                self.assertEqual(proven["dll"], dll)
                self.assertEqual(proven["symbol"], "__C_specific_handler")
                self.assertEqual(int(proven["iat_slot_rva"], 16), slot)
                self.assertEqual(int(proven["scope_table_rva"], 16), unwind + 8)
                self.assertEqual(proven["scope_count"], 1)
                self.assertEqual(proven["scope"], {
                    "begin_rva": hex(root), "end_rva": hex(end - 1),
                    "filter_rva": hex(filter_rva), "continuation_rva": hex(end - 1)})
                self.assertIn("guest exception dispatch", diagnostic["message"])
                plain = run(FORGE, "lift", source, "--executable", "--output", self.output)
                self.assertEqual(plain.returncode, 1)
                self.assertIn(f"{dll}!__C_specific_handler, IAT slot {hex(slot)}", plain.stderr)
                self.assertIn(f"filter {hex(filter_rva)}, continuation {hex(end - 1)}", plain.stderr)

    def test_c_specific_scope_bounds_and_provenance(self):
        data = bytearray(image("seh-kernel32").read_bytes())
        layout = Layout(data)
        records = layout.file_offset(layout.directory(3)[0])
        begin, end, unwind = struct.unpack_from("<III", data, records)
        table = layout.file_offset(unwind) + 8
        for offset, value, reason, code in (
                (0, 0xffffffff, "truncated", "INVALID_PE"),
                (0, 0, "expected one", "EXECUTABLE_UNSUPPORTED_STARTUP"),
                (4, end, "protected range", "EXECUTABLE_UNSUPPORTED_STARTUP"),
                (8, end + 1, "protected range", "EXECUTABLE_UNSUPPORTED_STARTUP"),
                (12, begin + 1, "eligible function", "EXECUTABLE_UNSUPPORTED_STARTUP"),
                (16, end, "continuation", "EXECUTABLE_UNSUPPORTED_STARTUP")):
            with self.subTest(offset=offset, value=value):
                edited = data.copy()
                struct.pack_into("<I", edited, table + offset, value)
                diagnostic = self.reject(edited)
                self.assertEqual(diagnostic["code"], code)
                handler = diagnostic["context"]["entry_unwind_handler"]["c_specific_handler"]
                self.assertNotIn("scope", handler)
                self.assertIn(reason, handler["limitation"])

        # An arbitrary handler can put any language-specific data in its trailer.
        other = data.copy()
        other[other.index(b"KERNEL32.dll")] = ord("X")
        handler = self.reject(other)["context"]["entry_unwind_handler"]
        self.assertNotIn("c_specific_handler", handler)

        # An advertised dynamic relocation table has an unknown write footprint.
        dynamic = data.copy()
        section = layout.section_header(unwind)
        raw, size = layout.u32(section + 20), layout.u32(section + 8)
        config = (size + 7) & ~7
        self.assertLessEqual(config + 232, layout.u32(section + 16))
        struct.pack_into("<I", dynamic, section + 8, config + 232)
        struct.pack_into("<II", dynamic, layout.directories + 10 * 8,
                         layout.u32(section + 12) + config, 232)
        struct.pack_into("<I", dynamic, raw + config, 232)
        struct.pack_into("<I", dynamic, raw + config + 224, 1)
        handler = self.reject(dynamic)["context"]["entry_unwind_handler"]
        self.assertNotIn("c_specific_handler", handler)

        # The scope row, filter unwind header and filter unwind codes all contribute to the proof.
        reloc = layout.file_offset(layout.directory(5)[0])
        filter_unwind = layout.u32(records + 12 + 8)
        self.assertEqual(data[layout.file_offset(filter_unwind) + 2], 1)
        for target, kind, reason in ((unwind + 12, 10, "mutable or split"),
                                     (filter_unwind, 10, "mutable C-specific filter"),
                                     (filter_unwind + 4, 3, "mutable C-specific filter")):
            with self.subTest(relocated=hex(target)):
                changed = data.copy()
                struct.pack_into("<I", changed, reloc, target & ~0xfff)
                struct.pack_into("<H", changed, reloc + 8, (kind << 12) | (target & 0xfff))
                diagnostic = self.reject(changed)
                self.assertEqual(diagnostic["code"], "EXECUTABLE_UNSUPPORTED_STARTUP")
                handler = diagnostic["context"]["entry_unwind_handler"]["c_specific_handler"]
                self.assertEqual(handler["scope_count"], 1)
                self.assertNotIn("scope", handler)
                self.assertIn(reason, handler["limitation"])

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
        info = layout.file_offset(int(unwind, 16))
        self.assertEqual(data[info:info + 8], bytes.fromhex("01000000 00000000"))
        data[info] |= 2 << 3  # UNW_FLAG_UHANDLER
        struct.pack_into("<I", data, info + 4, int(callee, 16))
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

    def test_bounded_table_rejections(self):
        original, symbols = bounded_fixture()
        layout = Layout(original)
        base, = struct.unpack_from("<Q", original, layout.opt + 24)
        table = symbols["count_table"]
        site = symbols["count_site"]
        # Identify the exact relocation belonging to the first constructor.
        directory, size = layout.directory(5)
        block = layout.file_offset(directory)
        end = block + size
        fields = {}
        while block < end:
            page, length = struct.unpack_from("<II", original, block)
            for n in range(block + 8, block + length, 2):
                fixup, = struct.unpack_from("<H", original, n)
                if fixup >> 12 == 10:
                    fields[page + (fixup & 4095)] = n
            block += length

        for mutation in ("missing_reloc", "wrong_reloc", "excess_count", "truncated",
                         "no_terminator", "unreadable", "wrong_index", "outside", "middle", "guard",
                         "scan_guard", "entry_bypass", "provenance", "metadata", "overlap"):
            with self.subTest(mutation=mutation):
                data = bytearray(original)
                expected_site = site
                offset = layout.file_offset
                header = offset(table)
                caller = offset(symbols["run_count"])
                at = offset(site)
                if mutation in ("missing_reloc", "wrong_reloc"):
                    rel = fields[table + 8]
                    v, = struct.unpack_from("<H", data, rel)
                    struct.pack_into("<H", data, rel, 0 if mutation == "missing_reloc" else (v & 4095) | 0x3000)
                elif mutation == "excess_count":
                    struct.pack_into("<Q", data, header, 1025)
                elif mutation in ("truncated", "no_terminator"):
                    last = symbols["one_table"]
                    struct.pack_into("<I", data, layout.opt + 16, symbols["run_one"])
                    struct.pack_into("<Q", data, offset(last), 2 if mutation == "truncated" else 2**64 - 1)
                    sec = layout.section_header(last)
                    struct.pack_into("<I", data, sec + 8, last - layout.u32(sec + 12) + 16)
                    expected_site = symbols["run_one"] + site - symbols["run_count"]
                elif mutation == "unreadable":
                    sec = layout.section_header(table)
                    struct.pack_into("<I", data, sec + 36, layout.u32(sec + 36) & ~0x40000000)
                elif mutation == "wrong_index":
                    self.assertEqual(data[at + 2:at + 6], bytes.fromhex("4883eb08"))
                    data[at + 5] = 16
                elif mutation in ("outside", "middle"):
                    struct.pack_into("<Q", data, header + 8,
                                     base + (table if mutation == "outside" else symbols["writer"] + 1))
                elif mutation == "guard":
                    # A jump around the zero check must not become a valid backedge.
                    branch = data.index(bytes.fromhex("85c974"), caller, at) + 2
                    data[branch + 1] = at - (branch + 2)
                elif mutation == "entry_bypass":
                    # Add a predecessor before the base definition while preserving
                    # every instruction of the valid reverse loop and scan.
                    self.assertEqual(data[caller + 2:caller + 6], bytes.fromhex("4883ec28"))
                    data[caller + 2:caller + 6] = bytes([0x74, at - (caller + 4), 0x90, 0x90])
                elif mutation == "scan_guard":
                    branch = data.index(bytes.fromhex("83f8ff74"), caller, at) + 3
                    data[branch + 1] += 2
                elif mutation == "provenance":
                    self.assertEqual(data[at:at + 2], bytes.fromhex("ff13"))
                    data[at + 1] = 0x16
                elif mutation == "metadata":
                    # The loader writes this four-byte TLS index over a function pointer.
                    tls = layout.directory(9)[0]
                    if not tls:
                        # Reserve directory bytes in the unused, zero-filled section padding.
                        sec = layout.section_header(table)
                        old_size = layout.u32(sec + 8)
                        tls = table - table % 4096 + ((old_size + 7) & ~7)
                        struct.pack_into("<I", data, sec + 8, tls - (table & ~4095) + 40)
                        struct.pack_into("<II", data, layout.directories + 9 * 8, tls, 40)
                    tls_offset = header + tls - table
                    struct.pack_into("<Q", data, tls_offset + 16, base + table + 8)
                else:
                    rows, size = layout.directory(3)
                    rec = offset(rows)
                    while layout.u32(rec) != symbols["two"]:
                        rec += 12
                        self.assertLess(rec, offset(rows) + size)
                    struct.pack_into("<I", data, rec + 4, symbols["writer"] + 1)
                report = self.reject(data)
                ctx = report["context"]
                self.assertEqual(ctx.get("instruction_rva"), hex(expected_site), report["message"])
                self.assertEqual(ctx.get("opcode"), "CALL64m")
                self.assertNotIn("iat_slot_rva", ctx)
                if mutation == "entry_bypass":
                    self.assertIn("bypasses bounded table proof", report["message"])
                    self.assertIn(dict(caller_rva=hex(symbols["run_count"]), instruction_rva=hex(site)),
                                  ctx["unresolved_calls"])
                if mutation == "outside":
                    self.assertEqual(ctx["table_target_rva"], hex(table))
                    self.assertIn(dict(caller_rva=hex(symbols["run_count"]), instruction_rva=hex(site),
                                       target_rva=hex(table)), ctx["unresolved_calls"])

    def test_forward_table_rejections(self):
        original, symbols = bounded_fixture(image("forward-call"))
        layout = Layout(original)
        site, load = symbols["many_site"], symbols["many_load"]
        bounds, first, last = (symbols[key] for key in ("many_bounds", "slots", "slots_end"))
        offset = layout.file_offset
        base, = struct.unpack_from("<Q", original, layout.opt + 24)
        directory, size = layout.directory(5)
        fields = {}
        block = offset(directory)
        while block < offset(directory) + size:
            page, length = struct.unpack_from("<II", original, block)
            for at in range(block + 8, block + length, 2):
                fixup, = struct.unpack_from("<H", original, at)
                if fixup >> 12 == 10:
                    fields[page + (fixup & 4095)] = at
            block += length

        for case in ("alignment", "reversed", "underflow", "budget", "unmapped", "permission",
                     "missing", "conflict", "loader", "loader_code", "data_target", "interior", "after_load",
                     "after_guard", "late_backedge", "empty_backedge", "stride", "partial_rax", "unguarded_null"):
            with self.subTest(case=case):
                data = bytearray(original)
                # Select this recorded function directly so malformed input is attributed
                # to its own call even when another table shares the containing section.
                struct.pack_into("<I", data, layout.opt + 16, symbols["outer"])
                section = layout.section_header(first)
                if case in ("alignment", "reversed", "underflow", "budget", "unmapped"):
                    endpoint = {"alignment": last-1, "reversed": first-8, "underflow": -8,
                                "budget": first+8*1025, "unmapped": first+0x4000}[case]
                    struct.pack_into("<i", data, offset(bounds)+10, endpoint-(bounds+14))
                elif case == "permission":
                    struct.pack_into("<I", data, section + 36, layout.u32(section+36) & ~0x40000000)
                elif case == "missing":
                    struct.pack_into("<H", data, fields[first], 0)
                elif case == "conflict":
                    data[fields[first+16]:fields[first+16]+2] = data[fields[first]:fields[first]+2]
                elif case in ("loader", "loader_code"):
                    tls = first+0x80
                    struct.pack_into("<I", data, section+8, tls+40-layout.u32(section+12))
                    struct.pack_into("<II", data, layout.directories+9*8, tls, 40)
                    index = bounds if case == "loader_code" else first
                    struct.pack_into("<Q", data, offset(tls)+16, base+index)
                elif case in ("data_target", "interior"):
                    target = first if case == "data_target" else symbols["writer"]+1
                    struct.pack_into("<Q", data, offset(first), base+target)
                elif case in ("after_load", "after_guard", "late_backedge", "empty_backedge"):
                    if case == "empty_backedge":
                        struct.pack_into("<i", data, offset(bounds)+10, first-(bounds+14))
                    dest = {"after_load": load+3, "after_guard": site, "late_backedge": load, "empty_backedge": load}[case]
                    edge = symbols["late_edge"]
                    data[offset(edge):offset(edge)+2] = struct.pack("<Bb", 0x75, dest-edge-2)
                elif case == "stride":
                    data[offset(site)+5] = 16
                elif case == "partial_rax":
                    data[offset(site)-7:offset(site)] = bytes.fromhex("b4 00 90 90 90 90 90")
                else:
                    data[offset(load)+6] = 0x75  # JNE skips non-NULL and reaches CALL on NULL.
                report = self.reject(data)
                ctx = report["context"]
                self.assertEqual((ctx.get("instruction_rva"), ctx.get("opcode")),
                                 (hex(site), "CALL64r"), report)
                if case in ("after_load", "after_guard", "late_backedge", "empty_backedge"):
                    self.assertIn(f"bypasses bounded table proof from {edge:#x} to {dest:#x}", report["message"])
                    self.assertIn(dict(caller_rva=hex(symbols["outer"]), instruction_rva=hex(site)),
                                  ctx["unresolved_calls"])
                if case == "loader":
                    self.assertEqual(report["code"], "LIFT_IMAGE_MEMORY")
                    self.assertIn("loader write overlaps bounded table", report["message"])
                    self.assertEqual((ctx["table_first_rva"], ctx["table_last_rva"], ctx["pointer_load_rva"]),
                                     (hex(first), hex(last), hex(load)))
                if case == "loader_code":
                    self.assertIn(f"proof depends on loader-written code at {bounds:#x}", report["message"])
                    self.assertNotIn("branch_target", ctx)
                    self.assertIn(dict(caller_rva=hex(symbols["outer"]), instruction_rva=hex(site)),
                                  ctx["unresolved_calls"])
                if case == "budget":
                    self.assertIn("count exceeds budget", report["message"])
                if case in ("after_load", "after_guard", "late_backedge", "empty_backedge", "missing",
                            "data_target", "interior", "conflict", "budget", "alignment", "reversed"):
                    self.assertEqual(ctx.get("pointer_load_rva"), hex(load), report)

    def test_nested_forward_table_failure(self):
        original, symbols = bounded_fixture(image("forward-call"))
        layout = Layout(original)
        base, = struct.unpack_from("<Q", original, layout.opt + 24)
        outer, outer_site, inner_site = (symbols[k] for k in ("outer", "many_site", "null_site"))
        inner, bounds, load = null_walk(original, layout, inner_site)
        # Reuse the single-entry table's relocated slot for the nested walk.
        first = symbols["empty"] - 8
        bad_target = symbols["slots"]
        for case, last in (("invalid_range", first + 9), ("invalid_target", first + 8)):
            with self.subTest(case=case):
                data = bytearray(original)
                struct.pack_into("<I", data, layout.opt + 16, outer)
                struct.pack_into("<Q", data, layout.file_offset(symbols["slots"]), base + inner)
                struct.pack_into("<Q", data, layout.file_offset(first), base + bad_target)
                set_forward_bounds(data, layout, bounds, first, last)
                ctx = self.reject(data)["context"]
                self.assertEqual((ctx["caller_rva"], ctx["call_site_rva"]), (hex(outer), hex(outer_site)))
                self.assertIn(dict(caller_rva=hex(outer), instruction_rva=hex(outer_site), target_rva=hex(inner)),
                              ctx["calls"])
                self.assertEqual((ctx["function_rva"], ctx["instruction_rva"], ctx["table_first_rva"],
                                  ctx["table_last_rva"], ctx["pointer_load_rva"]),
                                 tuple(map(hex, (inner, inner_site, first, last, load))))
                edge = dict(caller_rva=hex(inner), instruction_rva=hex(inner_site))
                if case == "invalid_range":
                    self.assertNotIn("table_target_rva", ctx)
                else:
                    self.assertEqual(ctx["table_target_rva"], hex(bad_target))
                    edge["target_rva"] = hex(bad_target)
                    result = run(FORGE, "lift", self.dir / "bad.exe", "--executable", "--output", self.output)
                    self.assertEqual(result.returncode, 1)
                    self.assertIn(f"{inner_site:#x}: CALL64r", result.stderr)
                    self.assertIn(f"load at {load:#x}, target {bad_target:#x})", result.stderr)
                    self.assertIn(f"reached from call at {outer_site:#x} in {outer:#x}", result.stderr)
                self.assertIn(edge, ctx["unresolved_calls"])

    def test_forward_table_image_planning_failure(self):
        original, symbols = bounded_fixture(image("forward-call"))
        data = bytearray(original)
        layout = Layout(data)
        site = symbols["null_site"]
        inner, bounds, load = null_walk(data, layout, site)
        first = layout.u32(layout.opt + 56)
        layout.add_unused_section(257 << 20, 0xc0000080)
        set_forward_bounds(data, layout, bounds, first, first + 8)
        base, = struct.unpack_from("<Q", data, layout.opt + 24)
        struct.pack_into("<Q", data, layout.file_offset(symbols["slots"]), base + inner)

        for root in (entry(original), inner):
            with self.subTest(root=hex(root)):
                struct.pack_into("<I", data, layout.opt + 16, root)
                report = self.reject(data)
                self.assertEqual(report["code"], "LIFT_IMAGE_MEMORY")
                self.assertIn("writable virtual limit", report["message"])
                ctx = report["context"]
                self.assertTrue(ctx["recovery_complete"])
                self.assertEqual((ctx["instruction_rva"], ctx["block_rva"], ctx["table_first_rva"],
                                  ctx["table_last_rva"], ctx["pointer_load_rva"]),
                                 tuple(map(hex, (site, site, first, first + 8, load))))
                self.assertNotIn("table_target_rva", ctx)
                if root == inner:
                    self.assertNotIn("call_site_rva", ctx)
                else:
                    self.assertEqual((ctx["function_rva"], ctx["caller_rva"], ctx["call_site_rva"]),
                                     tuple(map(hex, (inner, symbols["outer"], symbols["many_site"]))))

    def test_bounded_nested_import_failure(self):
        original, symbols = bounded_fixture(image("bounded-cleanup"))
        data = bytearray(original)
        name = data.index(b"_onexit\0")
        data[name:name + 7] = b"_absent"
        writer = symbols["writer"]
        offset = Layout(data).file_offset(writer)
        inner = writer + data.index(b"\xff\x15", offset) - offset
        ctx = self.reject(data)["context"]
        outer = dict(caller_rva=hex(symbols["run_count"]), instruction_rva=hex(symbols["count_site"]),
                     target_rva=hex(writer))
        self.assertEqual((ctx["function_rva"], ctx["instruction_rva"], ctx["import_symbol"]),
                         (hex(writer), hex(inner), "_absent"))
        self.assertEqual((ctx["caller_rva"], ctx["call_site_rva"], ctx["table_header_rva"], ctx["table_target_rva"]),
                         (outer["caller_rva"], outer["instruction_rva"], hex(symbols["count_table"]), hex(writer)))
        self.assertIn(outer, ctx["calls"])
        self.assertNotIn(outer, ctx["unresolved_calls"])
        self.assertIn(dict(caller_rva=hex(writer), instruction_rva=hex(inner)), ctx["unresolved_calls"])

    def test_bounded_table_image_selection(self):
        original, symbols = bounded_fixture()
        data = bytearray(original)
        layout = Layout(data)
        layout.add_unused_section(33 << 20, 0x40000080)
        pe = self.dir / "large.exe"
        pe.write_bytes(data)

        def lift(name):
            return run(FORGE, "lift", pe, "--rva", hex(symbols[name]), "--signature", "i64(i64,i64)",
                       "--output", self.output, "--diagnostics-format", "json")

        for name in ("run_empty", "run_one", "run_count", "run_switch"):
            with self.subTest(name=name):
                result = lift(name)
                self.assertEqual(result.returncode, 0, result.stderr)

        # An ordinary read through incoming RCX still requires the generic image plan.
        offset = layout.file_offset(symbols["two"])
        data[offset:offset + 4] = bytes.fromhex("488b01 c3")
        pe.write_bytes(data)
        result = lift("two")
        self.assertEqual(result.returncode, 1)
        self.assertEqual(json.loads(result.stderr)["code"], "LIFT_IMAGE_MEMORY")

    def test_bounded_table_budgets(self):
        original, symbols = bounded_fixture(FIXTURES / "bounded-budget.exe")
        layout = Layout(original)
        table = layout.file_offset(symbols["budget_table"])
        tail = layout.file_offset(symbols["budget_tail"])
        pe = self.dir / "budget.exe"
        args = (FORGE, "lift", pe, "--rva", hex(entry(original)), "--signature", "i64(i64,i64)",
                "--output", self.output, "--diagnostics-format", "json")
        for header in (1024, 2**64 - 1):
            data = bytearray(original)
            struct.pack_into("<Q", data, table, header)
            # Four sites each traverse 1,024 duplicate pointers. The final empty
            # sentinel table can still inspect its NULL with zero allowance left.
            pe.write_bytes(data)
            result = run(*args)
            self.assertEqual(result.returncode, 0, result.stderr)
            for tail_header in (1, 2**64 - 1):
                with self.subTest(header=header, tail=tail_header):
                    struct.pack_into("<QQ", data, tail, tail_header, 123)  # missing DIR64
                    pe.write_bytes(data)
                    result = run(*args)
                    self.assertEqual(result.returncode, 1)
                    diagnostic = json.loads(result.stderr)
                    self.assertIn("bounded table entry budget exceeded", diagnostic["message"])
                    self.assertEqual(diagnostic["context"]["instruction_rva"], hex(symbols["budget_tail_site"]))

        # A malformed 1,025th nonzero entry exceeds the per-list limit first.
        data = bytearray(original)
        struct.pack_into("<Q", data, table + 8 * 1025, 123)
        pe.write_bytes(data)
        result = run(*args)
        self.assertEqual(result.returncode, 1)
        self.assertIn("missing bounded table terminator", json.loads(result.stderr)["message"])

    def test_tail_cycles_report_only_admitted_edges(self):
        data = bytearray((FIXTURES / "cfg.exe").read_bytes())
        layout = Layout(data)
        records = layout.file_offset(layout.directory(3)[0])
        root, left, right = (layout.u32(records + n * 12) for n in range(3))
        self.assertEqual(root, entry(data))

        def transfer(source, target, opcode):
            start = layout.file_offset(source)
            data[start:start + 5] = bytes([opcode]) + struct.pack("<i", target - source - 5)

        transfer(root, left, 0xe9)
        transfer(left, right, 0xe9)
        for opcode in (0xe9, 0xe8):
            with self.subTest(back_edge=opcode):
                transfer(right, left, opcode)
                data[layout.file_offset(right) + 5] = 0xc3
                diagnostic = self.reject(data)
                context = diagnostic["context"]
                self.assertEqual(diagnostic["code"], "LIFT_UNSUPPORTED_CONTROL_FLOW")
                self.assertIn("recursive cross-function tail transfer", diagnostic["message"])
                self.assertEqual((context["instruction_rva"], context["branch_target"]), (hex(left), right))
                self.assertEqual(context["tail_transfers"], [
                    dict(caller_rva=hex(root), instruction_rva=hex(root), target_rva=hex(left))])

        # A later decode failure wins the diagnostic; the already discovered cycle
        # still cannot supply admitted transfers in this partial snapshot.
        broken = layout.u32(records + 36)
        start = layout.file_offset(root)
        data[start:start + 4] = bytes.fromhex("31c0 7405")
        transfer(root + 4, left, 0xe9)
        transfer(root + 9, broken, 0xe9)
        offset = layout.file_offset(broken)
        data[offset:offset + 3] = bytes.fromhex("ff13 c3")
        ctx = self.reject(data)["context"]
        self.assertEqual((ctx["instruction_rva"], ctx["bytes"]), (hex(broken), "ff13"))
        self.assertEqual(ctx["tail_transfers"], [
            dict(caller_rva=hex(root), instruction_rva=hex(site), target_rva=hex(target))
            for site, target in ((root + 4, left), (root + 9, broken))])

    def test_tail_target_requires_stable_entry_evidence(self):
        data = bytearray(image("tail-jump").read_bytes())
        layout = Layout(data)
        root = entry(data)
        table, size = layout.directory(3)
        row = table + 2 * 12
        target, _, unwind = struct.unpack_from("<III", data, layout.file_offset(row))
        self.assertEqual(data[layout.file_offset(unwind) + 2], 1)  # One unwind code.

        # Reach the target first by CALL, then JMP to the same recorded entry.
        start = layout.file_offset(root)
        jump = root + 13
        encoded = b"\xe9" + struct.pack("<i", target - jump - 5)
        data[start:start + 18] = (bytes.fromhex("4883ec28 e8") + struct.pack("<i", target - root - 9)
                                  + bytes.fromhex("4883c428") + encoded)
        offset = layout.file_offset(target)
        data[offset:offset + 6] = bytes.fromhex("b82a000000 c3")

        # Both copies of a coalesced table row supply its provenance.
        section = layout.section_header(table)
        self.assertEqual(layout.u32(section + 8), size)
        self.assertLessEqual(size + 12, layout.u32(section + 16))
        struct.pack_into("<I", data, section + 8, size + 12)
        struct.pack_into("<I", data, layout.directories + 3 * 8 + 4, size + 12)
        duplicate = layout.file_offset(table) + size
        data[duplicate:duplicate + 12] = data[layout.file_offset(row):layout.file_offset(row) + 12]
        source = self.dir / "stable.exe"
        source.write_bytes(data)
        # Function lifting is portable, including on hosts without a native linker.
        ir = self.dir / "stable.ll"
        args = (FORGE, "lift", source, "--rva", hex(root), "--signature", "i64(i64,i64)", "--output", ir)
        self.assertEqual(run(*args).returncode, 0)

        for evidence in (row, table + size + 8, unwind + 4):
            for cause in ("writable", "relocated", "loader-written"):
                with self.subTest(evidence=hex(evidence), cause=cause):
                    changed = data.copy()
                    if cause == "writable":
                        header = Layout(changed).section_header(evidence)
                        struct.pack_into("<I", changed, header + 36, layout.u32(header + 36) | 0x80000000)
                    elif cause == "relocated":
                        reloc = layout.file_offset(layout.directory(5)[0])
                        struct.pack_into("<I", changed, reloc, evidence & ~0xfff)
                        changed[reloc + 8:reloc + layout.u32(reloc + 4)] = bytes(layout.u32(reloc + 4) - 8)
                        struct.pack_into("<H", changed, reloc + 8, 0x3000 | (evidence & 0xfff))
                    else:
                        struct.pack_into("<II", changed, layout.directories + 12 * 8, evidence, 4)
                    diagnostic = self.reject(changed)
                    self.assertEqual(diagnostic["code"], "LIFT_UNSUPPORTED_CONTROL_FLOW")
                    self.assertIn("stable target function table and unwind metadata", diagnostic["message"])
                    ctx = diagnostic["context"]
                    self.assertEqual((ctx["instruction_rva"], ctx["branch_target"], ctx["bytes"]),
                                     (hex(jump), target, encoded.hex()))
                    self.assertEqual(ctx["tail_transfers"], [])

    def test_invalid_roots(self):
        for root in (0, entry(image("return").read_bytes()) + 1):
            with self.subTest(root=root):
                data = bytearray(image("return").read_bytes())
                struct.pack_into("<I", data, Layout(data).opt + 16, root)
                diagnostic = self.reject(data)
                self.assertEqual(diagnostic["context"]["entry_rva"], hex(root))
                self.assertFalse(diagnostic["context"]["entry_recovered"])

    def test_initializer_leaf_failure_retains_import_and_target(self):
        data = bytearray((FIXTURES / "crt-initterm.exe").read_bytes())
        layout = Layout(data)
        root = entry(data)
        offset = layout.file_offset(root)
        # The third pair of LEAs selects the singleton metadata-free initializer.
        pair = bytes.fromhex("48 8d 0d")
        first_load = data.index(pair, offset)
        second_load = data.index(pair, first_load + 7)
        third_load = data.index(pair, second_load + 7)
        caller_pc = root + third_load - offset
        slot = caller_pc + 7 + struct.unpack_from("<i", data, third_load + 3)[0]
        base, = struct.unpack_from("<Q", data, layout.opt + 24)
        leaf_va, = struct.unpack_from("<Q", data, layout.file_offset(slot))
        target = leaf_va - base
        site = caller_pc + 14
        self.assertEqual(data[third_load + 14], 0xe8)
        thunk = site + 5 + struct.unpack_from("<i", data, third_load + 15)[0]
        thunk_offset = layout.file_offset(thunk)
        self.assertEqual(data[thunk_offset:thunk_offset + 2], bytes.fromhex("ff25"))
        iat = thunk + 6 + struct.unpack_from("<i", data, thunk_offset + 2)[0]

        patch = layout.file_offset(target)
        data[patch:patch + 2] = bytes.fromhex("0fa2")  # CPUID has no supported leaf effects.
        diagnostic = self.reject(data)
        self.assertEqual(diagnostic["code"], "LIFT_UNSUPPORTED_INSTRUCTION")
        context = diagnostic["context"]
        self.assertEqual((context["function_rva"], context["caller_rva"], context["call_site_rva"]),
                         (hex(target), hex(root), hex(site)))
        self.assertEqual((context["import_symbol"], context["iat_slot_rva"]), ("_initterm", hex(iat)))
        self.assertEqual(context["initializer_target_rva"], hex(target))
        self.assertNotIn("branch_target", context)
        self.assertIn({"caller_rva": hex(root), "instruction_rva": hex(site), "target_rva": hex(target)},
                      context["unresolved_calls"])
        tables = [t for t in context["initializer_tables"] if t["instruction_rva"] == hex(site)]
        self.assertEqual(tables[0]["initial_target_rvas"], [hex(target)])

        # A leaf that modifies RSP fails admission at the originating CALL.
        data[patch:patch + 2] = bytes.fromhex("535b")
        failure = self.reject(data)
        context = failure["context"]
        self.assertEqual((failure["code"], context["instruction_rva"], context["branch_target"]),
                         ("LIFT_UNSUPPORTED_CONTROL_FLOW", hex(site), thunk))
        self.assertEqual(context["initializer_target_rva"], hex(target))
        self.assertIn({"caller_rva": hex(root), "instruction_rva": hex(site), "target_rva": hex(target)},
                      context["unresolved_calls"])

    def test_initializer_nested_import_failure(self):
        data = bytearray((FIXTURES / "crt-initterm-terminal.exe").read_bytes())
        name = data.index(b"ExitProcess\0")
        data[name:name + 11] = b"MissingCall"
        ctx = self.reject(data)["context"]
        layout = Layout(data)
        root = entry(data)
        site = root + 18
        slot = root + 11 + struct.unpack_from("<i", data, layout.file_offset(root) + 7)[0]
        base, = struct.unpack_from("<Q", data, layout.opt + 24)
        target = struct.unpack_from("<Q", data, layout.file_offset(slot))[0] - base
        # The callback reserves home space, sets ECX and calls through the ExitProcess IAT.
        inner = target + 9
        offset = layout.file_offset(inner)
        self.assertEqual(data[offset:offset + 2], b"\xff\x15")
        iat = inner + 6 + struct.unpack_from("<i", data, offset + 2)[0]
        self.assertEqual((ctx["function_rva"], ctx["instruction_rva"], ctx["import_symbol"],
                          ctx["iat_slot_rva"]), (hex(target), hex(inner), "MissingCall", hex(iat)))
        self.assertEqual((ctx["initializer_target_rva"], ctx["caller_rva"], ctx["call_site_rva"]),
                         (hex(target), hex(root), hex(site)))
        self.assertEqual(ctx["unresolved_calls"][0],
                         {"caller_rva": hex(target), "instruction_rva": hex(inner)})
        self.assertNotIn({"caller_rva": hex(root), "instruction_rva": hex(site),
                          "target_rva": hex(target)}, ctx["unresolved_calls"])

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

    def test_invalid_callee_keeps_caller_import_evidence(self):
        original = bytearray(console_image("nested_exit").read_bytes())
        layout = Layout(original)
        root = entry(original)
        start = layout.file_offset(root)
        self.assertTrue(original.startswith(bytes.fromhex("4883ec38 b901000000 e8"), start))
        helper = root + 14 + struct.unpack_from("<i", original, start + 10)[0]
        pos = layout.file_offset(helper)
        # Make ExitProcess the helper's only reachable call and loop immediately after it.
        self.assertTrue(original.startswith(bytes.fromhex("4883ec38 85c9 740b b92a00feca ff15"), pos))
        original[pos + 7] = 0
        original[pos + 19:pos + 21] = bytes.fromhex("ebfe")
        site = helper + 13
        for kind, code in (("guest", "LIFT_INVALID_CALL_TARGET"), ("import", "LIFT_UNSUPPORTED_CONTROL_FLOW")):
            with self.subTest(kind=kind):
                data = original.copy()
                if kind == "guest":
                    data[pos + 13:pos + 19] = b"\xe8" + struct.pack("<i", 0x400000 - site - 5) + b"\x90"
                else:
                    data = data.replace(b"ExitProcess\0", b"BadFunction\0")
                diagnostic = self.reject(data)
                self.assertEqual(diagnostic["code"], code)
                ctx = diagnostic["context"]
                self.assertEqual(ctx["instruction_rva"], hex(site))
                self.assertFalse(ctx["recovery_complete"])
                imports = {(item["dll"].lower(), item["name"]) for item in ctx["imports"]}
                self.assertTrue({("kernel32.dll", "GetStdHandle"), ("kernel32.dll", "WriteFile")} <= imports,
                                imports)

    def test_unsupported_image_startup(self):
        data = bytearray(image("return").read_bytes())
        layout = Layout(data)
        for label in ("TLS", "CLR", "SEH", "align"):
            with self.subTest(requirement=label):
                changed = data.copy()
                if label == "TLS":
                    # A real PE TLS directory with callbacks and a data template.
                    changed = (FIXTURES / "metadata.exe").read_bytes()
                elif label == "CLR":
                    struct.pack_into("<II", changed, layout.directories + 14 * 8, entry(data), 72)
                elif label == "SEH":
                    changed = image("seh-kernel32").read_bytes()
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

    def test_data_import_slot_is_loader_owned(self):
        data = bytearray((FIXTURES / "crt-argument-heap.exe").read_bytes())
        layout = Layout(data)
        root = entry(data)
        start = layout.file_offset(root)
        # The first RIP-relative load in the probe reads the _fmode slot.
        self.assertEqual(data[start + 4:start + 7], bytes.fromhex("48 8b 15"))
        slot = root + 11 + struct.unpack_from("<i", data, start + 7)[0]
        # Retarget a DIR64 fixup to the loader-owned slot. A one-byte overlap
        # with its neighbor also invalidates that binding.
        block = layout.file_offset(layout.directory(5)[0])
        for start_rva, symbol in ((slot, "_fmode"), (slot - 1, "_commode")):
            with self.subTest(start_rva=hex(start_rva)):
                relocated = data.copy()
                offset = start_rva - layout.u32(block)
                self.assertIn(offset, range(0x1000))
                struct.pack_into("<H", relocated, block + 8, 0xa000 | offset)
                diagnostic = self.reject(relocated)
                self.assertEqual(diagnostic["code"], "EXECUTABLE_UNSUPPORTED_STARTUP")
                self.assertIn(f"invalid data import slot for msvcrt.dll!{symbol}", diagnostic["message"])

        # Store an immediate into that slot, then return a defined value.
        code = b"\xc7\x05" + struct.pack("<iI", slot - root - 10, 1) + bytes.fromhex("31 c0 c3")
        data[start:start + len(code)] = code
        diagnostic = self.reject(data)
        self.assertEqual(diagnostic["code"], "LIFT_IMAGE_MEMORY", diagnostic)
        symbols = [s for dll in diagnostic["context"]["load_imports"] for s in dll["symbols"]]
        self.assertIn({"iat_slot_rva": hex(slot), "name": "_fmode", "catalogued_data_export": True,
                       "catalogued_service": False}, symbols)

    def test_function_import_slot_access(self):
        original = image("import-register").read_bytes()
        root = entry(original)
        start = Layout(original).file_offset(root)
        # The normal entry first loads the complete Sleep IAT slot into R10.
        self.assertTrue(original.startswith(bytes.fromhex("48 83 ec 28 4c 8b 15"), start))
        slot = root + 11 + struct.unpack_from("<i", original, start + 7)[0]
        for label, opcode, offset in (("partial read", "8b05", 0), ("straddling read", "488b05", 1),
                                      ("whole-slot write", "488905", 0)):
            with self.subTest(access=label):
                prefix = bytes.fromhex("31c0" + opcode)
                disp = struct.pack("<i", slot + offset - (root + len(prefix) + 4))
                code = prefix + disp + bytes.fromhex("b82a000000 c3")
                data = bytearray(original)
                data[start:start + len(code)] = code
                diagnostic = self.reject(data)
                self.assertEqual(diagnostic["code"], "LIFT_IMAGE_MEMORY", diagnostic)
                self.assertEqual(diagnostic["context"]["instruction_rva"], hex(root + 2))

    def test_transformed_service_pointer_loses_provenance(self):
        data = bytearray((FIXTURES / "crt-argument-heap.exe").read_bytes())
        layout = Layout(data)
        start = layout.file_offset(entry(data))
        # This strlen call accepts a guest pointer returned by GetCommandLineA.
        # Replacing MOV RCX,RAX with LEA ECX,[RAX+1] changes both its value and width.
        copy = bytes.fromhex("48 89 c1 ff 15")
        off = data.index(copy, start)
        data[off:off + 3] = bytes.fromhex("8d 48 01")
        diagnostic = self.reject(data)
        self.assertEqual(diagnostic["code"], "LIFT_IMAGE_MEMORY", diagnostic)
        self.assertIn("argument 1 to strlen", diagnostic["message"])

    def test_crt_argv_string_service_boundary(self):
        data = (FIXTURES / "crt-argv-strlen.exe").read_bytes()
        diagnostic = self.reject(data)
        self.assertEqual(diagnostic["code"], "LIFT_IMAGE_MEMORY", diagnostic)
        self.assertIn("argument 1 to strlen requires proven", diagnostic["message"])
        root = entry(data)
        start = Layout(data).file_offset(root)
        # The call follows MOV RCX,[RDX+8], which loads argv[1].
        load = data.index(bytes.fromhex("48 8b 4a 08 ff 15"), start)
        self.assertEqual(diagnostic["context"]["instruction_rva"], hex(root + load - start + 4))

    def test_managed_services_require_process(self):
        for pe, name in ((image("top-level-filter"), "SetUnhandledExceptionFilter"),
                         (FIXTURES / "crt-amsg-exit-31.exe", "_amsg_exit"),
                         (FIXTURES / "crt-app-type-fatal-console.exe", "__set_app_type")):
            with self.subTest(name=name):
                result = run(FORGE, "lift", pe, "--rva", hex(entry(pe.read_bytes())), "--checked-memory",
                             "--signature", "i64(i64,i64)", "--diagnostics-format", "json", "--output", self.output)
                self.assertEqual(result.returncode, 1)
                diagnostic = json.loads(result.stderr)
                self.assertEqual(diagnostic["code"], "LIFT_UNSUPPORTED_CONTROL_FLOW")
                self.assertEqual(diagnostic["context"]["import_symbol"], name)
                self.assertIn("requires a managed process artifact", diagnostic["message"])

    def test_gs_requires_process_and_supported_offset(self):
        pe = image("tib")
        data = bytearray(pe.read_bytes())
        root = entry(data)
        result = run(FORGE, "lift", pe, "--rva", hex(root), "--signature", "i64(i64,i64)",
                     "--diagnostics-format", "json", "--output", self.output)
        self.assertEqual(result.returncode, 1)
        self.assertIn("requires a managed guest process", json.loads(result.stderr)["message"])
        offset = Layout(data).file_offset(root)
        self.assertEqual(data[offset:offset + 9], bytes.fromhex("654c8b142530000000"))
        data[offset + 5] = 0x60
        self.assertEqual(self.reject(data)["code"], "LIFT_UNSUPPORTED_PREFIX")

    def test_loader_inventory_survives_early_decode_failure(self):
        data = bytearray((FIXTURES / "metadata.exe").read_bytes())
        layout = Layout(data)
        root = entry(data)
        start = layout.file_offset(root)
        data[start:start + 2] = bytes.fromhex("ff e0")  # Unresolved JMP RAX
        diagnostic = self.reject(data)
        self.assertEqual(diagnostic["code"], "LIFT_UNSUPPORTED_CONTROL_FLOW")
        context = diagnostic["context"]
        self.assertEqual(context["instruction_rva"], hex(root))
        self.assertFalse(context["recovery_complete"])
        self.assertEqual(context["imports"], [])
        base = struct.unpack_from("<Q", data, layout.opt + 24)[0]
        self.assertEqual(context["tls"]["callback_vas"], [hex(base + root)])
        self.assertEqual(context["tls"]["zero_fill_size"], 4)
        self.assertIn("loader callbacks are unsupported", context["tls"]["limitation"])

        expected = {}
        position = layout.file_offset(layout.directory(1)[0])
        while layout.u32(position + 12):
            dll_offset = layout.file_offset(layout.u32(position + 12))
            dll = data[dll_offset:data.index(0, dll_offset)].decode().lower()
            iat = layout.u32(position + 16)
            expected[dll] = iat
            position += 20
        slots = {item["dll"].lower(): item["symbols"] for item in context["load_imports"]}
        self.assertEqual(set(slots), set(expected))
        self.assertEqual([(s["name"], s["iat_slot_rva"]) for s in slots["physics.dll"]],
                         [("#7", hex(expected["physics.dll"])), ("Named", hex(expected["physics.dll"] + 8))])
        self.assertEqual(slots["kernel32.dll"][0]["iat_slot_rva"], hex(expected["kernel32.dll"]))
        self.assertFalse(any(slot["catalogued_service"] for slot in slots["physics.dll"]))

    def test_entry_handler_evidence_survives_early_decode_failure(self):
        data = bytearray(image("return").read_bytes())
        layout = Layout(data)
        root = entry(data)
        data[layout.file_offset(root):layout.file_offset(root) + 2] = bytes.fromhex("ff e0")
        record = layout.file_offset(layout.directory(3)[0])
        unwind = layout.u32(record + 8)
        info = layout.file_offset(unwind)
        data[info] |= 1 << 3  # UNW_FLAG_EHANDLER
        trailer = info + 4 + ((data[info + 2] + 1) & ~1) * 2
        # Extend the file-backed virtual extent of .xdata into its existing raw padding.
        section = layout.section_header(unwind)
        raw = layout.u32(section + 20)
        self.assertLessEqual(trailer + 4 - raw, layout.u32(section + 16))
        struct.pack_into("<I", data, section + 8, max(layout.u32(section + 8), trailer + 4 - raw))
        struct.pack_into("<I", data, trailer, root)
        diagnostic = self.reject(data)
        self.assertEqual(diagnostic["code"], "LIFT_UNSUPPORTED_CONTROL_FLOW")
        self.assertEqual(diagnostic["context"]["entry_unwind_handler"],
                         {"unwind_rva": hex(unwind), "handler_rva": hex(root)})


class Reference(Workspace):
    def capture(self, source, args=()):
        suite = Path(__file__).resolve().parents[1] / "differential"
        sys.path.insert(0, str(suite))
        sys.path.insert(0, str(suite / "reference"))
        from docker_wine import execute
        from fixture_images import reference_environment

        pe = self.dir / source.name
        shutil.copyfile(source, pe)
        result = execute(reference_environment(suite)["container_image_id"], pe, list(args))
        return result.exit_code, result.stdout, result.stderr

    def test_executables(self):
        headers = image("headers")
        expected = {
            image("bounded-cleanup").name: (42, b"", b""),
            image("forward-call").name: (42, b"", b""),
            image("bounded-call").name: (42, b"", b""),
            image("tail-jump").name: (42, b"", b""),
            headers.name: (header_result(headers.read_bytes()), b"", b""),
            image("cmp16mi").name: CMP16MI,
            "crt-app-type-console.exe": APP_TYPE_RETURN,
            "crt-app-type-gui.exe": APP_TYPE_RETURN,
            **{f"crt-app-type-fatal-{mode}.exe": (255, b"", b"")
               for mode in ("console", "conflict", "gui", "unusual", "gui-unknown", "gui-newline")},
            "crt-argument-heap.exe": (41, b"", b""),
            "crt-initterm.exe": (42, b"", b""),
            "crt-initterm-spill.exe": (2, b"", b""),
            "crt-initterm-nested_table.exe": (42, b"MMM", b""),
            "crt-initterm-terminal.exe": (57, b"", b""),
            image("import-register").name: (42, b"", b""),
            image("noreturn").name: (42, b"", b""),
            image("tib").name: (42, b"", b""),
            image("top-level-filter").name: (42, b"", b""),
            console_image("hello").name: (0, GREETING, b""),
            console_image("binary_stdout").name: (len(BINARY), BINARY, b""),
            console_image("binary_stderr").name: (len(BINARY), b"", BINARY),
            console_image("nested_exit").name: (0xcafe002a, b"", b""),
        }
        for prefix in ("crt-term-", "executable-startup-info-"):
            for name, observation in legacy_observations("wine", prefix).items():
                expected[name] = captured_streams(observation)
        for filename, observations in amsg_observations("wine", AMSG_CASES + AMSG_MARKERS).items():
            expected[filename] = captured_streams(observations["pipe"])
        inputs = Path(__file__).resolve().parents[1] / "differential/reference/executable-inputs.txt"
        filenames = inputs.read_text().splitlines()
        self.assertEqual(filenames, sorted(expected))
        for name in filenames:
            with self.subTest(pe=name):
                self.assertEqual(self.capture(FIXTURES / name), expected[name])
        self.assertEqual(self.capture(FIXTURES / "crt-argument-heap.exe", ["*example"]),
                         (42, b"", b""))


class WindowsComparison(unittest.TestCase):
    def test_cmp16mi(self):
        pe = image("cmp16mi").resolve()
        digest = hashlib.sha256(pe.read_bytes()).hexdigest()
        self.assertEqual(digest, "19b6cdda1cf0f07807fdec86cb31247511628b7913406331de987291de553829")
        result = subprocess.run([pe], capture_output=True, timeout=10)
        print(f"{platform.platform()} {digest} exit={result.returncode} "
              f"stdout={result.stdout.hex()} stderr={result.stderr.hex()}", flush=True)
        self.assertEqual((result.returncode, result.stdout, result.stderr), CMP16MI)


class WindowsExecutable(unittest.TestCase):
    def check_image(self, name):
        pe = image(name).resolve()
        manifest = FIXTURES / "SHA256SUMS"
        self.assertEqual(hashlib.sha256(manifest.read_bytes()).hexdigest(), os.environ["PE_MANIFEST_SHA256"])
        digest = hashlib.sha256(pe.read_bytes()).hexdigest()
        self.assertIn(f"{digest}  {pe.name}", manifest.read_text().splitlines())
        result = subprocess.run([pe], capture_output=True, timeout=10)
        print(f"{pe.name} sha256={digest} exit={result.returncode} stdout={result.stdout.hex()} stderr={result.stderr.hex()}")
        self.assertEqual((result.returncode, result.stdout, result.stderr), (42, b"", b""))


class WindowsTailJump(WindowsExecutable):
    def test_tail_jump(self):
        self.check_image("tail-jump")


class WindowsBoundedCall(WindowsExecutable):
    def test_bounded_call(self):
        self.check_image("forward-call")
        self.check_image("bounded-call")
        self.check_image("bounded-cleanup")


class WindowsStartup(unittest.TestCase):
    def test_startup(self):
        sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "differential"))
        from comparison import Observation
        from manifests import load_catalog

        cases = [manifest.case for manifest in load_catalog() if manifest.case["id"].startswith("startup/")]
        self.assertEqual(len(cases), 8)
        for config in ("debug", "release"):
            directory = FIXTURES / config
            checksums = (directory / "SHA256SUMS").read_text().splitlines()
            for case in cases:
                with self.subTest(config=config, fixture=case["id"]):
                    pe = (directory / case["binary"]).resolve()
                    digest = hashlib.sha256(pe.read_bytes()).hexdigest()
                    self.assertIn(f"{digest}  {pe.name}", checksums)
                    result = subprocess.run([pe, *case["args"]], capture_output=True, timeout=10)
                    print(f"{config}/{case['id']} sha256={digest} exit={result.returncode} "
                          f"stdout={result.stdout.hex()} stderr={result.stderr.hex()}", flush=True)
                    self.assertEqual(Observation(result.returncode, result.stdout, result.stderr),
                                     Observation.from_manifest(case["expected"]))


class WindowsAppType(unittest.TestCase):
    def test_system_crt(self):
        dll = Path(os.environ["SystemRoot"]) / "System32/msvcrt.dll"
        data = dll.read_bytes()
        layout = Layout(data)
        print(f"{platform.platform()} {dll.name} sha256={hashlib.sha256(data).hexdigest()} "
              f"timestamp={layout.u32(layout.pe + 8):08X} size={layout.u32(layout.opt + 56):x}", flush=True)
        manifest = FIXTURES / "SHA256SUMS"
        self.assertEqual(hashlib.sha256(manifest.read_bytes()).hexdigest(), os.environ["PE_MANIFEST_SHA256"])
        hashes = {name: sha for sha, name in (line.split() for line in manifest.read_text().splitlines())}
        fatal = captured_streams(amsg_observations("windows", ("8",))["crt-amsg-exit-8.exe"]["pipe"])
        for name, expected in (("crt-app-type-console", APP_TYPE_RETURN), ("crt-app-type-gui", APP_TYPE_RETURN),
                               ("crt-amsg-exit-8", fatal), ("crt-app-type-fatal-console", fatal),
                               ("crt-app-type-fatal-conflict", fatal), ("crt-app-type-fatal-unusual", fatal),
                               ("crt-app-type-fatal-gui-unknown", (255, b"", b"")),
                               ("crt-app-type-fatal-gui-newline", (255, b"", b""))):
            with self.subTest(name=name):
                pe = (FIXTURES / (name + ".exe")).resolve()
                digest = hashlib.sha256(pe.read_bytes()).hexdigest()
                self.assertEqual(digest, hashes[pe.name])
                # GUI children exercise returning setters and fatal IDs that skip the dialog.
                result = subprocess.run([pe], capture_output=True, timeout=8)
                print(f"{name} {digest} exit={result.returncode} stdout={result.stdout.hex()} "
                      f"stderr={result.stderr.hex()}", flush=True)
                self.assertEqual((result.returncode, result.stdout, result.stderr), expected)


def bounded_fixture(pe=None):
    if pe is None:
        pe = image("bounded-call")
    module = json.loads(run(FORGE, "inspect", pe, "--format", "json", check=True).stdout)["modules"][0]
    symbols = {n: int(e["rva"], 16) for e in module["exports"] for n in e["names"]}
    return pe.read_bytes(), symbols


def null_walk(data, layout, site):
    """Locate the two LEAs and pointer load in the fixture's run_null function."""
    pdata, size = layout.directory(3)
    records = layout.file_offset(pdata)
    rows = struct.iter_unpack("<III", data[records:records + size])
    inner = next(start for start, end, _ in rows if start <= site < end)
    start, end = layout.file_offset(inner), layout.file_offset(site)
    bounds = data.index(bytes.fromhex("488d1d"), start, end)
    assert data.startswith(bytes.fromhex("488d35"), bounds + 7)
    load = data.index(bytes.fromhex("488b03"), bounds + 14, end)
    return inner, inner + bounds - start, inner + load - start


def set_forward_bounds(data, layout, bounds, first, last):
    for lea, dest in ((bounds, first), (bounds + 7, last)):
        struct.pack_into("<i", data, layout.file_offset(lea) + 3, dest - (lea + 7))


class Console(Workspace):
    def test_forward_empty_section_boundary(self):
        original, symbols = bounded_fixture(image("forward-call"))
        layout = Layout(original)
        site = symbols["null_site"]
        _, bounds, _ = null_walk(original, layout, site)
        tail = symbols["null_only"]
        reloc, _ = layout.directory(5)
        boundary = layout.u32(layout.section_header(reloc) + 12)
        pe = self.dir / "boundary.exe"
        for name, extent, first, last in (("empty", boundary, boundary, boundary),
                                          ("nonempty", boundary, boundary, boundary + 8),
                                          ("gap", boundary - 16, boundary - 8, boundary - 8)):
            with self.subTest(name=name):
                data = bytearray(original)
                struct.pack_into("<I", data, layout.section_header(tail) + 8, extent - tail)
                set_forward_bounds(data, layout, bounds, first, last)
                pe.write_bytes(data)
                if name == "empty":
                    tables = self.compile(pe)["context"]["bounded_calls"]
                    row = next(row for row in tables if row["instruction_rva"] == hex(site))
                    self.assertEqual((row["first_rva"], row["last_rva"], row["initial_target_rvas"]),
                                     (hex(first), hex(last), []))
                    result = self.program()
                    self.assertEqual((result.returncode, result.stdout, result.stderr), (42, b"", b""))
                else:
                    report = self.compile(pe, success=False)
                    self.assertEqual(report["code"], "LIFT_IMAGE_MEMORY")
                    self.assertIn(f"invalid guest pointer table at {first:#x}", report["message"])

    def test_forward_store_image_selection(self):
        original, symbols = bounded_fixture(image("forward-call"))
        large = bytearray(original)
        layout = Layout(large)
        layout.add_unused_section(256 << 20, 0xc0000080)
        site = symbols["many_site"]
        store = layout.file_offset(site) - 7
        self.assertEqual(large[store:store + 7], bytes.fromhex("48c703 00000000"))
        pe = self.dir / "store.exe"
        for name, instruction in (("immediate", large[store:store + 7]),
                                  ("register", bytes.fromhex("488903 90909090")),
                                  ("sib_no_index", bytes.fromhex("48890423 909090")),
                                  ("sib_no_index_scale_two", bytes.fromhex("48890463 909090")),
                                  ("indexed", bytes.fromhex("4889044b 909090")),
                                  ("other_base", bytes.fromhex("48c700 00000000")),
                                  ("next_slot", bytes.fromhex("48894308 909090")),
                                  ("segment_override", bytes.fromhex("65488903 909090"))):
            with self.subTest(name=name):
                data = bytearray(large)
                data[store:store + 7] = instruction
                pe.write_bytes(data)
                if name == "segment_override":
                    report = self.compile(pe, success=False)
                    self.assertEqual(report["context"]["instruction_rva"], hex(site - 7))
                    self.assertEqual(report["code"], "LIFT_UNSUPPORTED_PREFIX")
                elif name in ("other_base", "next_slot", "indexed"):
                    report = self.compile(pe, success=False)
                    self.assertEqual(report["code"], "LIFT_IMAGE_MEMORY")
                    self.assertEqual(report["context"]["instruction_rva"], hex(site - 7))
                    self.assertIn("writable virtual limit", report["message"])
                else:
                    self.compile(pe)
                    result = self.program()
                    self.assertEqual((result.returncode, result.stdout, result.stderr), (42, b"", b""))

    def test_forward_store_read_only_slot(self):
        original, symbols = bounded_fixture(image("forward-call"))
        data = bytearray(original)
        layout = Layout(data)
        base, = struct.unpack_from("<Q", data, layout.opt + 24)
        # The fixture starts .rdata with relocated pointer cells. Reuse one as the table.
        slot = next(rva for _, rva, _, _ in layout.sections
                    if data.startswith(b".rdata\0", layout.section_header(rva)))
        struct.pack_into("<Q", data, layout.file_offset(slot), base + symbols["terminal"])
        set_forward_bounds(data, layout, symbols["many_bounds"], slot, slot + 8)
        pe = self.dir / "readonly.exe"
        pe.write_bytes(data)
        self.compile(pe)
        result = self.program()
        self.assertEqual((result.returncode, result.stdout), (125, b""))
        self.assertIn(f"forge: guest memory fault address={base + slot:#x} access=2 reason=3\n".encode(),
                      result.stderr)

    def test_forward_all_terminal(self):
        original, symbols = bounded_fixture(image("forward-call"))
        data = bytearray(original)
        layout = Layout(data)
        base, = struct.unpack_from("<Q", data, layout.opt + 24)
        single = symbols["empty"] - 8
        self.assertEqual(struct.unpack_from("<Q", data, layout.file_offset(single))[0],
                         base + symbols["single_callback"])
        struct.pack_into("<Q", data, layout.file_offset(single), base + symbols["terminal"])
        pe = self.dir / "terminal.exe"
        pe.write_bytes(data)
        self.compile(pe)
        result = self.program()
        self.assertEqual((result.returncode, result.stdout, result.stderr), (57, b"", b""))

    def test_forward_live_targets(self):
        pe = image("forward-call")
        original, symbols = bounded_fixture(pe)
        layout = Layout(original)
        preferred, = struct.unpack_from("<Q", original, layout.opt + 24)
        run(CONTRACT, "--guest-base", hex(preferred + 0x30000000), pe, self.output,
            OPT, LLC, "/usr/bin/xcrun", *LINK, check=True)
        result = self.program()
        self.assertEqual((result.returncode, result.stdout, result.stderr), (42, b"", b""))
        # This nonempty zero-filled range admits no targets. A guest write makes
        # its call reachable with a nonzero register. The default dispatch must fault.
        data = bytearray(original)
        struct.pack_into("<I", data, layout.opt + 16, symbols["tamper_null"])
        modified = self.dir / "null-table.exe"
        modified.write_bytes(data)
        self.compile(modified)
        result = self.program()
        expected = (f"forge: bounded call RVA {symbols['null_site']:#x} table RVA {symbols['null_only']:#x}\n"
                    "forge: guest control fault\n").encode()
        self.assertEqual((result.returncode, result.stdout, result.stderr), (125, b"", expected))

        for target, code, fault in (("single_callback", 125, "control"), ("bad_return", 125, "control"),
                                    ("bad_save", 125, "ABI"), ("terminal", 57, None)):
            with self.subTest(target=target):
                data = bytearray(original)
                # single_callback is admitted at a different call site in this module.
                slot = symbols["replacement"] if target == "single_callback" else symbols["slots"]+16
                struct.pack_into("<Q", data, layout.file_offset(slot), preferred + symbols[target])
                modified = self.dir / "forward.exe"
                modified.write_bytes(data)
                self.compile(modified)
                result = self.program()
                expected = (f"forge: bounded call RVA {symbols['many_site']:#x} table RVA {symbols['slots']:#x}\n"
                            f"forge: guest {fault} fault\n").encode() if fault else b""
                self.assertEqual((result.returncode, result.stdout, result.stderr), (code, b"", expected))

    def test_counted_scan_escape(self):
        original, symbols = bounded_fixture()
        layout = Layout(original)
        # Both have a readable NULL just past the proved extent. Without the
        # scan guard the empty list returns 42 and the two-slot list exits 57.
        for header, site in (("switch_table", "switch_site"), ("mixed_table", "mixed_site")):
            with self.subTest(header=header):
                data = bytearray(original)
                if header == "switch_table":
                    struct.pack_into("<Q", data, layout.file_offset(symbols[header]), 0)
                else:
                    struct.pack_into("<I", data, layout.opt + 16, symbols["overrun_switch"])
                pe = self.dir / "escape.exe"
                pe.write_bytes(data)
                self.compile(pe)
                result = self.program()
                expected = (f"forge: bounded call RVA {symbols[site]:#x} table RVA {symbols[header]:#x}\n"
                            "forge: guest control fault\n").encode()
                self.assertEqual((result.returncode, result.stdout, result.stderr), (125, b"", expected))

    def test_bounded_zero_filled_terminator(self):
        original, symbols = bounded_fixture()
        data = bytearray(original)
        layout = Layout(data)
        end = symbols["one_table"] + 16
        section = layout.section_header(end)
        raw_size = end - layout.u32(section + 12)
        self.assertEqual(raw_size % 512, 0)
        self.assertLess(raw_size, layout.u32(section + 16))
        struct.pack_into("<I", data, section + 16, raw_size)
        pe = self.dir / "zero-tail.exe"
        pe.write_bytes(data)
        self.compile(pe)
        result = self.program()
        self.assertEqual((result.returncode, result.stdout, result.stderr), (42, b"", b""))

    def test_bounded_live_failures(self):
        original, symbols = bounded_fixture()
        layout = Layout(original)
        base, = struct.unpack_from("<Q", original, layout.opt + 24)
        site = symbols["count_site"]
        header = symbols["count_table"]
        prefix = f"forge: bounded call RVA {site:#x} table RVA {header:#x}\n".encode()
        for target in ("foreign", "null", "bad_nonvolatile", "bad_return", "terminal", "all_terminal", "shorten_mixed", "tamper_count", "tamper_scan"):
            with self.subTest(target=target):
                data = bytearray(original)
                def set_pointer(slot, rva):
                    struct.pack_into("<Q", data, layout.file_offset(slot), base + rva if rva else 0)

                if target in ("bad_nonvolatile", "bad_return"):
                    # These become legitimate entries but violate the normal return contract.
                    set_pointer(header + 32, symbols[target])
                    expected = prefix + (b"forge: guest ABI fault\n" if target == "bad_nonvolatile"
                                         else b"forge: guest control fault\n")
                elif target.startswith("tamper_"):
                    struct.pack_into("<I", data, layout.opt + 16, symbols[target])
                    at, table = site, header
                    if target == "tamper_scan":
                        at = symbols["run_empty"] + site - symbols["run_count"]
                        table = symbols["empty_table"]
                    expected = (f"forge: bounded call RVA {at:#x} table RVA {table:#x}\n"
                                "forge: guest control fault\n").encode()
                elif target in ("terminal", "all_terminal", "shorten_mixed"):
                    root = symbols["shorten_mixed"] if target == "shorten_mixed" else symbols["run_mixed"]
                    struct.pack_into("<I", data, layout.opt + 16, root)
                    if target == "all_terminal":
                        set_pointer(symbols["mixed_table"] + 8, symbols["terminal"])
                    expected = b""
                else:
                    # The writer retargets an earlier slot after recovery. Its replacement
                    # cell supplies either NULL or a body admitted only at another site.
                    if target == "null":
                        writer = layout.file_offset(symbols["writer"])
                        insn = data.index(bytes.fromhex("488b05"), writer)
                        data[insn:insn + 7] = bytes.fromhex("48c7c000000000")
                    else:
                        set_pointer(symbols["replacement"], symbols["exclusive"])
                    expected = prefix + b"forge: guest control fault\n"
                pe = self.dir / "mutation.exe"
                pe.write_bytes(data)
                self.compile(pe)
                result = self.program()
                self.assertEqual((result.returncode, result.stdout, result.stderr),
                                 (dict(terminal=57, all_terminal=57, shorten_mixed=42).get(target, 125), b"", expected))


    def test_bounded_call(self):
        self.compile(image("bounded-cleanup"))
        cleanup = self.program()
        self.assertEqual((cleanup.returncode, cleanup.stdout, cleanup.stderr), (42, b"", b""))
        pe = image("bounded-call")
        self.compile(pe)
        result = self.program()
        self.assertEqual((result.returncode, result.stdout, result.stderr), (42, b"", b""))
        data = pe.read_bytes()
        preferred, = struct.unpack_from("<Q", data, Layout(data).opt + 24)
        run(CONTRACT, "--guest-base", hex(preferred + 0x30000000), pe, self.output,
            OPT, LLC, "/usr/bin/xcrun", *LINK, check=True)
        result = self.program()
        self.assertEqual((result.returncode, result.stdout, result.stderr), (42, b"", b""))

    def test_tail_jump(self):
        pe = image("tail-jump")
        self.compile(pe)
        result = self.program()
        self.assertEqual((result.returncode, result.stdout, result.stderr), (42, b"", b""))

        module = json.loads(run(FORGE, "inspect", pe, "--format", "json", check=True).stdout)["modules"][0]
        terminal = next(int(row["rva"], 16) for row in module["exports"] if "terminal" in row["names"])
        data = bytearray(pe.read_bytes())
        struct.pack_into("<I", data, Layout(data).opt + 16, terminal)
        probe = self.dir / "terminal.exe"
        probe.write_bytes(data)
        self.compile(probe)
        result = self.program()
        self.assertEqual((result.returncode, result.stdout, result.stderr), (57, b"", b""))

    def test_cmp16mi(self):
        pe = image("cmp16mi")
        data = pe.read_bytes()
        layout = Layout(data)
        start = layout.file_offset(entry(data))
        self.assertEqual(data[start + 11:start + 16], bytes.fromhex("66 81 38 4d 5a"))
        self.assertIn(bytes.fromhex("66 43 81 3c 08 ff 7f"), data[start:start + 0x100])
        self.compile(pe)
        result = self.program()
        self.assertEqual((result.returncode, result.stdout, result.stderr), CMP16MI)

        preferred, = struct.unpack_from("<Q", data, layout.opt + 24)
        run(CONTRACT, "--guest-base", hex(preferred + 0x30000000), pe, self.output,
            OPT, LLC, "/usr/bin/xcrun", *LINK, check=True)
        rebased = self.program()
        self.assertEqual((rebased.returncode, rebased.stdout, rebased.stderr), CMP16MI)

    def test_crt_app_type(self):
        fatal = captured_streams(amsg_observations("windows", ("8",))["crt-amsg-exit-8.exe"]["pipe"])
        for mode, expected in (("console", APP_TYPE_RETURN), ("gui", APP_TYPE_RETURN), ("fatal-console", fatal),
                               ("fatal-conflict", fatal), ("fatal-unusual", fatal),
                               ("fatal-gui-unknown", (255, b"", b"")), ("fatal-gui-newline", (255, b"", b"")),
                               ("fatal-gui", (125, b"",
                                    b"forge: unsupported MSVCRT _amsg_exit GUI diagnostic routing\n"))):
            with self.subTest(mode=mode):
                self.compile(FIXTURES / f"crt-app-type-{mode}.exe")
                result = self.program()
                self.assertEqual((result.returncode, result.stdout, result.stderr), expected)

    def test_gui_subsystem_before_setter(self):
        # The checked Windows control calls only _amsg_exit. Change its PE subsystem
        # to exercise initial GUI classification without launching a Windows dialog.
        data = bytearray((FIXTURES / "crt-amsg-exit-8.exe").read_bytes())
        subsystem = Layout(data).opt + 68
        self.assertEqual(struct.unpack_from("<H", data, subsystem), (3,))
        struct.pack_into("<H", data, subsystem, 2)
        pe = self.dir / "gui.exe"
        pe.write_bytes(data)
        self.compile(pe)
        result = self.program()
        self.assertEqual((result.returncode, result.stdout, result.stderr),
                         (125, b"", b"forge: unsupported MSVCRT _amsg_exit GUI diagnostic routing\n"))

    def test_crt_fatal_exit(self):
        for filename, observations in amsg_observations("windows").items():
            pe = FIXTURES / filename
            data = pe.read_bytes()
            preferred, = struct.unpack_from("<Q", data, Layout(data).opt + 24)
            for base in (preferred, preferred + 0x30000000):
                with self.subTest(pe=filename, base=hex(base)):
                    if base == preferred:
                        diagnostic = self.compile(pe)
                        directory, = diagnostic["context"]["load_imports"]
                        slot, = directory["symbols"]
                        self.assertEqual((directory["dll"].lower(), slot["name"], slot["catalogued_service"]),
                                         ("msvcrt.dll", "_amsg_exit", True))
                    else:
                        run(CONTRACT, "--guest-base", hex(base), pe, self.output, OPT, LLC,
                            "/usr/bin/xcrun", *LINK, check=True)
                    result = self.program()
                    self.assertEqual((result.returncode, result.stdout, result.stderr),
                                     captured_streams(observations["pipe"]))

    def test_crt_fatal_exit_skips_marker(self):
        for filename, observations in amsg_observations("windows", AMSG_MARKERS).items():
            with self.subTest(pe=filename):
                self.compile(FIXTURES / filename)
                result = self.program()
                self.assertEqual((result.returncode, result.stdout, result.stderr),
                                 captured_streams(observations["pipe"]))
                self.assertEqual(result.stdout, b"M" if filename.endswith("-control.exe") else b"")

    def test_crt_fatal_exit_redirected_handles(self):
        (filename, observations), = amsg_observations("windows", ("31",)).items()
        self.compile(FIXTURES / filename)
        out, err = self.dir / "stdout.bin", self.dir / "stderr.bin"
        with out.open("wb") as stdout, err.open("wb") as stderr:
            result = self.program(stdout=stdout, stderr=stderr)
        self.assertEqual((result.returncode, out.read_bytes(), err.read_bytes()),
                         captured_streams(observations["file"]))

        def close_outputs():
            os.close(1)
            os.close(2)

        result = self.program(preexec_fn=close_outputs)
        self.assertEqual((result.returncode, result.stdout, result.stderr),
                         (observations["invalid"]["exit_code"], b"", b""))

        reader, writer = os.pipe()
        os.close(reader)
        with os.fdopen(writer, "wb") as broken:
            result = self.program(stdout=broken, stderr=broken)
        self.assertEqual(result.returncode, observations["broken-pipe"]["exit_code"])

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

    def test_read_only_output(self):
        path = self.dir / "read-only output"
        path.touch()
        for name, stream in (("host_failure", "stdout"), ("stderr_failure", "stderr"),
                             ("zero_stdout_failure", "stdout"), ("zero_stderr_failure", "stderr")):
            with self.subTest(name=name):
                self.compile(console_image(name))
                with path.open("rb") as read_only:
                    result = self.program(**{stream: read_only})
                other = result.stderr if stream == "stdout" else result.stdout
                # Each entry checks FALSE and a zero count before returning GetLastError().
                self.assertEqual((result.returncode, other, path.read_bytes()), (5, b"", b""))

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
                                     ("alternate_edge", 9, BINARY), ("call_at_end", 42, b""),
                                     ("branch_past_call", 23, b""), ("recursive_return", 13, b""),
                                     ("recursive_exit", 42, b"")):
            with self.subTest(name=name):
                self.compile(console_image(name))
                result = self.program()
                self.assertEqual((result.returncode, result.stdout, result.stderr), (status, b"", stderr))

    def test_compiled_noreturn_helper(self):
        pe = image("noreturn")
        diagnostic = self.compile(pe)
        result = self.program()
        self.assertEqual((result.returncode, result.stdout, result.stderr), (42, b"", b""))

        # Clang emits INT3 in the caller after CALL rel32. Even an incomplete instruction
        # here must be irrelevant to recovery when no other edge reaches this byte.
        call, = diagnostic["context"]["calls"]
        data = bytearray(pe.read_bytes())
        offset = Layout(data).file_offset(int(call["instruction_rva"], 16))
        self.assertEqual((data[offset], data[offset + 5]), (0xe8, 0xcc))
        data[offset + 5] = 0x0f
        truncated = self.dir / "unreachable-byte.exe"
        truncated.write_bytes(data)
        self.compile(truncated)
        result = self.program()
        self.assertEqual((result.returncode, result.stdout, result.stderr), (42, b"", b""))

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
    def test_repeated_cross_block_initializer_ranges(self):
        count = 6
        data, end = initializer_calls_at_image_end([0] * count, cross_block=True)
        pe = self.dir / "cross-block.exe"
        pe.write_bytes(data)
        tables = self.compile(pe)["context"]["initializer_tables"]
        self.assertEqual(len(tables), count)
        self.assertEqual(len({row["instruction_rva"] for row in tables}), count)
        for row in tables:
            self.assertEqual((row["first_rva"], row["last_rva"], row["initial_target_rvas"]),
                             (hex(end), hex(end), []))
        self.assertEqual(run(self.output).returncode, 0)

    def test_initializer_spill_and_zero_filled_endpoint(self):
        data, _ = initializer_zero_tail()
        pe = self.dir / "zero-tail.exe"
        pe.write_bytes(data)
        for base in (0x400000, 0x180000000):
            with self.subTest(base=hex(base)):
                run(CONTRACT, "--guest-base", hex(base), pe, self.output,
                    OPT, LLC, "/usr/bin/xcrun", *LINK, check=True)
                result = run(self.output)
                self.assertEqual((result.returncode, result.stdout, result.stderr), (2, "", ""))

    def test_initializer_order_rebasing_and_isolation(self):
        pe = FIXTURES / "crt-initterm.exe"
        diagnostic = self.compile(pe)
        self.assertIn({"dll": "msvcrt.dll", "name": "_initterm"}, diagnostic["context"]["imports"])
        result = run(self.output)
        self.assertEqual((result.returncode, result.stdout, result.stderr), (42, "", ""))

        data = pe.read_bytes()
        preferred, = struct.unpack_from("<Q", data, Layout(data).opt + 24)
        run(CONTRACT, "--guest-base", hex(preferred + 0x30000000), pe, self.output,
            OPT, LLC, "/usr/bin/xcrun", *LINK, check=True)
        rebased = run(self.output)
        self.assertEqual((rebased.returncode, rebased.stdout, rebased.stderr), (42, "", ""))

        # The first process overwrites both a writable table entry and the decimal accumulator.
        # The second process must start from the same PE's original slot and zero state.
        obj = self.dir / "initializers.o"
        run(CONTRACT, pe, "--object", obj, OPT, LLC, check=True)
        _, runtime, sdk, *flags = LINK
        run("/usr/bin/xcrun", "--sdk", sdk, "clang++", "-arch", "arm64", *flags,
            PROCESS_HARNESS, obj, runtime, "-o", self.output, check=True)
        result = run(self.output, "run", "0", "0", "0", "0", check=True)
        self.assertEqual(result.stderr, "")
        self.assertEqual(result.stdout.splitlines()[-2:], ["return 42"] * 2)

    def test_initializer_outcomes(self):
        opaque = "forge: unsupported guest access to a native callback return slot\n"
        unknown = "forge: unsupported MSVCRT initializer target\n"
        argument = "forge: unsupported guest access above the callback home space\n"
        for variant, status, stdout, stderr in (
                ("nested_table", 42, "MMM", ""), ("terminal", 57, "", ""),
                ("guest_fault", 125, "", "forge: guest memory fault address=0x1 access=1 reason=2\n"),
                ("stack_exhaustion", 125, "", "forge: guest memory fault address=0x6fffffe8 access=2 reason=4\n"),
                ("unknown_target", 125, "", unknown), ("data_target", 125, "", unknown),
                ("other_function", 125, "", unknown), ("other_initializer", 125, "", unknown),
                ("bad_rsp", 125, "", "forge: guest control fault\n"),
                ("clobber", 125, "", "forge: guest ABI fault\n"),
                ("nonvolatile_arg", 125, "", "forge: guest ABI fault\n"),
                ("stack_alias", 125, "", argument), ("tail_alias", 125, "", argument), ("service_alias", 125, "", argument),
                ("before_return", 125, "", "forge: guest memory fault address=0x70000f77 access=1 reason=4\n"),
                ("read_return", 125, "", opaque),
                ("write_return", 125, "", opaque), ("service_return", 125, "", opaque)):
            with self.subTest(variant=variant):
                self.compile(FIXTURES / f"crt-initterm-{variant}.exe")
                result = run(self.output)
                self.assertEqual((result.returncode, result.stdout, result.stderr), (status, stdout, stderr))

    def test_initializer_unsupplied_arguments(self):
        for variant, code, reason in (
                ("register_arg", "LIFT_UNDEFINED_REGISTER", "undefined incoming RCX"),
                ("stack_arg", "LIFT_UNSUPPORTED_CONTROL_FLOW", "no incoming Windows x64 stack arguments")):
            with self.subTest(variant=variant):
                diagnostic = self.compile(FIXTURES / f"crt-initterm-{variant}.exe", success=False)
                self.assertEqual((diagnostic["stage"], diagnostic["category"], diagnostic["code"]),
                                 ("lifting", "unsupported", code))
                self.assertIn(reason, diagnostic["message"])
                self.assertFalse(self.output.exists())

    def test_termination_matches_windows(self):
        for name, row in legacy_observations("windows", "crt-term-").items():
            with self.subTest(pe=name):
                self.compile(FIXTURES / name)
                result = self.program()
                code, stdout, stderr = captured_streams(row)
                self.assertEqual((result.returncode, result.stdout, result.stderr),
                                 (code & 255, stdout, stderr))

    def test_termination_callback_guards(self):
        for variant, marker, detail in (
                ("wrong-origin", "", "unproven MSVCRT termination callback for registration site"),
                ("unmapped", "", "unproven MSVCRT termination callback for registration site"),
                ("fault", "B", "guest memory fault address=0x1 access=1 reason=2"),
                ("nested-fault", "BC", "guest memory fault address=0x1 access=1 reason=2"),
                ("return-slot", "B", "unsupported guest access to a native callback return slot"),
                ("stack-above", "B", "unsupported guest access above the callback home space"),
                ("recursive-limit", "B" * 16, "unsupported recursive MSVCRT cleanup or handler limit")):
            with self.subTest(variant=variant):
                self.compile(FIXTURES / f"crt-term-{variant}.exe")
                result = run(self.output)
                self.assertEqual((result.returncode, result.stdout, result.stderr), (125, marker, f"forge: {detail}\n"))

        diagnostic = self.compile(FIXTURES / "crt-term-data.exe", success=False)
        self.assertEqual(diagnostic["code"], "LIFT_INVALID_CALL_TARGET")
        self.assertEqual(diagnostic["context"]["import_symbol"], "_onexit")
        self.assertIn("termination_target_rva", diagnostic["context"])

    def test_nonnull_tail_registration(self):
        self.compile(FIXTURES / "crt-term-tail-registration.exe")
        result = self.program()
        self.assertEqual((result.returncode, result.stdout, result.stderr), (42, b"B", b""))

    def test_null_registration_and_wrapper_diagnostics(self):
        pe = FIXTURES / "crt-term-null.exe"
        self.compile(pe)
        result = self.program()
        self.assertEqual((result.returncode, result.stdout, result.stderr), (91, b"", b""))

        # Read helper and wrapper extents from the fixture's unwind records.
        data = pe.read_bytes()
        layout = Layout(data)
        pdata = layout.file_offset(layout.directory(3)[0])
        helper, wrapper = layout.u32(pdata + 12), layout.u32(pdata + 24)
        mov = layout.file_offset(helper) + 4
        self.assertEqual(data[mov:mov + 6], bytes.fromhex("b900000000e8"))
        call, registration = helper + 9, wrapper + 4
        iat = registration + 6 + struct.unpack_from("<i", data, layout.file_offset(registration) + 2)[0]
        # A tail origin supplies the same proven null to the wrapper. Restore the
        # inherited stack before the jump and retain the original unwind extent.
        tail = bytearray(data)
        jump = helper + 13
        tail[mov + 5:mov + 14] = bytes.fromhex("4883c428e9") + struct.pack("<i", wrapper - jump - 5)
        probe = self.dir / "tail-registration.exe"
        probe.write_bytes(tail)
        self.compile(probe)
        result = self.program()
        self.assertEqual((result.returncode, result.stdout, result.stderr), (91, b"", b""))
        tail[mov + 1] = 1
        probe.write_bytes(tail)
        rejected = self.compile(probe, success=False)
        self.assertEqual(rejected["context"]["instruction_rva"], hex(jump))
        self.assertEqual(rejected["context"]["branch_target"], wrapper)

        # Replace the full zero with a nonzero immediate or a partial zero write.
        for instruction in ("b901000000", "66b9000090"):
            with self.subTest(instruction=instruction):
                bad = self.dir / "unknown.exe"
                bad.write_bytes(data[:mov] + bytes.fromhex(instruction) + data[mov + 5:])
                diagnostic = self.compile(bad, success=False)
                self.assertEqual(diagnostic["code"], "LIFT_UNSUPPORTED_CONTROL_FLOW")
                ctx = diagnostic["context"]
                self.assertEqual((ctx["function_rva"], ctx["block_rva"], ctx["instruction_rva"]),
                                 (hex(helper), hex(helper), hex(call)))
                self.assertEqual((ctx["caller_rva"], ctx["call_site_rva"], ctx["branch_target"]),
                                 (hex(wrapper), hex(registration), wrapper))
                self.assertEqual((ctx["import_dll"], ctx["import_symbol"], ctx["iat_slot_rva"]),
                                 ("msvcrt.dll", "_onexit", hex(iat)))
                self.assertEqual(ctx["unresolved_calls"], [
                    dict(caller_rva=hex(helper), instruction_rva=hex(call), target_rva=hex(wrapper))])
                plain = run(FORGE, "lift", bad, "--executable", "--output", self.output)
                self.assertIn(f"function {hex(helper)} calls {hex(wrapper)}, "
                              f"import msvcrt.dll!_onexit at {hex(registration)}", plain.stderr)

    def test_finite_cleanup_depth(self):
        for count, code, message in (
                (16, 42, b""), (17, 125, b"forge: unsupported recursive MSVCRT cleanup or handler limit\n")):
            with self.subTest(count=count):
                self.compile(FIXTURES / f"crt-term-depth-{count}.exe")
                result = self.program()
                self.assertEqual((result.returncode, result.stdout, result.stderr), (code, b"B" * 16, message))

    def test_termination_rejects_image_base_callback(self):
        data = bytearray((FIXTURES / "crt-term-data.exe").read_bytes())
        root = entry(data)
        offset = Layout(data).file_offset(root)
        self.assertEqual(data[offset + 9:offset + 12], bytes.fromhex("488d05"))
        struct.pack_into("<i", data, offset + 12, -(root + 16))
        image_base_callback = self.dir / "image-base.exe"
        image_base_callback.write_bytes(data)
        diagnostic = self.compile(image_base_callback, success=False)
        self.assertEqual(diagnostic["code"], "LIFT_INVALID_CALL_TARGET")
        self.assertIn("PE header", diagnostic["message"])

    def test_termination_requires_crt_stream_support(self):
        diagnostic = self.compile(FIXTURES / "crt-term-stdio.exe", success=False)
        self.assertEqual(diagnostic["context"]["import_symbol"], "fopen")
        self.assertFalse(self.output.exists())

    def test_termination_rebased_dword(self):
        pe = FIXTURES / "crt-term-exit.exe"
        obj = self.dir / "termination.o"
        run(CONTRACT, "--guest-base", "0x180000000", pe, "--object", obj, OPT, LLC, check=True)
        _, runtime, sdk, *flags = LINK
        run("/usr/bin/xcrun", "--sdk", sdk, "clang++", "-arch", "arm64", *flags,
            PROCESS_HARNESS, obj, runtime, "-o", self.output, check=True)
        # The embedder borrows a regular output file. A captured pipe requires an
        # explicit host SIGPIPE policy and is already exercised by the standalone test.
        captured = self.dir / "stdout.bin"
        with captured.open("wb") as stream:
            result = subprocess.run([self.output, "run", "0", "0", "0", "0"], stdout=stream,
                                    stderr=subprocess.PIPE, timeout=10, check=True)
        self.assertEqual(result.stderr, b"")
        output = captured.read_bytes().decode()
        self.assertEqual(output.replace("BAA", "").splitlines()[-2:], [f"exit {0xcafe002a}"] * 2)
        self.assertEqual(output.count("BAA"), 2)

    def test_startup_info(self):
        for name, row in legacy_observations("windows", "executable-startup-info-", "clear").items():
            with self.subTest(pe=name):
                diagnostic = self.compile(FIXTURES / name)
                variants = name.removesuffix(".exe").split("-")[-1]
                imports = {item["name"] for item in diagnostic["context"]["imports"]}
                self.assertEqual({symbol for symbol in imports if symbol.startswith("GetStartupInfo")},
                                 {"GetStartupInfo" + v.upper() for v in ("aw" if variants == "fields" else variants)})
                result = self.program()
                self.assertEqual((result.returncode, result.stdout, result.stderr),
                                 (row["exit_code"], b"", b""))

        self.compile(image("startup-info-w-fault"))
        result = run(self.output)
        self.assertEqual((result.returncode, result.stdout, result.stderr),
                         (125, "", "forge: guest memory fault address=0x70000fd8 access=2 reason=4\n"))

    def test_startup_title_encoding_at_call(self):
        pe = self.dir / "café.exe"
        for variant in ("a", "w"):
            with self.subTest(variant=variant):
                shutil.copyfile(image("startup-title-" + variant), pe)
                self.compile(pe)
                called = self.program()
                self.assertEqual((called.returncode, called.stdout, called.stderr),
                                 (125, b"", b"forge: GetStartupInfoA/W requires an ASCII startup title\n"))
                skipped = self.program(preexec_fn=lambda: os.close(1))
                self.assertEqual((skipped.returncode, skipped.stdout, skipped.stderr), (41, b"", b""))

        shutil.copyfile(FIXTURES / "command-line.exe", pe)
        self.compile(pe)
        result = self.program()
        self.assertEqual((result.returncode, result.stdout, result.stderr),
                         (125, b"", b"forge: runtime failure stage=register status=1\n"))

    def test_top_level_filter_registration(self):
        pe = image("top-level-filter")
        self.compile(pe)
        result = run(self.output)
        self.assertEqual((result.returncode, result.stdout, result.stderr), (42, "", ""))

        data = pe.read_bytes()
        preferred, = struct.unpack_from("<Q", data, Layout(data).opt + 24)
        run(CONTRACT, "--guest-base", hex(preferred + 0x30000000), pe, self.output,
            OPT, LLC, "/usr/bin/xcrun", *LINK, check=True)
        rebased = run(self.output)
        self.assertEqual((rebased.returncode, rebased.stdout, rebased.stderr), (42, "", ""))

        # Each process leaves filter B installed after checking its predecessor.
        obj = self.dir / "filter.o"
        run(CONTRACT, pe, "--object", obj, OPT, LLC, check=True)
        _, runtime, sdk, *flags = LINK
        run("/usr/bin/xcrun", "--sdk", sdk, "clang++", "-arch", "arm64", *flags,
            PROCESS_HARNESS, obj, runtime, "-o", self.output, check=True)
        result = run(self.output, "run", "0", "0", "0", "0", check=True)
        self.assertEqual(result.stderr, "")
        self.assertEqual(result.stdout.splitlines()[-2:], ["return 42"] * 2)

    def test_installed_filter_preserves_terminal_fault(self):
        self.compile(image("top-level-filter-fault"))
        result = run(self.output)
        self.assertEqual((result.returncode, result.stdout, result.stderr),
                         (125, "", "forge: guest memory fault address=0x1 access=1 reason=2\n"))

    def test_import_register_loop_and_identity(self):
        pe = image("import-register")
        diagnostic = self.compile(pe)
        self.assertEqual({row["name"] for row in diagnostic["context"]["imports"]},
                         {"Sleep", "GetLastError", "SetLastError"})
        result = run(self.output)
        self.assertEqual((result.returncode, result.stdout, result.stderr), (42, "", ""))

        # Redirect only the scalar load into R10, preserving the expected Sleep
        # binding at CALL. An unchecked static dispatch would still return 42.
        layout = Layout(pe.read_bytes())
        base = struct.unpack_from("<Q", layout.data, layout.opt + 24)[0]
        directory, = diagnostic["context"]["load_imports"]
        slots = {row["name"]: base + int(row["iat_slot_rva"], 16) for row in directory["symbols"]}
        sleep = f"@forge_image_address(i64 {slots['Sleep']}, i64 8, i1 false,"
        setter = f"@forge_image_address(i64 {slots['SetLastError']}, i64 8, i1 false,"
        ir = run(CONTRACT, pe, check=True).stdout
        self.assertIn(sleep, ir)
        mutated = self.dir / "mismatch.ll"
        mutated.write_text(ir.replace(sleep, setter, 1))
        obj = self.dir / "mismatch.o"
        run(LLC, "-filetype=obj", mutated, "-o", obj, check=True)
        startup, runtime, sdk, *flags = LINK
        run("/usr/bin/xcrun", "--sdk", sdk, "clang++", "-arch", "arm64", *flags,
            obj, startup, runtime, "-o", self.output, check=True)
        fault = run(self.output)
        self.assertEqual((fault.returncode, fault.stdout, fault.stderr),
                         (125, "", "forge: guest control fault\n"))

    def test_guarded_call(self):
        pe = image("guarded-call")
        diagnostic = self.compile(pe)
        call, = diagnostic["context"]["calls"]
        data = pe.read_bytes()
        layout = Layout(data)
        call_offset = layout.file_offset(int(call["instruction_rva"], 16))
        self.assertEqual(data[call_offset:call_offset+2], bytes.fromhex("ff d0"))
        program = run(self.output)
        self.assertEqual((program.returncode, program.stdout, program.stderr), (42, "", ""))

        base = struct.unpack_from("<Q", data, layout.opt + 24)[0]
        run(CONTRACT, "--guest-base", hex(base + 0x30000000), pe, self.output,
            OPT, LLC, "/usr/bin/xcrun", *LINK, check=True)
        rebased = run(self.output)
        self.assertEqual((rebased.returncode, rebased.stdout, rebased.stderr), (42, "", ""))

    def test_crt_arguments_and_heap(self):
        self.compile(FIXTURES / "crt-argument-heap.exe")
        for args, expected in (([], 41), (["*example"], 42), (["another value"], ord("a"))):
            with self.subTest(args=args):
                result = run(self.output, *args)
                self.assertEqual((result.returncode, result.stdout, result.stderr), (expected, "", ""))

        pe = FIXTURES / "crt-argument-heap.exe"
        obj = self.dir / "crt.o"
        run(CONTRACT, pe, "--object", obj, OPT, LLC, check=True)
        _, runtime, sdk, *flags = LINK
        run("/usr/bin/xcrun", "--sdk", sdk, "clang++", "-arch", "arm64", *flags,
            PROCESS_HARNESS, obj, runtime, "-o", self.output, check=True)
        result = run(self.output, "run", "0", "0", "0", "0", check=True)
        self.assertEqual([row for row in result.stdout.splitlines() if row.startswith("return ")],
                         ["return 41", "return 41"])

    def test_linker_import_thunks(self):
        result = self.compile(image("import-thunk"))
        self.assertEqual({item["name"] for item in result["context"]["imports"]},
                         {"SetLastError", "GetLastError", "ExitProcess"})
        run_result = run(self.output)
        self.assertEqual((run_result.returncode, run_result.stdout, run_result.stderr), (42, "", ""))

    def test_primary_tib(self):
        self.compile(image("tib"))
        result = run(self.output)
        self.assertEqual((result.returncode, result.stdout, result.stderr), (42, "", ""))

    def test_process_command_line(self):
        pe = self.dir / "guest original.exe"
        shutil.copyfile(FIXTURES / "command-line.exe", pe)
        self.compile(pe)
        pe.unlink()
        for args in ([], [""], ["a b", "forge"], ['a"b', "space slash\\", 'x\\"y']):
            with self.subTest(args=args):
                expected = subprocess.list2cmdline([r"C:\guest original.exe", *args])
                checksum = 0
                for byte in expected.encode("ascii"):
                    checksum = (checksum * 33 + byte) & 255
                result = run(self.output, *args)
                self.assertEqual((result.returncode, result.stdout, result.stderr), (checksum, "", ""))

    def test_scalar_only_import_does_not_consume_arguments(self):
        data = bytearray((FIXTURES / "command-line.exe").read_bytes())
        start = Layout(data).file_offset(entry(data))
        self.assertTrue(data.startswith(bytes.fromhex("48 83 ec 28 ff 15"), start))
        # Use the same slot as the original CALL, adjusting for the longer MOV.
        # Return whether its guest function address is nonzero. No service runs.
        disp = struct.unpack_from("<i", data, start + 6)[0] - 1
        body = bytes.fromhex("48 8b 15") + struct.pack("<i", disp)
        body += bytes.fromhex("31 c0 48 85 d2 0f 95 c0 48 83 c4 28 c3")
        data[start + 4:start + 4 + len(body)] = body
        pe = self.dir / "identity.exe"
        pe.write_bytes(data)
        self.compile(pe)
        result = run(self.output, "café")
        self.assertEqual((result.returncode, result.stdout, result.stderr), (1, "", ""))

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
              "readiness": ("Readiness",), "native": ("Native", "Console"), "reference": ("Reference",),
              "windows-cmp16mi": ("WindowsComparison",), "windows-app-type": ("WindowsAppType",),
              "windows-bounded-call": ("WindowsBoundedCall",), "windows-tail-jump": ("WindowsTailJump",), "windows-startup": ("WindowsStartup",)}
    unittest.main(argv=[__file__, *suites[MODE]], verbosity=2)
