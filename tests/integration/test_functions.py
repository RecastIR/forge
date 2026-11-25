"""Exercise discovery and lift diagnostics through their CLI entry points."""
import json
import os
from pathlib import Path
import resource
import signal
import stat
import struct
import sys
import unicodedata
import unittest

from cli_case import Case, FIXTURES, SUITE
from pe_layout import Layout


class Discovery(Case):
    def analyze(self, image, *args, code=0):
        p = self.invoke("analyze", image, "--functions", "--format", "json", *args, code=code)
        return json.loads(p.stdout)

    def test_metadata_and_gaps(self):
        # Missing imports leave root-only analysis usable.
        image = self.copy("metadata.exe")
        r = self.analyze(image, "--strict")
        f, = r["functions"]
        self.assertTrue(f["contains_tls_callback"] and f["contains_entry_point"])
        self.assertEqual((f["size"], f["source"], f["status"]), (9, "exception_directory", "valid"))
        self.assertEqual(r["unknown_executable_ranges"], [])
        self.assertEqual(self.invoke("analyze", image, "--functions", "--strict").stdout,
                         b"Functions (1), source: PE exception directory\n"
                         b"  0x1000..0x1009 (9 bytes) unwind 0x210c valid records 0 entry TLS callback\n")
        r = self.analyze(FIXTURES / "minimal.exe", "--strict")
        self.assertEqual(r["functions"], [])
        self.assertEqual(r["unknown_executable_ranges"], [{"start_rva": "0x1000", "end_rva": "0x1001"}])
        self.assertNotIn("name", self.analyze(FIXTURES / "arithmetic.exe")["functions"][0])

    def test_dwarf_and_section_alignment(self):
        exe = FIXTURES / "add.exe"
        f, = self.analyze(exe)["functions"]
        self.assertEqual(f["name"], "entry")
        self.assertEqual(f["location"]["file"].split("/")[-1], "add.c")
        self.assertGreater(f["location"]["line"], 0)
        lines = self.invoke("inspect", exe).stdout.decode().splitlines()
        column, = [line.index("RVA") for line in lines if "Permissions" in line]
        rows = [line for line in lines if line.startswith("    .")]
        self.assertTrue(any(".debug_abbrev" in row for row in rows))
        self.assertTrue(all(row.index("0x") == column for row in rows))

    def test_enclosing_dwarf_function(self):
        f, = self.analyze(FIXTURES / "inlined.exe", "--strict")["functions"]
        self.assertEqual(f["name"], "entry")
        self.assertEqual(f["location"]["file"].split("/")[-1], "inlined.c")
        source = Path(__file__).resolve().parents[1] / "fixtures/inlined.c"
        call_line, = (i for i, line in enumerate(source.read_text().splitlines(), 1)
                      if "return step(a) + b;" in line)
        self.assertEqual(f["location"]["line"], call_line)

    def test_unicode_section_columns(self):
        image = FIXTURES / "unicode.exe"
        for flags in ((), ("--verbose",)):
            lines = self.invoke("inspect", image, *flags).stdout.decode().splitlines()
            column, = [line.index("RVA") for line in lines if "Permissions" in line]
            for section in (".donnée", ".界区"):
                row, = [line for line in lines if line.lstrip().startswith(section)]
                prefix = row[:row.index("0x")]
                self.assertEqual(sum(2 if unicodedata.east_asian_width(c) == "W" else 1
                                     for c in prefix), column)
        self.assertEqual(self.invoke("inspect", image, "--format", "json").stdout,
                         self.invoke("inspect", image, "--format", "json", "--verbose").stdout)

    def test_chained_fragment_and_gap(self):
        image = FIXTURES / "chained.exe"
        oracle = self.readobj("chained.exe", "--unwind")
        self.assertIn("ChainInfo (0x4)", oracle)
        self.assertIn("Chained {\n        StartAddress: (0x140001000)", oracle)
        a = self.analyze(image, "--strict")
        primary, fragment, unrelated = a["functions"]
        self.assertTrue(primary["liftable"] and unrelated["liftable"])
        self.assertEqual((fragment["start_rva"], fragment["chained_fragment"], fragment["status"],
                          fragment["liftable"]), ("0x1010", True, "valid", False))
        self.assertEqual(a["diagnostics"], [])
        self.assertEqual(a["unknown_executable_ranges"],
                         [{"start_rva": primary["end_rva"], "end_rva": fragment["start_rva"]}])
        self.assertIn(b"chained fragment", self.invoke("analyze", image, "--functions").stdout)
        output = self.dir / "function.ll"
        for signature in ((), ("--signature", "i64(i64,i64)")):
            p = self.invoke("lift", image, "--rva", fragment["start_rva"], "--output", output,
                            *signature, code=1)
            self.assertIn(b"0x1010: chained unwind fragment", p.stderr)
            self.assertFalse(output.exists())
        self.invoke("lift", image, "--rva", unrelated["start_rva"], "--output", output)

        data = bytearray(image.read_bytes())
        layout = Layout(data)
        table = layout.file_offset(layout.directory(3)[0])
        struct.pack_into("<I", data, table+12, int(primary["end_rva"], 16)-1)
        image = self.dir / "overlap.exe"
        image.write_bytes(data)
        rows = self.analyze(image, "--strict", code=3)["functions"]
        self.assertEqual([row["status"] for row in rows], ["conflicting", "conflicting", "valid"])
        self.assertTrue(rows[1]["chained_fragment"])

    def test_unwind_header_and_trailer(self):
        original = FIXTURES / "chained.exe"
        fragment = self.analyze(original)["functions"][1]
        data = bytearray(original.read_bytes())
        offset = Layout(data).file_offset(int(fragment["unwind_rva"], 16))
        image = self.dir / "unwind.exe"
        output = self.dir / "fragment.ll"
        for version_flags, slots, status, exit_code, reason in [
                (0x22, 0, "valid", 0, None),       # version 2 chained header
                (0x27, 0, "unsupported", 0, None),
                (0x21, 1, "invalid", 3, "truncated chained runtime function"),
                (0x29, 0, "invalid", 3, "also declares a handler")]:
            with self.subTest(version_flags=version_flags, slots=slots):
                data[offset] = version_flags
                data[offset+2] = slots
                image.write_bytes(data)
                a = self.analyze(image, "--strict", code=exit_code)
                row = a["functions"][1]
                self.assertEqual((row["status"], row["liftable"]), (status, False))
                if reason:
                    self.assertIn(reason, a["diagnostics"][0]["message"])
                if status == "unsupported":
                    self.assertEqual(row["unwind_version"], 7)
                    p = self.invoke("lift", image, "--rva", row["start_rva"], "--output", output, code=1)
                    self.assertIn(b"unsupported unwind version 7", p.stderr)
                self.invoke("inspect", image, "--strict")

    def test_truncated_unwind_handler_rva(self):
        original = (FIXTURES / "executable-return.exe").read_bytes()
        layout = Layout(original)
        record = layout.file_offset(layout.directory(3)[0])
        entry, _, unwind = struct.unpack_from("<III", original, record)
        header = layout.file_offset(unwind)
        section = layout.section_header(unwind)
        image = self.dir / "truncated-handler.exe"
        output = self.dir / "output"

        # One code slot ends at byte six. The handler RVA begins at byte eight.
        for flags, extent in ((1, 8), (2, 11)):
            with self.subTest(flags=flags, extent=extent):
                data = bytearray(original)
                data[header:header + 4] = bytes((1 | (flags << 3), 1, 1, 0))
                data[header + 4:header + 6] = bytes((1, 0x30))  # UWOP_PUSH_NONVOL RBX
                struct.pack_into("<I", data, section + 8, unwind - layout.u32(section + 12) + extent)
                image.write_bytes(data)

                result = self.analyze(image, "--strict", code=3)
                function, = result["functions"]
                self.assertEqual((function["status"], function["liftable"]), ("invalid", False))
                finding, = result["diagnostics"]
                self.assertEqual(finding["code"], "INVALID_FUNCTION_RECORD")
                self.assertIn("truncated unwind handler RVA", finding["message"])
                for selection in (("--rva", hex(entry)), ("--executable",)):
                    failure = self.invoke("lift", image, *selection, "--output", output,
                                          "--diagnostics-format", "json", code=1)
                    self.assertEqual(json.loads(failure.stderr)["code"], "ENTRY_INVALID_START")
                    self.assertFalse(output.exists())

    def test_recover_readable_conflicts(self):
        data = bytearray((FIXTURES / "arithmetic.exe").read_bytes())
        info = Layout(data)
        table, size = info.directory(3)
        offset = info.file_offset(table)
        first, second, third = [struct.unpack_from("<III", data, offset + 12*i) for i in range(3)]
        for kind, record in [
            ("partial", (first[1]-1, second[1], second[2])),
            ("nested", (first[0]+1, first[1], second[2])),
            ("equal_conflict", (*first[:2], second[2])),
            ("duplicate", first)]:
            with self.subTest(kind=kind):
                # Original indices deliberately differ from RVA order.
                struct.pack_into("<III", data, offset, *third)
                struct.pack_into("<III", data, offset+12, *record)
                struct.pack_into("<III", data, offset+24, *first)
                image = self.dir / "records.exe"
                image.write_bytes(data)
                code = 0 if kind == "duplicate" else 3
                a = self.analyze(image, "--strict", code=code)
                self.assertEqual(a, self.analyze(image))
                functions = a["functions"]
                self.assertEqual([int(f["start_rva"],16) for f in functions],
                                 sorted(int(f["start_rva"],16) for f in functions))
                if kind == "duplicate":
                    self.assertEqual(functions[0]["record_indices"], [1, 2])
                    self.assertTrue(functions[0]["liftable"])
                    self.assertFalse(a["diagnostics"])
                else:
                    self.assertEqual([f["status"] for f in functions[:2]], ["conflicting"]*2)
                    self.assertFalse(any(f["liftable"] for f in functions[:2]))
                    self.assertCountEqual(a["diagnostics"][0]["record_indices"], [1, 2])
                    self.assertEqual(a["diagnostics"][0]["code"], "FUNCTION_RANGE_OVERLAP")
                    args = ("lift", image, "--rva", hex(first[0]), "--output", self.dir/"bad.ll")
                    self.assertIn(b"expected an exact, valid, unambiguous", self.invoke(*args, code=1).stderr)
                    diagnostic = json.loads(self.invoke(*args, "--diagnostics-format", "json", code=1).stderr)
                    self.assertEqual(diagnostic["code"], "ENTRY_INVALID_START")
                    self.assertEqual(diagnostic["context"], dict(input=str(image), entry_rva=hex(first[0]), signature="register-state"))
                self.invoke("lift", image, "--rva", hex(third[0]), "--output", self.dir/"ok.ll")
                self.assertTrue(all(f["status"] == "valid" for f in functions if int(f["start_rva"],16) >= third[0]))

    def test_exact_range_diagnostics(self):
        original = (FIXTURES / "add.exe").read_bytes()
        layout = Layout(original)
        off = layout.file_offset(layout.directory(3)[0])
        start, end, unwind = struct.unpack_from("<III", original, off)
        image = self.dir / "entry.exe"
        output = self.dir / "entry.ll"
        for requested, stop, code in (
                (start + 1, end, "ENTRY_INVALID_START"),
                (start, start, "ENTRY_INVALID_START"),
                (start, end + 0x100, "ENTRY_UNMAPPED_CODE")):
            with self.subTest(requested=requested, end=stop):
                data = bytearray(original)
                struct.pack_into("<III", data, off, start, stop, unwind)
                image.write_bytes(data)
                args = ("lift", image, "--rva", hex(requested), "--output", output)
                reason = "expected an exact, valid, unambiguous discovered function start"
                self.assertEqual(self.invoke(*args, code=1).stderr,
                                 f"{image}: LIFT_ERROR: {requested:#x}: {reason}\n".encode())
                failure = json.loads(self.invoke(*args, "--diagnostics-format", "json", code=1).stderr)
                context = dict(input=str(image), entry_rva=hex(requested), signature="register-state")
                if code == "ENTRY_UNMAPPED_CODE":
                    context["end_rva"] = hex(stop)
                self.assertEqual((failure["category"], failure["code"], failure["context"]),
                                 ("invalid_input", code, context))
                self.assertFalse(output.exists())

    def test_empty_range_at_valid_start(self):
        data = bytearray((FIXTURES / "arithmetic.exe").read_bytes())
        info = Layout(data)
        off = info.file_offset(info.directory(3)[0])
        begin, end, unwind = struct.unpack_from("<III", data, off)
        struct.pack_into("<III", data, off+12, begin, begin, unwind)
        image = self.dir/"empty.exe"
        image.write_bytes(data)
        rows = self.analyze(image, "--strict", code=3)["functions"][:2]
        self.assertEqual([(f["status"], f["liftable"]) for f in rows],
                         [("invalid", False), ("valid", True)])
        self.invoke("lift", image, "--rva", hex(begin), "--output", self.dir/"ok.ll")

    def test_bad_dwarf_is_optional(self):
        image = FIXTURES/"add.exe"
        data = bytearray(image.read_bytes())
        debug = next(s for s in self.report(image)["modules"][0]["sections"] if s["name"] == ".debug_info")
        struct.pack_into("<I", data, debug["file_offset"], 0xfffffff1)
        image = self.dir/"bad-debug.exe"
        image.write_bytes(data)
        f, = self.analyze(image, "--strict")["functions"]
        self.assertTrue(f["liftable"])
        self.assertNotIn("name", f)

    def test_invalid_and_partial(self):
        original = (FIXTURES / "arithmetic.exe").read_bytes()
        info = Layout(original)
        table, size = info.directory(3)
        off = info.file_offset(table)
        for begin, end, unwind in [(0x1000, 0x1000, 0), (0x1008, 0x1000, 0),
                                   (0x2000, 0x2008, 0x2000), (0xfffffff0, 0xffffffff, 0),
                                   (0x1000, 0x1007, 0x7001), (0x1000, 0x1007, 0x8000)]:
            data = bytearray(original)
            struct.pack_into("<III", data, off, begin, end, unwind)
            image = self.dir/"invalid.exe"
            image.write_bytes(data)
            a = self.analyze(image, "--strict", code=3)
            f, = [f for f in a["functions"] if f["record_indices"] == [0]]
            self.assertEqual((f["status"], f["liftable"]), ("invalid", False))
            self.assertEqual(f["size"], end-begin if end >= begin else None)
            self.assertEqual(len(a["functions"]), size//12)
        data = bytearray(original)
        struct.pack_into("<I", data, info.directories + 3*8 + 4, size-1)
        image.write_bytes(data)
        a = self.analyze(image, "--strict", code=3)
        self.assertEqual(a["diagnostics"][0]["record_indices"], [size//12 - 1])
        self.assertEqual(len(a["functions"]), size//12-1)
        self.assertEqual(a["diagnostics"][0]["code"], "PARTIAL_RUNTIME_FUNCTION")
        self.invoke("inspect", image, code=1)
        struct.pack_into("<I", data, info.directories + 3*8, 0xfffffff0)
        image.write_bytes(data)
        self.assertEqual(self.invoke("analyze", image, "--functions", code=1).stdout, b"")


class Lift(Case):
    def test_guarded_readonly_callback(self):
        original = (FIXTURES / "executable-guarded-call.exe").read_bytes()
        layout = Layout(original)
        entry = layout.u32(layout.opt + 16)
        start = layout.file_offset(entry)
        call = original.index(bytes.fromhex("ff d0"), start)
        slot = entry + 11 + struct.unpack_from("<i", original, start + 7)[0]
        base = struct.unpack_from("<Q", original, layout.opt + 24)[0]
        cell = struct.unpack_from("<Q", original, layout.file_offset(slot))[0] - base
        target = struct.unpack_from("<Q", original, layout.file_offset(cell))[0] - base
        image, output = self.dir / "callback.exe", self.dir / "callback.ll"
        args = ("lift", image, "--rva", hex(entry), "--signature", "i64(i64,i64)", "--output", output)
        image.write_bytes(original)
        self.invoke(*args)
        self.assertIn(f"call void @forge_guest_{target:x}", output.read_text())

        # JE lands immediately after CALL. A backedge discovered after the call
        # must invalidate the chain even though the first traversal is sound.
        self.assertEqual(original[call+2:call+7], bytes.fromhex("48 83 c4 28 c3"))
        edits = [
            ("alternate predecessor", call + 2, bytes.fromhex("75 fc c3"), "bypasses"),
            ("argument clobbers eax", call - 2, bytes.fromhex("31 c0"), "register call"),
            ("setup writes ebx", call - 2, bytes.fromhex("31 db"), "register call"),
            ("null guard reversed", start + 17, b"\x75", "register call"),
            ("target outside image", layout.file_offset(cell), struct.pack("<Q", base-1), "outside the image"),
        ]
        flags = layout.section_header(slot) + 36
        edits.append(("writable cells", flags, struct.pack("<I", layout.u32(flags) | 0x80000000),
                      "stable read-only pointer"))
        reloc = layout.file_offset(layout.directory(5)[0])
        page, size = struct.unpack_from("<II", original, reloc)
        for location in (slot, cell):
            field = next(i for i in range(reloc + 8, reloc + size, 2)
                         if struct.unpack_from("<H", original, i)[0] == (0xa000 | (location - page)))
            edits.append((f"missing DIR64 at {location:x}", field, b"\0\0", "exact DIR64"))
        edits.append(("overlapping fixups", field, struct.pack("<H", 0xa000 | (slot - page)),
                      "overlapping base relocations"))
        for name, off, patch, detail in edits:
            with self.subTest(name=name):
                data = bytearray(original)
                data[off:off+len(patch)] = patch
                image.write_bytes(data)
                self.assertIn(detail.encode(), self.invoke(*args, code=1).stderr)

    def test_signatureless_state_alignment(self):
        output = self.dir / "state.ll"
        self.invoke("lift", FIXTURES / "arithmetic.exe", "--rva", "0x1000", "--output", output)
        module = output.read_text()
        self.assertIn('target triple = "arm64-apple-macosx11.0.0"', module)
        adapter = module.split("define internal void @forge_lifted_1000(", 1)[1].split("\n}", 1)[0]
        pointers = {"%state"}
        for line in adapter.splitlines():
            if "getelementptr" in line and ", ptr %state," in line:
                pointers.add(line.split(" = ", 1)[0].strip())
        for instruction in ("load i64", "store i64"):
            accesses = [line for line in adapter.splitlines()
                        if instruction in line and any(f", ptr {ptr}," in line for ptr in pointers)]
            self.assertEqual(len(accesses), 7, instruction)
            for line in accesses:
                self.assertIn(", align 4", line)

    def test_usage_and_invalid_rva(self):
        exe = FIXTURES / "arithmetic.exe"
        output = self.dir/"existing.ll"
        output.write_text("keep me")
        # The uncovered leaf is the last byte of .text.
        text = next(s for s in self.report(exe)["modules"][0]["sections"] if s["name"] == ".text")
        leaf = int(text["rva"], 16) + text["virtual_size"] - 1
        for rva in ("0x1001", hex(leaf), "0x2000", "0xffffffff"):
            p = self.invoke("lift", exe, "--rva", rva, "--output", output, code=1)
            self.assertIn(b"exact, valid", p.stderr)
        for args in [("--rva", "0x100000000"), ("--rva", "-1"), ("--rva", "0x12z"),
                     ("--signature", "i32()"), ("--rva", "0x"), ("--strict",)]:
            self.invoke("lift", exe, *args, "--output", output, code=2)
        self.invoke("analyze", exe, code=2)
        self.invoke("lift", FIXTURES/"Physics.DLL", "--rva", "0x1000", "--output", output, code=1)
        fifo = self.dir/"pipe"
        os.mkfifo(fifo)
        self.invoke("lift", fifo, "--rva", "0", "--output", output, code=1)
        self.assertEqual(output.read_text(), "keep me")

    def test_json_diagnostics(self):
        good = FIXTURES / "add.exe"
        corrupt = self.dir / "malformed.exe"
        corrupt.write_bytes(b"not a PE")
        missing = self.dir / "missing.exe"
        output = self.dir / "result.ll"
        invalid_output = self.dir / "absent" / "result.ll"
        unsupported = self.copy("arithmetic.exe", 'encoded "name".exe')
        data = bytearray(unsupported.read_bytes())
        offset = Layout(data).file_offset(0x1000)
        # The first MOV is accepted. Memory-source PUSH at the next instruction is unsupported.
        data[offset:offset + 7] = bytes.fromhex("48 89 c8 ff 31 c3 cc")
        unsupported.write_bytes(data)

        for image, dest, start, expected in (
            (corrupt, output, "0x1000", ("pe", "invalid_input", "INVALID_PE")),
            (missing, output, "0x1000", ("input", "io", "INPUT_OPEN")),
            (FIXTURES / "i386.exe", output, "0x1000", ("pe", "unsupported", "UNSUPPORTED_ARCHITECTURE")),
            (good, output, "0x1001", ("entry", "invalid_input", "ENTRY_INVALID_START")),
            (unsupported, output, "0x1000", ("lifting", "unsupported", "LIFT_UNSUPPORTED_INSTRUCTION")),
            (good, invalid_output, "0x1000", ("publication", "io", "OUTPUT_CREATE")),
        ):
            with self.subTest(code=expected[-1]):
                args = ("lift", image, "--rva", start, "--output", dest)
                result = self.invoke(*args, "--diagnostics-format", "json", code=1)
                self.assertEqual(result.stdout, b"")
                self.assertTrue(result.stderr.endswith(b"\n"))
                self.assertEqual(result.stderr.count(b"\n"), 1)
                doc = json.loads(result.stderr.decode("utf-8"))
                self.assertEqual(set(doc), {"schema_version", "stage", "category", "code", "message", "context"})
                self.assertIs(type(doc["schema_version"]), int)
                self.assertEqual(doc["schema_version"], 1)
                self.assertTrue(doc["message"])
                self.assertEqual((doc["stage"], doc["category"], doc["code"]), expected)
                context = doc["context"]
                self.assertEqual((context["input"], context["entry_rva"]), (str(image), start))
                if image == unsupported:
                    self.assertEqual((context["instruction_rva"], context["end_rva"], context["bytes"]),
                                     ("0x1003", "0x1007", "ff31"))
                    self.assertIn("PUSH", context["opcode"])
                if image.name == "i386.exe":
                    self.assertEqual(context["architecture"], "i386")
                if expected[0] == "publication":
                    self.assertEqual(context["output"], str(dest))
                self.assertEqual(self.invoke(*args, code=1).stderr,
                                 self.invoke(*args, "--diagnostics-format", "text", code=1).stderr)
                self.assertFalse(dest.exists())

        result = self.invoke("lift", good, "--rva", "0x1000", "--output", output,
                             "--diagnostics-format", "json")
        self.assertEqual((result.stdout, result.stderr), (b"", b""))
        self.assertIn("forge_lifted_1000", output.read_text())

    def test_json_usage_and_output_aliases(self):
        image = self.copy("add.exe")
        before = image.read_bytes()
        hard = self.dir / "hard"
        os.link(image, hard)
        sym = self.dir / "sym"
        sym.symlink_to(image)
        for alias in (image, hard, sym):
            args = ("lift", image, "--rva", "0x1001", "--output", alias)
            default = self.invoke(*args, code=2)
            requested = self.invoke(*args, "--diagnostics-format", "json", code=2)
            self.assertEqual(requested.stderr, default.stderr)
            self.assertTrue(requested.stderr.startswith(b"forge: --output must differ"))
            self.assertEqual(alias.read_bytes(), before)
        for args in (("lift", "--diagnostics-format", "JSON"),
                     ("lift", "--diagnostics-format", "json", "--rva", "bad"),
                     ("lift", "--diagnostics-format"),
                     ("inspect", image, "--diagnostics-format", "json"),
                     ("analyze", image, "--functions", "--diagnostics-format", "json")):
            result = self.invoke(*args, code=2)
            self.assertEqual(result.stdout, b"")
            self.assertTrue(result.stderr.startswith(b"forge: "))
            self.assertIn(b"Usage: forge", result.stderr)

    def test_reject_unsupported_and_unproven(self):
        original = (FIXTURES / "arithmetic.exe").read_bytes()
        info = Layout(original)
        offset = info.file_offset(0x1000)
        output = self.dir/"existing.ll"
        output.write_text("sentinel")
        for code, expected in [
                ("88 c8 c3", "undefined RAX"), ("66 89 c8 c3", "undefined RAX"),
                ("48 03 01 c3", "undefined incoming RAX"),  # ADD64rm consumes its old destination.
                ("48 13 01 c3", "operand form"), ("f0 48 01 11 c3", "prefix"),
                ("48 8b 45 00 c3", "undefined incoming RBP"),
                ("f3 c3", "prefix"), ("48 48 89 c8 c3", "prefix"),
                ("ff d0 c3", "unsupported"), ("ff e0", "unsupported"),
                ("b8 01 00 00 00 31 c0", "outside"), ("eb 05", "outside"), ("74 01 48 89 c8 c3", "enters an instruction"),
                ("75 02 31 c0 c3", "flags"), ("e8 00 00 00 00", "unsupported"),
                ("4c 89 c0 c3", "undefined incoming R8"), ("c3", "undefined RAX"),
                ("48 29 c8 c3", "undefined incoming RAX"), ("44 29 c1 c3", "undefined incoming R8"),
                ("48 39 d1 74 01 c3 c3", "undefined RAX"),
                ("09 c0 c3", "undefined incoming RAX"), ("f7 f1 c3", "unsupported"),
                ("48 19 c0 c3", "condition flags: CF"), ("39 c0 18 c0 c3", "undefined RAX"),
                ("39 c0 c3", "undefined RAX"), ("38 e0 c3", "undefined incoming RAX"),
                ("39 c0 18 e0 c3", "undefined incoming RAX"),
                ("31 c0 9f c3", "AF"), ("0f af ca 0f 94 c0 c3", "ZF"),
                ("66 66 89 c8 c3", "prefix"), ("14 00 c3", "undefined incoming RAX"),
                ("39 d1 0f 94 c0 c3", "undefined RAX"), ("c0 e9 08 0f 92 c0", "CF"),
                ("83 d1 00 c3", "CF"), ("d2 e1 0f 90 c0 c3", "OF"), ("48 89 c8 48 89 c8 40", "invalid or truncated"),
                ("31 c0 31 c0 31 c0 90", "fallthrough outside function")]:
            with self.subTest(code=code):
                body = bytes.fromhex(code)
                self.assertLessEqual(len(body), 7)
                data = bytearray(original)
                data[offset:offset+7] = body.ljust(7, b"\xcc")
                image = self.dir/"changed.exe"
                image.write_bytes(data)
                p = self.invoke("lift", image, "--rva", "0x1000", "--signature", "i64(i64,i64)",
                                "--output", output, code=1)
                self.assertIn(expected.encode(), p.stderr)
                self.assertIn(b"LIFT_ERROR: 0x100", p.stderr)
                self.assertEqual(output.read_text(), "sentinel")
        self.assertFalse(list(self.dir.glob("*.tmp-*")))

    def test_cyclic_state_and_reachability(self):
        original = (FIXTURES / "cfg.exe").read_bytes()
        layout = Layout(original)
        record = layout.file_offset(layout.directory(3)[0])
        entry = 0x1000
        image, output = self.dir / "graph.exe", self.dir / "graph.ll"

        def lift(code, failure=None, reason=None, category="unsupported"):
            body = bytes.fromhex(code)
            data = bytearray(original)
            pos = layout.file_offset(entry)
            data[pos:pos + len(body)] = body
            struct.pack_into("<I", data, record + 4, entry + len(body))
            image.write_bytes(data)
            args = ("lift", image, "--rva", hex(entry), "--signature", "i64(i64,i64)",
                    "--diagnostics-format", "json", "--output", output)
            if failure:
                output.write_text("previous IR")
            result = self.invoke(*args, code=1 if failure else 0)
            if failure:
                diagnostic = json.loads(result.stderr)
                self.assertEqual((diagnostic["stage"], diagnostic["category"], diagnostic["code"]),
                                 ("lifting", category, failure))
                if reason:
                    self.assertTrue(diagnostic["message"].endswith(reason), diagnostic)
                context = diagnostic["context"]
                self.assertEqual((context["signature"], context["entry_rva"], context["input"]),
                                 ("i64(i64,i64)", hex(entry), str(image)))
                self.assertLessEqual(int(context["block_rva"], 16), int(context["instruction_rva"], 16))
                self.assertEqual(output.read_text(), "previous IR")
                return context
            return output.read_text()

        # A skipped prefix does not impose another instruction interpretation.
        for code in ("eb 01 48 89 c8 c3", "89 c8 c3 0f", "eb fe", "e9 fb ff ff ff",
                     "ff c9 0f 85 f8 ff ff ff 89 c8 c3", "ff c9 75 fc 89 c8 c3",
                     "39 d1 74 00 0f 94 c0 0f b6 c0 c3"):
            with self.subTest(code=code):
                lift(code)

        lift("68 ff ff", "LIFT_INVALID_ENCODING", category="invalid_input")
        lift("66 81 38 4d", "LIFT_INVALID_ENCODING", category="invalid_input")

        # The RIZ spelling in a SIB with a redundant scale has no index.
        lift("48 89 4c 64 08 48 8b 44 64 08 c3")
        lift("48 89 e0 c3")
        # Both the address and the eight bytes starting at the next RIP are in .text.
        lift("48 8d 05 00 00 00 00 c3")
        lift("48 8b 05 00 00 00 00 c3")
        for code, failure in (
                ("66 50 c3", "LIFT_UNSUPPORTED_PREFIX"),
                ("66 c9 c3", "LIFT_UNSUPPORTED_PREFIX"),
                ("66 83 38 ff c3", "LIFT_UNSUPPORTED_PREFIX"),  # CMP16mi8 sign-extends imm8.
                ("66 66 81 38 4d 5a c3", "LIFT_UNSUPPORTED_PREFIX"),
                ("67 66 81 38 4d 5a c3", "LIFT_UNSUPPORTED_PREFIX"),
                ("f2 48 ab c3", "LIFT_UNSUPPORTED_PREFIX"),
                ("67 f3 48 ab c3", "LIFT_UNSUPPORTED_PREFIX"),
                ("f3 ab c3", "LIFT_UNSUPPORTED_PREFIX"),
                ("8f 01 c3", "LIFT_UNSUPPORTED_INSTRUCTION"),
                ("c2 08 00", "LIFT_UNSUPPORTED_CONTROL_FLOW"),
                ("cb", "LIFT_UNSUPPORTED_CONTROL_FLOW"),
                ("67 48 8b 01 c3", "LIFT_UNSUPPORTED_PREFIX"),
                ("65 48 8b 01 c3", "LIFT_UNSUPPORTED_PREFIX"),
                ("48 8b 04 25 08 00 00 00 c3", "LIFT_UNSUPPORTED_INSTRUCTION"),
                ("48 a1 00 00 00 70 00 00 00 00 c3", "LIFT_UNSUPPORTED_INSTRUCTION"),
                ("48 8b 04 9c c3", "LIFT_UNDEFINED_REGISTER"),
                ("b7 ff 48 8b 03 c3", "LIFT_UNDEFINED_REGISTER"),
                ("41 b2 01 4c 89 d0 c3", "LIFT_UNDEFINED_REGISTER")):  # R10B alone cannot define R10
            with self.subTest(code=code):
                lift(code, failure)

        # LEA defines R8. MOVSX defines AX and MOVZX supplies the full RAX for ADC.
        lift("39 d1 4c 8d 04 11 eb 00 66 0f be c2 eb 00 0f b7 c0 4c 11 c0 c3")
        # INC, DEC and NOT preserve CMP's CF through CMOV and into the next block.
        lift("89 c8 39 d1 ff c0 ff ca f7 d2 0f 42 c2 eb 00 48 11 d0 c3")

        register, flag = "LIFT_UNDEFINED_REGISTER", "LIFT_UNDEFINED_FLAG"
        for code, diagnostic, reason, block, instruction, opcode, encoded in (
                # First arrival cannot borrow RAX or CF from a later iteration.
                ("48 01 c8 48 89 d0 eb f8", register, "incoming RAX", 0, 0, "ADD64rr", "4801c8"),
                ("11 d1 eb fc", flag, "flags: CF", 0, 0, "ADC32rr", "11d1"),
                # Carry invalidated only on the backedge.
                ("39 d1 72 05 c0 e1 08 eb f9 89 c8 c3", flag, "flags: CF", 2, 2, "JCC_1", "7205"),
                # Exactly one incoming path defines all of R8. The join reads it after a MOV.
                ("39 d1 74 03 49 89 c8 89 d0 4c 01 c0 c3", register, "incoming R8", 7, 9, "ADD64rr", "4c01c0"),
                # One arm writes AH and the other AL. Neither defines all of AX.
                ("39 d1 74 04 88 cc eb 02 88 c8 0f b7 c0 c3", register, "incoming RAX", 10, 10, "MOVZX32rr16", "0fb7c0"),
                # TEST leaves AF undefined. Only the CMP path supplies it to LAHF.
                ("85 d1 74 02 39 d1 9f c3", flag, "flags: AF", 6, 6, "LAHF", "9f"),
                # Self-CMP can set flags on undefined scratch without defining that register.
                ("45 39 c0 eb 00 4c 89 c0 c3", register, "incoming R8", 5, 5, "MOV64rr", "4c89c0"),
                # Even with a known-true condition, CMOV reads its old destination.
                ("39 c9 eb 00 0f 44 c2 c3", register, "incoming RAX", 4, 4, "CMOV32rr", "0f44c2"),
                # A possible zero count requires a prior ZF. Large logical byte shifts lose CF.
                ("48 d3 fa eb 00 0f 94 c0 c3", flag, "flags: ZF", 5, 5, "SETCCr", "0f94c0"),
                ("39 d1 d2 ea eb 00 0f 92 c0 c3", flag, "flags: CF", 6, 6, "SETCCr", "0f92c0"),
                ("39 d1 48 d3 fa eb 00 0f 90 c0 c3", flag, "flags: OF", 7, 7, "SETCCr", "0f90c0")):
            with self.subTest(code=code):
                context = lift(code, diagnostic, reason)
                self.assertEqual((context["block_rva"], context["instruction_rva"], context["opcode"], context["bytes"]),
                                 (hex(entry + block), hex(entry + instruction), opcode, encoded))

        # Discover a target inside an instruction before and after the containing decode.
        for code, origin, target in (
                ("39 d1 74 01 48 89 c8 c3", 2, 5),
                ("48 89 c8 eb fc", 3, 1),
                ("39 d1 74 05 eb 04 0f 0f 0f 48 89 c8 c3", 4, 10),
                ("e9 00 00 00 80", 0, 5 - (1 << 31)),
                ("eb 00", 0, 2)):
            with self.subTest(code=code):
                context = lift(code, "LIFT_UNSUPPORTED_CONTROL_FLOW")
                self.assertEqual((context["instruction_rva"], context["branch_target"]),
                                 (hex(entry + origin), entry + target))
        self.assertEqual(lift("eb 01 cc 0f", "LIFT_INVALID_ENCODING", category="invalid_input")["bytes"], "0f")
        self.assertEqual(lift("ff e0", "LIFT_UNSUPPORTED_CONTROL_FLOW")["bytes"], "ffe0")

    def test_call_targets_and_callee_locations(self):
        original = (FIXTURES / "cfg.exe").read_bytes()
        layout = Layout(original)
        records = layout.file_offset(layout.directory(3)[0])
        helper, helper_end, unwind = struct.unpack_from("<III", original, records)
        caller, caller_end, _ = struct.unpack_from("<III", original, records + 24)
        image, output = self.dir / "calls.exe", self.dir / "calls.ll"

        def write_body(data, rva, body):
            pos = layout.file_offset(rva)
            data[pos:pos + len(body)] = body

        def call(at, target):
            return b"\xe8" + struct.pack("<i", target - (at + 5))

        def diagnose(data):
            image.write_bytes(data)
            output.write_text("previous IR")
            p = self.invoke("lift", image, "--rva", hex(caller), "--signature", "i64(i64,i64)",
                            "--output", output, "--diagnostics-format", "json", code=1)
            self.assertEqual(output.read_text(), "previous IR")
            return json.loads(p.stderr)

        # The two function bodies are deliberately in reverse RVA order.
        def recursive_body(rva, target):
            prefix = bytes.fromhex("85 c9 74 10 48 83 ec 28 ff c9")
            return prefix + call(rva + len(prefix), target) + bytes.fromhex("48 83 c4 28 c3 89 c8 c3")

        cycle = bytearray(original)
        write_body(cycle, caller, recursive_body(caller, helper))
        write_body(cycle, helper, recursive_body(helper, caller))
        image.write_bytes(cycle)
        args = ("lift", image, "--rva", hex(caller), "--signature", "i64(i64,i64)", "--output", output)
        self.invoke(*args)
        first = output.read_bytes()
        self.invoke(*args)
        self.assertEqual(output.read_bytes(), first)
        for start in (caller, helper):
            self.assertEqual(first.count(f"\nrva_{start:x}:".encode()), 1)

        for target, code in ((caller + 1, "LIFT_INVALID_CALL_TARGET"),
                             (helper + 1, "LIFT_UNSUPPORTED_CONTROL_FLOW"),
                             (-100, "LIFT_INVALID_CALL_TARGET"),
                             (0x70000000, "LIFT_INVALID_CALL_TARGET")):
            with self.subTest(target=target):
                data = bytearray(original)
                write_body(data, caller, call(caller, target) + b"\xc3")
                diagnostic = diagnose(data)
                context = diagnostic["context"]
                self.assertEqual((diagnostic["code"], context["branch_target"]), (code, target))
                if target == caller + 1:
                    self.assertIn(f"enters decoded instruction at {caller:#x}", diagnostic["message"])
                self.assertEqual((context["block_rva"], context["instruction_rva"],
                                  context["opcode"], context["bytes"]),
                                 (hex(caller), hex(caller), "CALL64pcrel32", call(caller, target).hex()))

        # The peer calls into a reachable helper. Classify using the full set
        # of decoded instructions for either ordering of their metadata RVAs.
        peer = layout.u32(records + 12)
        for leaf, source in ((helper, peer), (peer, helper)):
            for delta, code in ((1, "LIFT_INVALID_CALL_TARGET"), (3, "LIFT_UNSUPPORTED_CONTROL_FLOW")):
                with self.subTest(leaf=leaf, delta=delta):
                    data = bytearray(original)
                    write_body(data, caller, call(caller, leaf) + call(caller + 5, source) + b"\xc3")
                    write_body(data, leaf, bytes.fromhex("48 89 c8 c3"))
                    target = leaf + delta
                    branch = call(source, target)
                    write_body(data, source, branch + b"\xc3")
                    diagnostic = diagnose(data)
                    context = diagnostic["context"]
                    self.assertEqual(diagnostic["code"], code)
                    self.assertEqual((context["function_rva"], context["block_rva"], context["instruction_rva"],
                                      context["file_offset"], context["bytes"], context["branch_target"]),
                                     (hex(source), hex(source), hex(source), layout.file_offset(source),
                                      branch.hex(), target))

        # Jumping to the same proven function entry remains an unsupported tail jump.
        data = bytearray(original)
        write_body(data, caller, b"\xe9" + struct.pack("<i", helper - (caller + 5)))
        jump = diagnose(data)
        self.assertEqual((jump["code"], jump["context"]["branch_target"], jump["context"]["opcode"]),
                         ("LIFT_UNSUPPORTED_CONTROL_FLOW", helper, "JMP_4"))
        write_body(data, caller, bytes.fromhex("ff d1"))
        indirect = diagnose(data)
        self.assertEqual((indirect["code"], indirect["context"]["opcode"]),
                         ("LIFT_UNSUPPORTED_CONTROL_FLOW", "CALL64r"))

        # A last-in-range CALL may target a valid helper but lacks a continuation.
        data = bytearray(original)
        struct.pack_into("<I", data, records + 24 + 4, caller + 5)
        write_body(data, helper, bytes.fromhex("89 c8 c3"))
        write_body(data, caller, call(caller, helper))
        end = diagnose(data)
        self.assertEqual((end["code"], end["context"]["opcode"], end["context"]["branch_target"]),
                         ("LIFT_UNSUPPORTED_CONTROL_FLOW", "CALL64pcrel32", caller + 5))

        # Overlapping records describe no unique callee even when an exact start exists.
        data = bytearray(cycle)
        struct.pack_into("<III", data, records + 12, helper + 1, helper_end, unwind)
        invalid = diagnose(data)
        self.assertEqual((invalid["code"], invalid["context"]["branch_target"]),
                         ("LIFT_INVALID_CALL_TARGET", helper))

        # Removing the helper's metadata leaves executable bytes with no proven boundary.
        data = bytearray(cycle)
        data[records:records + 12] = data[records + 12:records + 24]
        missing = diagnose(data)
        self.assertEqual((missing["code"], missing["context"]["branch_target"]),
                         ("LIFT_UNSUPPORTED_CONTROL_FLOW", helper))

        # Reachable, unsupported callee instruction with an RVA below the external entry.
        data = bytearray(cycle)
        write_body(data, helper, bytes.fromhex("f7 f1 c3"))
        failure = diagnose(data)
        context = failure["context"]
        self.assertEqual(failure["code"], "LIFT_UNSUPPORTED_INSTRUCTION")
        self.assertEqual((context["entry_rva"], context["end_rva"], context["function_rva"]),
                         (hex(caller), hex(caller_end), hex(helper)))
        self.assertEqual((context["block_rva"], context["instruction_rva"], context["file_offset"],
                          context["bytes"]), (hex(helper), hex(helper), layout.file_offset(helper), "f7f1"))

    def test_inferred_leaf_boundaries_and_effects(self):
        original = (FIXTURES / "leaves.exe").read_bytes()
        module = self.report(FIXTURES / "leaves.exe")["modules"][0]
        caller, = [int(e["rva"], 16) for e in module["exports"] if "call_leaves" in e["names"]]
        section, = [s for s in module["sections"] if s["name"] == ".probe"]
        start = int(section["rva"], 16)
        end = start + section["virtual_size"]
        layout = Layout(original)
        image, ir = self.dir / "candidate.exe", self.dir / "candidate.ll"
        before = self.invoke("analyze", FIXTURES / "leaves.exe", "--functions", "--format", "json").stdout

        def lift(targets, fragments, reason="", code="LIFT_UNSUPPORTED_CONTROL_FLOW", fence=None,
                 bad_unwind=False, edit=None):
            data = bytearray(original)
            # Establish a concrete incoming RAX for leaves that preserve it.
            body = bytearray.fromhex("48 83 ec 28 89 c8")
            for target in targets:
                body.extend(b"\xe8" + struct.pack("<i", target - (caller + len(body) + 5)))
            body.extend(bytes.fromhex("48 83 c4 28 c3"))
            for rva, payload in [(caller, body), *fragments]:
                off = layout.file_offset(rva)
                data[off:off + len(payload)] = payload
            if fence is not None:
                table = layout.file_offset(layout.directory(3)[0])
                struct.pack_into("<I", data, table + 12, fence)
                if bad_unwind:
                    struct.pack_into("<I", data, table + 20, 0)
            if edit:
                edit(data)
            image.write_bytes(data)
            ir.write_text("previous IR")
            result = self.invoke("lift", image, "--rva", hex(caller), "--signature", "i64(i64,i64)",
                                 "--output", ir, "--diagnostics-format", "json", code=int(bool(reason)))
            if reason:
                error = json.loads(result.stderr)
                self.assertEqual(error["code"], code, error)
                self.assertIn(reason, error["message"])
                self.assertEqual(ir.read_text(), "previous IR")
                return error["context"]
            return ir.read_text()

        for encoding, reason in (("50 58 c3", "modifies RSP"), ("58 c3", "modifies RSP"),
                ("48 29 cc c3", "modifies RSP"), ("40 b4 00 c3", "modifies RSP"),
                ("b7 00 c3", "modifies RBX"), ("44 0f 44 e0 c3", "modifies R12"),
                ("e8 00 00 00 00 c3", "nested call"), ("ff d0", "indirect or far call"),
                ("ff e0", "unsupported control transfer"), ("eb fe", "no reachable normal return"),
                ("eb fd", hex(start - 1))):
            with self.subTest(encoding=encoding):
                context = lift([start], [(start, bytes.fromhex(encoding))], reason)
                if encoding == "eb fd":
                    self.assertEqual((context["instruction_rva"], context["branch_target"], context["call_site_rva"]),
                                     (hex(start), start - 1, hex(caller + 6)))
                else:
                    self.assertEqual((context["instruction_rva"], context["branch_target"]),
                                     (hex(caller + 6), start))

        for encoding in ("0f 57 f6 c3", "0f ae 11 c3", "f7 f1 c3"):
            with self.subTest(encoding=encoding):
                context = lift([start], [(start, bytes.fromhex(encoding))], "unsupported",
                               "LIFT_UNSUPPORTED_INSTRUCTION")
                self.assertEqual((context["function_rva"], context["instruction_rva"], context["caller_rva"],
                                  context["call_site_rva"]), (hex(start), hex(start), hex(caller), hex(caller+6)))

        lift([end - 1], [], "truncated", "LIFT_INVALID_ENCODING")
        lift([end], [], "outside", "LIFT_INVALID_CALL_TARGET")
        lift([layout.directory(3)[0]], [], "outside", "LIFT_INVALID_CALL_TARGET")
        lift([start], [(start, bytes.fromhex("eb 3e"))], hex(start + 64), fence=start + 64)
        lift([start + 65], [(start + 65, b"\xc3")], "conflicts with a recorded", fence=start + 64,
             bad_unwind=True)
        lift([start + 62], [(start + 62, bytes.fromhex("89 c8"))], "fallthrough", fence=start + 64)
        fixup, = [int(r["rva"], 16) for block in module["relocations"] for r in block["entries"]
                  if r["type"] == 10 and start <= int(r["rva"], 16) < end]
        lift([fixup], [(fixup, b"\xc3")], "relocation")
        lift([fixup - 2], [(fixup - 2, bytes.fromhex("eb 08")), (fixup + 8, b"\xc3")])
        def tls_index(data):
            tls = start + 256
            struct.pack_into("<II", data, layout.directories + 8 * 9, tls, 40)
            struct.pack_into("<QQQQII", data, layout.file_offset(tls),
                             0, 0, int(module["image_base_va"], 16) + start + 4, 0, 0, 0)

        literal = (start + 3, bytes.fromhex("b8 78 56 34 12 c3"))
        lift([start + 3], [literal], "loader-written", edit=tls_index)
        lift([start], [(start, b"\xeb\x06"), literal], edit=tls_index)

        def partial_record(data):
            table = layout.directory(3)[0]
            struct.pack_into("<II", data, layout.directories + 3 * 8, table, 20)
            struct.pack_into("<II", data, layout.file_offset(table) + 12, start, start + 3)

        ctx = lift([start], [(start, b"\x89\xc8\xc3")], "partial runtime function", edit=partial_record)
        self.assertEqual((ctx["instruction_rva"], ctx["branch_target"]), (hex(caller + 6), start))
        analysis = self.invoke("analyze", image, "--functions", "--format", "json")
        self.assertIn("PARTIAL_RUNTIME_FUNCTION", [d["code"] for d in json.loads(analysis.stdout)["diagnostics"]])
        table, table_size = layout.directory(3)
        table_offset = layout.file_offset(table)
        recorded_callee = layout.u32(table_offset + 12)

        def partial_after_complete_records(data):
            relocated_table = start + 256
            offset = layout.file_offset(relocated_table)
            data[offset:offset + table_size] = original[table_offset:table_offset + table_size]
            struct.pack_into("<II", data, offset + table_size, start, start + 3)
            struct.pack_into("<II", data, layout.directories + 3 * 8, relocated_table, table_size + 8)

        lift([recorded_callee], [], edit=partial_after_complete_records)

        for offset, payload, reason, code, claimed in (
                (62, "06 cc", "invalid", "LIFT_INVALID_ENCODING", "06cc"),
                (62, "b8 01 02 03 04", "decode boundary", "LIFT_UNSUPPORTED_CONTROL_FLOW", "b801"),
                (63, "48 89 c8", "decode boundary", "LIFT_UNSUPPORTED_CONTROL_FLOW", "48")):
            address = start + offset
            ctx = lift([address], [(address, bytes.fromhex(payload))], reason, code, fence=start + 64)
            self.assertEqual((ctx["function_rva"], ctx["instruction_rva"], ctx["bytes"], ctx["file_offset"],
                              ctx["caller_rva"], ctx["call_site_rva"]),
                             (hex(address), hex(address), claimed, layout.file_offset(address),
                              hex(caller), hex(caller + 6)))
        # An independently called leaf in the skipped bytes owns its own instructions.
        sparse = [(start, bytes.fromhex("eb 06 cc cc 89 c8 c3 cc c3"))]
        ir_text = lift([start, start+4, start], sparse)
        self.assertEqual(ir_text.count(f"define internal void @forge_guest_{start:x}("), 1)
        self.assertEqual(ir_text, lift([start, start+4, start], sparse))
        self.assertEqual(self.invoke("analyze", image, "--functions", "--format", "json").stdout, before)
        self.assertIn("ENTRY_INVALID_START", self.invoke("lift", image, "--rva", hex(start), "--output", ir,
                      "--diagnostics-format", "json", code=1).stderr.decode())

        context = lift([start, start+4], [(start, bytes.fromhex("eb 06 cc cc 89 c8 c3 cc 44 89 d0 c3"))],
                       "R10", "LIFT_UNDEFINED_REGISTER")
        self.assertEqual((context["function_rva"], context["instruction_rva"], context["call_site_rva"]),
                         (hex(start), hex(start + 8), hex(caller + 6)))

        lift([start], [(start, bytes.fromhex("85 c9 74 01 48 89 c8 c3"))], "branch enters an instruction",
             "LIFT_INVALID_CALL_TARGET")
        for order in ((start, start+1), (start+1, start)):
            context = lift(order, [(start, bytes.fromhex("48 89 c8 c3"))], "enters decoded instruction",
                           "LIFT_INVALID_CALL_TARGET")
            self.assertEqual(context["branch_target"], start+1)
        for order in ((start, start+4), (start+4, start)):
            lift(order, [(start, bytes.fromhex("eb 06 cc cc eb 02 cc cc c3"))], "overlaps decoded function")

        # A closed cycle may coexist with a returning path, including a backedge to entry.
        lift([start], [(start, bytes.fromhex("85 c9 74 02 eb fa c3"))])
        lift([start], [(start, bytes.fromhex("48 8b 44 24 08 c3"))])
        nop = bytes.fromhex("0f 1f 00")
        lift([start], [(start, nop*4095 + b"\xc3")])
        lift([start], [(start, nop*4096 + b"\xc3")], "instruction budget")
        for distance in (65535, 65536):
            jump = b"\xe9" + struct.pack("<i", distance - 5)
            lift([start], [(start, jump), (start + distance, b"\xc3")],
                 "" if distance == 65535 else hex(start + distance))

    def test_imported_call(self):
        data = bytearray((FIXTURES / "metadata.exe").read_bytes())
        layout = Layout(data)
        entry = layout.u32(layout.opt + 16)
        iat, size = layout.directory(12)
        self.assertGreaterEqual(size, 8)
        encoded = b"\xff\x15" + struct.pack("<i", iat - (entry + 6))
        pos = layout.file_offset(entry)
        # The replaced call has its own reachable continuation in the recorded extent.
        data[pos:pos + len(encoded) + 1] = encoded + b"\xc3"
        image = self.dir / "import.exe"
        image.write_bytes(data)
        failure = self.invoke("lift", image, "--rva", hex(entry), "--output", self.dir / "import.ll",
                              "--diagnostics-format", "json", code=1)
        diagnostic = json.loads(failure.stderr)
        self.assertEqual((diagnostic["code"], diagnostic["context"]["opcode"], diagnostic["context"]["bytes"]),
                         ("LIFT_UNSUPPORTED_CONTROL_FLOW", "CALL64m", encoded.hex()))

    def test_direct_call_to_linker_import_thunk(self):
        image = FIXTURES / "import-call.exe"
        data = image.read_bytes()
        layout = Layout(data)
        entry = layout.u32(layout.opt + 16)
        call = entry + 4  # SUB RSP, 40 precedes the direct CALL.
        site = layout.file_offset(call)
        self.assertEqual(data[site], 0xe8)
        target = call + 5 + struct.unpack_from("<i", data, site + 1)[0]
        thunk = layout.file_offset(target)
        self.assertEqual(data[thunk:thunk + 2], b"\xff\x25")
        slot = target + 6 + struct.unpack_from("<i", data, thunk + 2)[0]
        iat, size = layout.directory(12)
        self.assertTrue(iat <= slot < iat + size)
        failure = self.invoke("lift", image, "--rva", hex(entry), "--output", self.dir / "import.ll",
                              "--diagnostics-format", "json", code=1)
        diagnostic = json.loads(failure.stderr)
        self.assertEqual((diagnostic["code"], diagnostic["context"]["opcode"],
                          diagnostic["context"]["branch_target"]),
                         ("LIFT_UNSUPPORTED_CONTROL_FLOW", "CALL64pcrel32", target))
        self.assertEqual((diagnostic["context"]["import_dll"], diagnostic["context"]["import_symbol"],
                          int(diagnostic["context"]["iat_slot_rva"], 16)), ("Physics.DLL", "Named", slot))

    def test_flag_missing_at_forward_join(self):
        image = FIXTURES / "arithmetic.exe"
        export = next(e for e in self.report(image)["modules"][0]["exports"] if "immediates" in e["names"])
        rva = int(export["rva"], 16)
        data = bytearray(image.read_bytes())
        start = Layout(data).file_offset(rva)
        # CMP defines AF. Only the fallthrough XOR invalidates it before LAHF.
        body = bytes.fromhex("39 d1 74 02 31 c0 9f c3")
        data[start:start + len(body)] = body
        changed = self.dir / "join.exe"
        changed.write_bytes(data)
        for signature in ([], ["--signature", "i64(i64,i64)"]):
            failure = self.invoke("lift", changed, "--rva", hex(rva), *signature,
                                  "--output", self.dir / "join.ll", code=1)
            self.assertIn(f"{hex(rva+6)}: LAHF [9f]".encode(), failure.stderr)
            self.assertIn(b"undefined condition flags: AF", failure.stderr)

    def test_atomic_publication(self):
        image = FIXTURES / "add.exe"
        output = self.dir / "function.ll"
        args = ("lift", image, "--rva", "0x1000", "--output", output)
        output.write_bytes(b"old contents")
        previous = self.dir / "previous.ll"
        os.link(output, previous)

        def limit_file_size():
            signal.signal(signal.SIGXFSZ, signal.SIG_IGN)
            resource.setrlimit(resource.RLIMIT_FSIZE, (64, 64))

        p = self.invoke(*args, code=1, preexec_fn=limit_file_size)
        self.assertIn(b"OUTPUT_ERROR", p.stderr)
        self.assertEqual(output.read_bytes(), b"old contents")
        self.assertEqual(list(self.dir.glob("*.tmp-*")), [])

        self.invoke(*args, preexec_fn=lambda: os.close(0))
        self.assertIn("define internal void @forge_lifted_1000(", output.read_text())
        self.assertEqual(previous.read_bytes(), b"old contents")
        output.unlink()
        output.mkdir()
        sentinel = output / "keep"
        sentinel.write_bytes(b"keep")
        p = self.invoke(*args, code=1)
        self.assertIn(b"OUTPUT_ERROR", p.stderr)
        self.assertEqual(sentinel.read_bytes(), b"keep")
        self.assertEqual(list(self.dir.glob("*.tmp-*")), [])

    def assert_published_at(self, output):
        self.invoke("lift", FIXTURES / "add.exe", "--rva", "0x1000", "--output", output,
                    umask=0o027)
        self.assertEqual(list(output.parent.iterdir()), [output])
        self.assertIn("define internal void @forge_lifted_1000(", output.read_text())
        self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o640)

    def test_publication_in_percent_directory(self):
        parent = self.dir / "100%"
        parent.mkdir()
        self.assert_published_at(parent / "function.ll")

    def test_publication_at_name_max(self):
        name_max = os.pathconf(self.dir, "PC_NAME_MAX")
        self.assertGreater(name_max, 1)
        self.assert_published_at(self.dir / ("." + "x" * (name_max - 1)))

    def test_publication_descriptor_transfer_failure(self):
        output = self.dir / "function.ll"
        output.write_bytes(b"old contents")

        def only_stdin_slot_available():
            os.close(0)
            resource.setrlimit(resource.RLIMIT_NOFILE, (3, resource.getrlimit(resource.RLIMIT_NOFILE)[1]))

        p = self.invoke("lift", FIXTURES / "add.exe", "--rva", "0x1000", "--output", output,
                        code=1, preexec_fn=only_stdin_slot_available)
        self.assertIn(b"OUTPUT_ERROR", p.stderr)
        self.assertEqual(output.read_bytes(), b"old contents")
        self.assertEqual(list(self.dir.glob("*.tmp-*")), [])

    def test_relocation_overlaps_instruction(self):
        data = bytearray((FIXTURES / "metadata.exe").read_bytes())
        info = Layout(data)
        reloc = info.file_offset(info.directory(5)[0])
        struct.pack_into("<I", data, reloc, 0x1000)
        struct.pack_into("<H", data, reloc+8, 0xa000)
        exe = self.dir/"relocated.exe"
        exe.write_bytes(data)
        p = self.invoke("lift", exe, "--rva", "0x1000", "--output", self.dir/"rel.ll", code=1)
        self.assertIn(b"base relocation at 0x1000", p.stderr)

    def test_function_relocation_intervals(self):
        original = (FIXTURES / "metadata.exe").read_bytes()
        layout = Layout(original)
        entry = 0x1004
        record = layout.file_offset(layout.directory(3)[0])
        table, size = layout.directory(5)
        reloc = layout.file_offset(table)
        program = self.dir / "relocated.exe"
        output = self.dir / "function.ll"

        # The selected function occupies [0x1004, 0x1007). Zero-width padding,
        # fields ending at its start, and fields starting at its end are harmless.
        # Disjoint malformed data fields must not force image initialization.
        for fields, witness in (
                ((0x0004, 0x3000, 0xa007), None),
                ((0x3001,), 0x1001),
                ((0x7000,), 0x1000),
                ((0x1006, 0xa000, 0x1006), 0x1006),
                ((0x1001, 0x2005, 0x2005, 0xa002), 0x1005)):
            with self.subTest(fields=fields):
                data = bytearray(original)
                struct.pack_into("<II", data, record, entry, entry + 3)
                start = layout.file_offset(entry)
                data[start:start + 3] = bytes.fromhex("31 c0 c3")
                count = (size - 8) // 2
                struct.pack_into("<I", data, reloc, 0x1000)
                struct.pack_into("<" + "H" * count, data, reloc + 8, *fields, *([0] * (count - len(fields))))
                program.write_bytes(data)
                p = self.invoke("lift", program, "--rva", hex(entry), "--output", output,
                                "--diagnostics-format", "json", code=int(witness is not None))
                if witness is not None:
                    failure = json.loads(p.stderr)
                    self.assertEqual(failure["code"], "ENTRY_RELOCATION_OVERLAP")
                    self.assertIn(f"base relocation at {witness:#x}", failure["message"])

    def test_relocated_callee_preserves_call_site(self):
        data = bytearray((FIXTURES / "image.exe").read_bytes())
        layout = Layout(data)
        records = layout.file_offset(layout.directory(3)[0])
        callee, caller = layout.u32(records), layout.u32(records + 12)
        # The fixup touches only the callee and ends exactly at the caller.
        witness = caller - 2
        self.assertLessEqual(callee, witness)
        reloc = layout.file_offset(layout.directory(5)[0])
        struct.pack_into("<I", data, reloc, witness & ~0xfff)
        struct.pack_into("<H", data, reloc + 8, 0x1000 | (witness & 0xfff))
        call = b"\xe8" + struct.pack("<i", callee - caller - 5)
        start = layout.file_offset(caller)
        data[start:start + 6] = call + b"\xc3"
        program = self.dir / "relocated-callee.exe"
        program.write_bytes(data)
        p = self.invoke("lift", program, "--rva", hex(caller), "--output", self.dir / "calls.ll",
                        "--diagnostics-format", "json", code=1)
        failure = json.loads(p.stderr)
        self.assertEqual(failure["code"], "LIFT_UNSUPPORTED_CONTROL_FLOW")
        self.assertIn(f"base relocation at {witness:#x}", failure["message"])
        context = failure["context"]
        self.assertEqual((context["instruction_rva"], context["branch_target"], context["bytes"]),
                         (hex(caller), callee, call.hex()))


if __name__ == "__main__":
    suite = {"discovery": Discovery, "lift": Lift}[SUITE]
    result = unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(suite))
    sys.exit(not result.wasSuccessful())
