"""Exercise discovery and lift diagnostics through their CLI entry points."""
import json
import os
import resource
import signal
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
        r = self.analyze(self.copy("metadata.exe"), "--strict")
        f, = r["functions"]
        self.assertTrue(f["contains_tls_callback"] and f["contains_entry_point"])
        self.assertEqual((f["size"], f["source"], f["status"]), (9, "exception_directory", "valid"))
        self.assertEqual(r["unknown_executable_ranges"], [])
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
        self.assertEqual(f["location"]["line"], 6)  # call site in entry, helper body is line 2

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
                    self.invoke("lift", image, "--rva", hex(first[0]), "--output", self.dir/"bad.ll", code=1)
                self.invoke("lift", image, "--rva", hex(third[0]), "--output", self.dir/"ok.ll")
                self.assertTrue(all(f["status"] == "valid" for f in functions if int(f["start_rva"],16) >= third[0]))

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

    def test_reject_unsupported_and_unproven(self):
        original = (FIXTURES / "arithmetic.exe").read_bytes()
        info = Layout(original)
        offset = info.file_offset(0x1000)
        output = self.dir/"existing.ll"
        output.write_text("sentinel")
        for code, expected in [
                ("88 c8 c3", "undefined RAX"), ("66 89 c8 c3", "undefined RAX"), ("48 8b 01 c3", "operand form"),
                ("48 89 e0 c3", "RSP"), ("48 8d 05 00 00 00 00", "RIP"),
                ("f3 c3", "prefix"), ("48 48 89 c8 c3", "prefix"),
                ("ff d0 c3", "unsupported"), ("ff e0", "unsupported"),
                ("b8 01 00 00 00 31 c0", "outside"), ("eb fe", "backward"), ("eb 05", "outside"), ("eb 01 48 89 c8 c3", "enters an instruction"),
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
                ("31 c0 31 c0 31 c0 90", "unsupported")]:
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

        self.invoke(*args)
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


if __name__ == "__main__":
    suite = {"discovery": Discovery, "lift": Lift}[SUITE]
    result = unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(suite))
    sys.exit(not result.wasSuccessful())
