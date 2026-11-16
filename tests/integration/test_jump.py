"""Run the guarded dispatches and reject contradictory evidence from a linked fixture."""
import json
import os
from pathlib import Path
import platform
import struct
import subprocess
import sys
import unittest

from image_scaling import image_stats
from pe_layout import Layout
from test_stack import FORGE, IMAGE, GuestExecution, run

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "differential"))
import differential as diff


class JumpTables(GuestExecution):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.original = Path(IMAGE).read_bytes()
        cls.layout = Layout(cls.original)
        section_headers = cls.layout.opt + struct.unpack_from("<H", cls.original, cls.layout.pe + 20)[0]
        cls.headers = {cls.original[p:p+8].rstrip(b"\0").decode(): p for p in
                       range(section_headers, section_headers + 40 * len(cls.layout.sections), 40)}

    def test_rebased_and_original_flags(self):
        entry = self.exports["entry"]
        ir = self.work / "rebased.ll"
        for base in (self.image_base, self.image_base + 0x3210000):
            ir.write_bytes(run(os.environ["FORGE_TEST_LIFT_CONTRACT"], "--emit-rebased", IMAGE,
                               hex(entry), hex(base)))
            self.assertEqual(image_stats(IMAGE, base, ir)["budgeted_initialized_bytes"], 12)
            for exe in self.compile_variants(ir):
                # ADD of the signed offset to the table VA supplies carry to ADC.
                for index, result in [(0, 43), (1, base+entry+31), (2, 43), (3, -91), (-1, -91),
                                      (0x4000000000000002, 43)]:
                    self.expect(exe, index, 42, result)

    def test_unexpected_runtime_target_traps(self):
        ir = self.work / "mismatch.ll"
        run(FORGE, "lift", IMAGE, "--rva", hex(self.exports["entry"]),
            "--signature", "i64(i64,i64)", "--output", ir)
        # A zero displacement sends entry 0 to the table VA. Entry 2 still points at
        # the original shared destination, through the same runtime load and switch.
        table = self.layout.u32(self.headers[".jtab"] + 12)
        start = self.layout.file_offset(table)
        prefix = f'@image_{table:x} = private constant [12 x i8] c"'
        word = "".join(f"\\{byte:02X}" for byte in self.original[start:start+4])
        source = ir.read_text()
        self.assertEqual(source.count(prefix + word), 1)
        ir.write_text(source.replace(prefix + word, prefix + r"\00" * 4))
        for exe in self.compile_variants(ir):
            self.trap(exe, [(0, 2)])
            self.expect(exe, 2, 42, 43)
            self.expect(exe, 3, 2, -91)

    def diagnostic(self, root, edits):
        data = bytearray(self.original)
        for pos, patch in edits:
            data[pos:pos+len(patch)] = patch
        image = self.work / "edited.exe"
        image.write_bytes(data)
        output = self.work / "prior.ll"
        output.write_bytes(b"sentinel")
        command = [FORGE, "lift", image, "--rva", hex(root), "--signature", "i64(i64,i64)",
                   "--diagnostics-format", "json", "--output", output]
        proc = subprocess.run(command, capture_output=True, timeout=10)
        self.assertEqual((proc.returncode, proc.stdout), (1, b""))
        self.assertEqual(output.read_bytes(), b"sentinel")
        return json.loads(proc.stderr)

    def rejects(self, root, jump, edits, reason, *, target=None, code="LIFT_UNSUPPORTED_CONTROL_FLOW"):
        report = self.diagnostic(root, edits)
        self.assertEqual(report["code"], code)
        self.assertIn(reason, report["message"])
        where = report["context"]
        self.assertEqual((where["entry_rva"], where["instruction_rva"], where["opcode"]),
                         (hex(root), hex(jump), "JMP64r"))
        pos = self.layout.file_offset(jump)
        encoded = bytes.fromhex(where["bytes"])
        self.assertEqual((where["file_offset"], encoded),
                         (pos, (self.work / "edited.exe").read_bytes()[pos:pos+len(encoded)]))
        if target is not None:
            self.assertEqual(where["branch_target"], target)
        return report

    def test_index_width_on_both_incoming_paths(self):
        root = self.exports["width_paths"]
        for exe in self.variants("width_paths"):
            for path in (0, 1):
                self.expect(exe, 0x100000001, path, 22)
                self.expect(exe, 0x100000002, path, 33)

        # Both paths bound ECX. The redirected path reaches LEA with RCX still 0x100000001.
        branch = self.layout.file_offset(root + 10)
        self.assertEqual(self.original[branch:branch+2], b"\xeb\x00")
        edits = [(branch + 1, b"\x07")]
        report = self.rejects(root, root + 33, edits, "bypasses proof", target=root + 19)
        self.assertEqual(self.diagnostic(root, edits), report)

    def test_called_table_requires_recorded_extent(self):
        root, leaf = self.exports["table_caller"], self.exports["entry"]
        for exe in self.variants("table_caller"):
            self.expect(exe, 0, 42, 43)

        # Withdraw only the leaf's runtime-function record. Its code and table stay identical.
        pdata, size = self.layout.directory(3)
        first = self.layout.file_offset(pdata)
        self.assertEqual(self.layout.u32(first), leaf)
        edits = [(first, self.original[first+12:first+size]),
                 (self.layout.directories + 3*8 + 4, struct.pack("<I", size - 12))]
        report = self.diagnostic(root, edits)
        self.assertEqual(report["code"], "LIFT_UNSUPPORTED_CONTROL_FLOW")
        self.assertIn("indirect jump recovery requires a validated unwind-backed function extent", report["message"])
        self.assertIn(f"{hex(leaf + 21)}: JMP64r [ffe0]", report["message"])
        site = root + 4
        where = report["context"]
        pos = self.layout.file_offset(site)
        self.assertEqual((where["entry_rva"], where["instruction_rva"], where["opcode"],
                          where["file_offset"], where["bytes"], where["branch_target"]),
                         (hex(root), hex(site), "CALL64pcrel32", pos, self.original[pos:pos+5].hex(), leaf))

    def test_conflicting_fixups_retain_dispatch_evidence(self):
        root = self.exports["entry"]
        table = self.layout.u32(self.headers[".jtab"] + 12)
        reloc, size = self.layout.directory(5)
        self.assertEqual(size, 12)
        field = 0xa000 | ((table + 4) & 0xfff)
        block = struct.pack("<IIHH", table & ~0xfff, size, field, field)
        report = self.rejects(root, root + 21, [(self.layout.file_offset(reloc), block)],
                              f"at RVA {hex(table)} indices 0..2, entry 1: overlapping base relocations",
                              code="INVALID_PE")
        self.assertEqual((report["stage"], report["category"]), ("pe", "invalid_input"))

    def test_dynamic_relocations_block_only_table_recovery(self):
        image = Path(IMAGE).with_name("jump-dvrt.exe")
        data = image.read_bytes()
        layout = Layout(data)
        config = layout.file_offset(layout.directory(10)[0])
        offset, section = struct.unpack_from("<IH", data, config + 224)
        self.assertEqual(offset, 0)
        _, dvrt, _, disk = layout.sections[section - 1]
        self.assertEqual(struct.unpack_from("<IIQ", data, disk), (1, 24, 5))
        module = json.loads(run(FORGE, "inspect", image, "--format", "json"))["modules"][0]
        exports = {name: row["rva"] for row in module["exports"] for name in row["names"]}
        jump = int(exports["entry"], 16) + 20
        self.assertEqual(layout.u32(disk + 20) + struct.unpack_from("<H", data, disk + 28)[0], jump)

        # Both the section/offset and legacy preferred-VA advertisement are sufficient.
        legacy = bytearray(data)
        struct.pack_into("<IH", legacy, config + 224, 0, 0)
        struct.pack_into("<Q", legacy, config + 192, int(module["image_base_va"], 16) + dvrt)
        old = self.work / "dvrt-va.exe"
        old.write_bytes(legacy)
        for fixture in (image, old):
            ir = self.work / "dvrt.ll"
            ir.write_bytes(b"sentinel")
            args = [FORGE, "lift", fixture, "--signature", "i64(i64,i64)", "--output", ir]
            failure = subprocess.run([*args, "--rva", exports["entry"], "--diagnostics-format", "json"],
                                     capture_output=True, timeout=10)
            self.assertEqual((failure.returncode, ir.read_bytes()), (1, b"sentinel"))
            report = json.loads(failure.stderr)
            self.assertEqual((report["code"], report["context"]["instruction_rva"]),
                             ("LIFT_UNSUPPORTED_CONTROL_FLOW", hex(jump)))
            self.assertIn("dynamic relocation", report["message"])
            run(*args, "--rva", exports["direct_only"])

    def test_initialization_failure_reaches_differential_parser(self):
        table = self.layout.u32(self.headers[".jtab"] + 12)
        reloc, size = self.layout.directory(5)
        block = struct.pack("<IIHH", table & ~0xfff, size, 0xa000 | ((table+8) & 0xfff), 0)
        edits = [(self.layout.file_offset(reloc), block)]
        jump = self.exports["entry"] + 21
        ir = self.work / "generated" / "case.ll"
        ir.parent.mkdir(exist_ok=True)
        for name in ("entry", "table_caller"):
            report = self.diagnostic(self.exports[name], edits)
            where = report["context"]
            self.assertEqual((where["instruction_rva"], where["bytes"], where["file_offset"]),
                             (hex(jump), "ffe0", self.layout.file_offset(jump)))
            self.assertEqual(where.get("function_rva"), hex(self.exports["entry"]) if name == "table_caller" else None)
            self.assertIn(f"at RVA {hex(table)} indices 0..2", report["message"])
            image = self.work / "edited.exe"
            selected = diff.analyze(FORGE, image, name, self.work)
            with self.assertRaisesRegex(ValueError, "^pe/INVALID_PE: .*relocation target outside"):
                diff.lift(FORGE, image, {"signature": "i64(i64,i64)"}, selected, ir)

    def test_table_decode_crosses_default_leader(self):
        root = self.exports["entry"]
        table = self.layout.u32(self.headers[".jtab"] + 12)
        # Entries 0 and 1 now reach the same instruction, spanning the known JA target.
        edits = [(self.layout.file_offset(table), struct.pack("<i", root+31-table)),
                 (self.layout.file_offset(root+31), b"\xb8")]
        # Alternatively, entry 2 branches to the preceding NOP. Its direct successor
        # falls through the table target before crossing the same default leader.
        via_direct = [(self.layout.file_offset(root+23), b"\xeb\x05"),
                      (self.layout.file_offset(root+30), b"\x90")]
        for patch in (edits, edits + via_direct):
            report = self.rejects(root, root+21, patch, "entry 0: branch enters an instruction",
                                  code="LIFT_INVALID_BRANCH_TARGET", target=root+31)
            self.assertIn(f"at {hex(root+32)} (instruction begins at {hex(root+31)})", report["message"])
            self.assertEqual(self.diagnostic(root, patch), report)

    def test_inferred_leaf_call_via_table(self):
        image = self.work / "case-caller.exe"
        image.write_bytes(self.original)
        ir = self.work / "generated" / "case.ll"
        ir.parent.mkdir(exist_ok=True)
        selected = diff.analyze(FORGE, image, "case_caller", self.work)
        with self.assertRaisesRegex(diff.Unsupported, "LIFT_UNDEFINED_REGISTER"):
            diff.lift(FORGE, image, {"signature": "i64(i64,i64)"}, selected, ir)
        raw = (self.work / "lifting.log").read_bytes()
        module = diff.read_json(self.work / "inspect.json")["modules"][0]
        analysis = diff.read_json(self.work / "analysis.json")

        def verify():
            return diff.parse_diagnostic(raw, image, selected, ir, lambda leaf, caller, site:
                                         diff.resolve_leaf_window(module, analysis, image, leaf, caller, site, FORGE))

        self.assertEqual(verify()["context"]["opcode"], "ADD64rr")
        table = self.layout.file_offset(self.layout.u32(self.headers[".jtcall"] + 12))
        changed = bytearray(self.original)
        changed[table:table+4] = changed[table+4:table+8]
        image.write_bytes(changed)
        with self.assertRaisesRegex(ValueError, "reachable direct CALL"):
            verify()

        start = self.layout.file_offset(selected.start)
        for pos, replacement, reason in [
                (start+8, b"\x00", "bypasses the dispatch guard"),  # Both JA edges enter the MOV.
                (start+9, b"\x89\xd0", "unproven caller dispatch bound"),  # Copy unchecked EDX.
                (self.layout.directories + 12*8,
                 struct.pack("<II", self.layout.u32(self.headers[".jtcall"] + 12), 4),
                 "loader-written")]:
            with self.subTest(reason=reason):
                changed = bytearray(self.original)
                changed[pos:pos+len(replacement)] = replacement
                image.write_bytes(changed)
                with self.assertRaisesRegex(ValueError, reason):
                    verify()

        # An equivalent full-width guard reads RCX directly, with no register copy.
        changed = bytearray(self.original)
        changed[start+4:start+11] = b"\x90\x48\x83\xf9\x01\x77" + bytes([self.original[start+8] - 2])
        changed[start+21] = 0x88  # MOVSXD index RCX, formerly RAX.
        image.write_bytes(changed)
        self.assertEqual(verify()["context"]["opcode"], "ADD64rr")

    def test_bounds_and_encoding(self):
        root = self.exports["entry"]
        start = self.layout.file_offset(root)
        for offset, patch, reason in [
                (0, "85 c9 90", "unproven"),       # No comparison with an immediate.
                (2, "ff", "4294967295 exceeds recovery budget"),
                (3, "7f", "unproven"),             # Signed greater-than.
                (5, "90 90", "unproven"),          # High index bits unconstrained.
                (5, "89 d0", "unproven"),          # MOV from the unchecked register.
                (5, "ff c1", "unproven"),          # Index changed after JA.
                (7, "4c 8d 81", "unresolved"),     # Non-RIP base.
                (14, "49 8b 04 80", "unrecognized"),  # Full pointer, not signed dword.
                (14, "49 63 04 40", "unrecognized"),  # Wrong stride.
                (21, "ff e2", "unrecognized"),     # Jump via a different register.
                (4, "02", "bypasses proof"),       # Taken edge skips the extension.
                (32, "eb e3", "bypasses proof")]: # Default jumps back to the MOV.
            with self.subTest(offset=offset, patch=patch):
                self.rejects(root, root + 21, [(start+offset, bytes.fromhex(patch))], reason)
        root = self.exports["cfg_jump_table"]
        pos = self.layout.file_offset(root)
        # Replace MOV + imm8 CMP with a single CMP RCX, 1024.
        self.rejects(root, root+23, [(pos, bytes.fromhex("48 81 f9 00 04 00 00"))], "budget")

    def test_table_bytes_and_destinations(self):
        root = self.exports["entry"]
        table = self.layout.u32(self.headers[".jtab"] + 12)
        start = self.layout.file_offset(root)
        word = self.layout.file_offset(table)
        for dest, reason, invalid in [(table, "outside executable", True),
                                      (-1, "outside executable", True),
                                      (root+33, "enters an instruction", True),
                                      (root+40, "invalid or truncated", True),
                                      (self.exports["cfg_jump_table"], "outside validated function", False),
                                      (root+5, "bypasses proof", False)]:
            with self.subTest(dest=dest):
                self.rejects(root, root+21, [(word+8, struct.pack("<i", dest-table))],
                             reason, code="LIFT_INVALID_BRANCH_TARGET" if invalid else "LIFT_UNSUPPORTED_CONTROL_FLOW",
                             target=dest)
        perm = self.headers[".jtab"] + 36
        self.rejects(root, root+21, [(perm, struct.pack("<I", self.layout.u32(perm) | 0x80000000))],
                     "stable, read-only")
        self.rejects(root, root+21, [(self.layout.directories + 12*8, struct.pack("<II", table+4, 4))],
                     "entry 1: loader-written")
        self.rejects(root, root+21, [(self.layout.directories + 12*8, struct.pack("<II", root+3, 2))],
                     "dispatch function bytes are not stable")
        fixup = self.layout.u32(self.headers[".jtfix"] + 12)
        for base, reason in [(table+1, "entry 2: unmapped or truncated"),
                             (table+4, "entry 2: unmapped or truncated"),
                             (fixup, "entry 0: loader-written or relocated")]:
            with self.subTest(table=base):
                # Set every complete shifted word to a valid target, up to the short final entry.
                edits = [(start+10, struct.pack("<i", base-(root+14)))]
                if base != fixup:
                    edits.append((self.layout.file_offset(base), struct.pack("<ii", root+23-base, root+23-base)))
                self.rejects(root, root+21, edits, reason)

    def test_total_entry_budget_counts_duplicate_edges(self):
        root = self.exports["table_budget"]
        for exe in self.variants("table_budget"):
            self.expect(exe, 1023, 0, 53)
        first = self.layout.u32(self.headers[".jtmax"]+12)
        fourth = first + 3*4096
        # Recover the first four stage addresses from their linked tables. All
        # five dispatch sequences have the same encoding and a short default JA.
        stride = first + struct.unpack_from("<i", self.original, self.layout.file_offset(first))[0] - root
        fifth = root + 4*stride
        jump = fifth + stride - 2
        self.rejects(root, jump, [(self.layout.file_offset(fourth), struct.pack("<i", fifth-fourth))],
                     "function jump-table recovery budget exceeded")

    def test_second_table_can_invalidate_first_guard(self):
        for exe in self.variants("two_tables"):
            self.expect(exe, 0, 0, 77)
            self.expect(exe, 0, 1, -19)
            self.expect(exe, 1, 0, -19)
        root = self.exports["two_tables"]
        second = self.layout.u32(self.headers[".jtnest"]+12) + 8
        self.rejects(root, root+20, [(self.layout.file_offset(second), struct.pack("<i", root+6-second))],
                     "bypasses proof", target=root+6)


if __name__ == "__main__":
    if (platform.system(), platform.machine()) != ("Darwin", "arm64"):
        sys.exit(77)
    unittest.main(argv=[sys.argv[0]])
