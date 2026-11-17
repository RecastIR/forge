"""Exercise IAT proofs and Windows ABI effects through the normal lift command."""
import json
from pathlib import Path
import struct
import sys
import unittest

from cli_case import Case, FIXTURES
from pe_layout import Layout


class Imports(Case):
    def setUp(self):
        super().setUp()
        self.original = (FIXTURES / "last-error.exe").read_bytes()
        self.layout = Layout(self.original)
        self.output = self.dir / "lifted.ll"
        module = self.report(FIXTURES / "last-error.exe")["modules"][0]
        exports = {name: int(e["rva"], 16) for e in module["exports"] for name in e["names"]}
        self.root, self.helper = exports["last_error"], exports["last_error_set"]
        self.code = self.layout.file_offset(self.root)
        self.descriptors = self.layout.file_offset(self.layout.directory(1)[0])
        self.slots = {}
        for offset in (self.descriptors, self.descriptors + 20):
            lookup, _, _, name, iat = struct.unpack_from("<5I", self.original, offset)
            if self.original[self.layout.file_offset(name):].startswith(b"KERNEL32.dll\0"):
                self.descriptor, self.lookup, self.iat = offset, lookup, iat
                for i in range(3):
                    hint = struct.unpack_from("<Q", self.original, self.layout.file_offset(lookup) + 8*i)[0]
                    start = self.layout.file_offset(hint) + 2
                    self.slots[self.original[start:self.original.index(0, start)].decode()] = iat + 8*i

    def invoke_lift(self, data, *opts, reason=None, code=None, symbol=None, name=None, entry=None):
        image = self.dir / "guest.exe"
        image.write_bytes(data)
        args = ("--signature", "i64(i64,i64)", "--runtime") if not opts else opts
        if reason:
            self.output.write_bytes(b"previous module")
        result = self.invoke("lift", image, "--rva", hex(self.root if entry is None else entry), "--output", self.output,
                             "--diagnostics-format", "json", *args, code=int(reason is not None))
        if not reason:
            return self.output.read_text()
        self.lift_stderr = result.stderr
        diag = json.loads(result.stderr)
        self.assertIn(reason, diag["message"])
        self.assertEqual(diag["code"], code)
        self.assertEqual(self.output.read_bytes(), b"previous module")
        ctx = diag["context"]
        self.assertEqual(ctx["input"], str(image))
        if symbol:
            self.assertEqual(ctx["import_symbol"], symbol)
        if name:
            self.assertEqual(ctx["import_dll"], name)
        if "instruction_rva" in ctx:
            site = self.layout.file_offset(int(ctx["instruction_rva"], 16))
            self.assertTrue(ctx["bytes"])
            self.assertEqual(bytes.fromhex(ctx["bytes"]), data[site:site + len(ctx["bytes"])//2])
        return ctx

    def patch(self, *instructions):
        # All test blocks end within the recorded root and use valid reachable continuations.
        data = bytearray(self.original)
        pos = self.code
        for item in instructions:
            if isinstance(item, tuple):
                prefix, target = item
                prefix = bytes.fromhex(prefix)
                next_rva = self.root + pos - self.code + len(prefix) + 4
                encoded = prefix + struct.pack("<i", target - next_rva)
            else:
                encoded = bytes.fromhex(item)
            data[pos:pos+len(encoded)] = encoded
            pos += len(encoded)
        return data

    def test_context_selection_and_calls(self):
        ir = self.invoke_lift(self.original)
        self.assertIn("define i64 @forge_lifted_with_runtime(", ir)
        self.assertNotIn("@forge_lifted_", ir.replace("@forge_lifted_with_runtime", ""))
        self.assertNotIn("@forge_lifted(", ir)
        self.assertEqual(ir.count("call i32 @forge_rt_set_last_error"), 1)
        self.assertEqual(ir.count("call i32 @forge_rt_get_last_error"), 3)
        ctx = self.invoke_lift(self.original, "--signature", "i64(i64,i64)", reason="--runtime",
                               code="LIFT_UNSUPPORTED_CONTROL_FLOW")
        raw = self.invoke("lift", FIXTURES / "last-error.exe", "--rva", hex(self.root), "--output", self.output,
                          "--diagnostics-format", "json", code=1)
        self.assertEqual(json.loads(raw.stderr)["context"]["signature"], "register-state")
        self.assertIn(b"--runtime", raw.stderr)
        self.assertEqual(ctx["opcode"], "CALL64m")
        self.assertIn("iat_slot_rva", ctx)
        for flag in ("--runtime", "--checked-memory"):
            self.invoke("lift", FIXTURES / "last-error.exe", "--rva", hex(self.root), "--output",
                        self.output, flag, code=2)
        ir = self.invoke_lift(self.patch("89c8 c3"))
        self.assertNotIn("@forge_rt_", ir)
        self.assertIn("@forge_lifted_with_runtime(", ir)

    def test_checked_reservation_covers_pe_headers(self):
        # The fixed guest stack occupies only the first page, before the first section.
        self.assertGreaterEqual(min(start for size, start, _, _ in self.layout.sections if size), 0x1000)
        stackful = bytearray(self.original)
        stackless = self.patch("89c8 c3")
        for data in (stackful, stackless):
            struct.pack_into("<Q", data, self.layout.opt + 24, 0x70000000)

        checked = ("--signature", "i64(i64,i64)", "--checked-memory")
        size = self.layout.u32(self.layout.opt + 56)
        reason = ("PE image overlaps the guest stack [0x70000000, 0x70001000) "
                  f"at selected image base 0x70000000 with SizeOfImage {size:#x}")
        context = self.invoke_lift(stackful, *checked, reason=reason, code="LIFT_IMAGE_MEMORY")
        self.assertEqual(int(context["entry_rva"], 16), self.root)
        self.assertIn("instruction_rva", context)
        self.assertTrue(context["bytes"])
        self.assertIn("@forge_lifted_with_runtime(", self.invoke_lift(stackful))
        self.assertIn("call i32 @forge_rt_enter(", self.invoke_lift(stackless, *checked))

    def test_bound_and_fallback(self):
        data = self.patch(("ff15", self.slots["GetLastError"]), "c3")
        desc = self.descriptor
        fallback = bytearray(data)
        struct.pack_into("<I", fallback, desc, 0)
        self.assertIn("@forge_rt_get_last_error", self.invoke_lift(fallback))
        struct.pack_into("<I", data, desc+4, 0xffffffff)
        for i in range(3):
            struct.pack_into("<Q", data, self.layout.file_offset(self.iat)+8*i, 0x7ffaa0001000+i*32)
        self.assertIn("@forge_rt_get_last_error", self.invoke_lift(data))
        missing = bytearray(data)
        struct.pack_into("<I", missing, desc, 0)
        self.invoke_lift(missing, reason="no independent", code="LIFT_UNSUPPORTED_CONTROL_FLOW", name="KERNEL32.dll")
        report = self.report(self.dir / "guest.exe")["modules"][0]
        kernel = next(d for d in report["imports"] if d["normalized_name"] == "kernel32.dll")
        self.assertEqual(kernel["symbols"], [{"unresolved": True}]*3)
        struct.pack_into("<Q", data, self.layout.file_offset(self.lookup), 0x7ffaa0001111)
        self.invoke_lift(data, reason="hint/name RVA", code="INVALID_PE")

    def test_malformed_metadata(self):
        pristine = self.patch(("ff15", self.slots["GetLastError"]), "c3")
        last = max((start + size - 4 for size, start, _, _ in self.layout.sections))
        second = self.descriptors + (20 if self.descriptor == self.descriptors else 0)
        fields = [(self.descriptor + 16, "I", 0xfffffff8, "outside sections"),
                  (self.descriptor, "I", last, "virtual section"),
                  (self.descriptor + 16, "I", last, "virtual section"),
                  (self.layout.file_offset(self.iat), "Q", 0, "disagree"),
                  (self.layout.file_offset(self.iat), "Q", self.layout.u32(self.layout.file_offset(self.lookup)+8), "disagree")]
        for offset, fmt, value, reason in fields:
            with self.subTest(offset=offset, value=value):
                data = bytearray(pristine)
                struct.pack_into("<" + fmt, data, offset, value)
                self.invoke_lift(data, reason=reason, code="INVALID_PE")
        # A second descriptor can duplicate both valid tables. Ownership still conflicts.
        data = bytearray(pristine)
        data[second:second+20] = data[self.descriptor:self.descriptor+20]
        self.invoke_lift(data, reason="overlapping IAT", code="INVALID_PE")

    def test_loader_field_owns_iat_bytes(self):
        data = self.patch(("ff15", self.slots["GetLastError"]), "c3")
        # Append a TLS directory inside the existing raw padding of the relocation section.
        reloc, size = self.layout.directory(5)
        header = self.layout.section_header(reloc)
        struct.pack_into("<I", data, header + 8, size + 40)
        struct.pack_into("<II", data, self.layout.directories + 9*8, reloc + size, 40)
        base = struct.unpack_from("<Q", data, self.layout.opt + 24)[0]
        struct.pack_into("<Q", data, self.layout.file_offset(reloc) + size + 16,
                         base + self.slots["GetLastError"] + 4)
        ctx = self.invoke_lift(data, reason="another loader-written field", code="INVALID_PE")
        self.assertEqual(ctx["import_ownership_reason"], "overlapping_loader_field")
        # Pass the real CLI diagnostic through the differential runner and test a forged slot.
        sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "differential"))
        from lift_diagnostics import SelectedFunction, parse_diagnostic
        sys.path.pop(0)
        image = self.dir / "guest.exe"
        end = int(ctx["end_rva"], 16)
        selected = SelectedFunction(self.root, end, self.code, "exe", False)
        parsed = parse_diagnostic(self.lift_stderr, image, selected, self.output)
        self.assertEqual(parsed["context"], ctx)
        parsed["context"]["iat_slot_rva"] = hex(self.slots["GetLastError"] + 1)
        with self.assertRaisesRegex(ValueError, "IAT slot disagrees"):
            parse_diagnostic((json.dumps(parsed) + "\n").encode(), image, selected, self.output)

        other = self.descriptors + (20 if self.descriptor == self.descriptors else 0)
        owner = self.layout.directory(1)[0] + other - self.descriptors
        struct.pack_into("<Q", data, self.layout.file_offset(reloc) + size + 16, base + owner + 16)
        ctx = self.invoke_lift(data, reason="ownership depends on loader-written", code="LIFT_UNSUPPORTED_CONTROL_FLOW")
        self.assertEqual((ctx["import_descriptor_rva"], ctx["import_ownership_reason"]),
                         (hex(owner), "loader_written_ownership"))

    def test_other_descriptor_ownership(self):
        slot = self.slots["GetLastError"]
        directory = self.layout.directory(1)[0]
        other = self.descriptors + (20 if self.descriptors == self.descriptor else 0)
        owner = directory + other - self.descriptors
        lookup = self.layout.u32(other)
        iat = self.layout.u32(other + 16)
        # Physics.DLL supplies one symbol. Its zero terminators bound its writes.
        for field, descriptor in ((owner + 16, owner), (owner, owner), (lookup + 8, owner),
                                  (iat + 8, owner), (directory + 40, directory + 40)):
            data = self.patch(("ff15", slot), "c3")
            reloc = self.layout.file_offset(self.layout.directory(5)[0])
            struct.pack_into("<I", data, self.layout.directories + 5*8+4, 12)
            struct.pack_into("<IIHH", data, reloc, field & ~4095, 12, 0x3000 | (field & 4095), 0)
            for entry, site, requested in ((self.root, self.root, slot),
                                            (self.helper, self.helper + 4, self.slots["SetLastError"])):
                with self.subTest(field=field, entry=entry):
                    ctx = self.invoke_lift(data, entry=entry, reason="ownership depends on relocated bytes",
                                           code="LIFT_UNSUPPORTED_CONTROL_FLOW")
                    self.assertEqual((ctx["import_descriptor_rva"], ctx["import_ownership_reason"],
                                      ctx["iat_slot_rva"], ctx["instruction_rva"]),
                                     (hex(descriptor), "relocated_ownership", hex(requested), hex(site)))

        # An unrelated symbol's name can be relocated without moving its descriptor's IAT.
        hint = self.layout.u32(self.layout.file_offset(lookup))
        data = self.patch(("ff15", slot), "c3")
        reloc = self.layout.file_offset(self.layout.directory(5)[0])
        struct.pack_into("<I", data, self.layout.directories + 5*8+4, 12)
        struct.pack_into("<IIHH", data, reloc, hint & ~4095, 12, 0x3000 | (hint & 4095), 0)
        self.assertIn("@forge_rt_get_last_error", self.invoke_lift(data))

    def test_import_identities_and_indirections(self):
        slot = self.slots["GetLastError"]
        data = self.patch(("ff15", slot), "c3")
        symbol_index = (slot-self.iat)//8
        ordinal = bytearray(data)
        for table in (self.lookup, self.iat):
            struct.pack_into("<Q", ordinal, self.layout.file_offset(table) + 8*symbol_index, (1 << 63) | 17)
        self.invoke_lift(ordinal, reason="unsupported import", code="LIFT_UNSUPPORTED_CONTROL_FLOW", symbol="#17")
        wrong = bytearray(data)
        name = self.layout.file_offset(self.layout.u32(self.descriptor + 12))
        wrong[name:name+8] = b"OTHERDLL"
        self.invoke_lift(wrong, reason="unsupported import", code="LIFT_UNSUPPORTED_CONTROL_FLOW", symbol="GetLastError")
        for target in (self.root, slot + 1):
            self.invoke_lift(self.patch(("ff15", target), "c3"), reason="complete validated IAT", code="LIFT_UNSUPPORTED_CONTROL_FLOW")
        self.invoke_lift(self.patch(("ff15", self.slots["Sleep"]), "c3"), reason="unsupported import",
                         code="LIFT_UNSUPPORTED_CONTROL_FLOW", symbol="Sleep")
        self.invoke_lift(self.patch("ff11 c3"), reason="RIP-relative call", code="LIFT_UNSUPPORTED_CONTROL_FLOW")
        self.invoke_lift(self.patch(("488b05", slot), "ffd0 c3"), reason="expected a same-block", code="LIFT_UNSUPPORTED_CONTROL_FLOW")
        self.invoke_lift(self.patch(("488b05", slot), "c3"), reason="loader-written", code="LIFT_IMAGE_MEMORY")
        store = self.patch(("48890d", slot), "89c8 c3")
        # Writable section permissions alone cannot authorize writing an IAT entry.
        flags = self.layout.section_header(slot) + 36
        struct.pack_into("<I", store, flags, self.layout.u32(flags) | 0x80000000)
        self.invoke_lift(store, reason="loader-written", code="LIFT_IMAGE_MEMORY")
        delayed = FIXTURES / "last-error-delay.exe"
        meta = self.report(delayed)["modules"][0]
        self.root = int(next(e["rva"] for e in meta["exports"] if "last_error" in e["names"]), 16)
        self.layout = Layout(delayed.read_bytes())
        self.invoke_lift(delayed.read_bytes(), reason="delay import", code="LIFT_UNSUPPORTED_CONTROL_FLOW")

    def test_relocated_identity(self):
        target = self.slots["GetLastError"]
        original = self.patch(("ff15", target), "c3")
        entry = self.lookup + target - self.iat
        hint = self.layout.u32(self.layout.file_offset(entry))
        for field in (entry, hint, self.layout.u32(self.descriptor + 12)):
            with self.subTest(field=field):
                data = bytearray(original)
                reloc = self.layout.file_offset(self.layout.directory(5)[0])
                struct.pack_into("<I", data, self.layout.directories + 5*8+4, 12)
                struct.pack_into("<IIHH", data, reloc, field & ~4095, 12, 0xa000 | (field & 4095), 0)
                self.invoke_lift(data, reason="import identity overlaps", code="LIFT_UNSUPPORTED_CONTROL_FLOW",
                                 name="KERNEL32.dll", symbol="GetLastError")

    def test_call_overwrites_partial_spill(self):
        # The spill helper's caller resumes at ADD RSP,40. Its byte is selected only
        # while the saved pointer survives the imported call.
        epilogue = bytes.fromhex("4883c428 c3")
        cont = self.original.index(epilogue, self.code)
        self.assertEqual(self.original[cont-5], 0xe8)
        backing = f"@image_{self.root + cont - self.code:x} ="
        self.assertIn(backing, self.invoke_lift(self.original))
        data = bytearray(self.original)
        for encoding in ("4c89442420", "4c8b442420"):
            # Move the store and reload from RSP+32 to RSP-4. Four bytes now
            # overlap the eight-byte return slot installed by the service CALL.
            op = bytes.fromhex(encoding)
            self.assertEqual(data.count(op), 1)
            data[data.index(op) + len(op) - 1] = 0xfc
        self.assertNotIn(backing, self.invoke_lift(data))

    def test_external_effects(self):
        get, put = (("ff15", self.slots[name]) for name in ("GetLastError", "SetLastError"))
        for seq, why, code in [
            ((get, put, "89c8 c3"), "RCX", "LIFT_UNDEFINED_REGISTER"),
            (("b801000000", put, "c3"), "undefined RAX", "LIFT_UNDEFINED_REGISTER"),
            (("b801000000", ("e8", self.helper), "c3"), "undefined RAX", "LIFT_UNDEFINED_REGISTER"),
            ((get, "4889d0 c3"), "RDX", "LIFT_UNDEFINED_REGISTER"),
            (("39d1", get, "0f92c0 c3"), "undefined condition flags", "LIFT_UNDEFINED_FLAG"),
            # One branch carries defined RAX, the other calls a void service.
            (("b801000000 39d1 7406", put, "c3"), "undefined RAX", "LIFT_UNDEFINED_REGISTER")]:
            with self.subTest(seq=seq):
                self.invoke_lift(self.patch(*seq), reason=why, code=code)
        self.assertIn("@forge_rt_get_last_error", self.invoke_lift(self.patch(get, "c3")))
        # A preserved definition and a getter definition meet at RET with all RAX bits available.
        self.invoke_lift(self.patch("b805000000 39d1 7406", get, "c3"))
        # Save an opaque incoming RBX, retain a guest input in it across the service, then restore it.
        self.invoke_lift(self.patch("53 4889cb 4883ec20", get, "4889d8 4883c420 5b c3"))


if __name__ == "__main__":
    unittest.main(argv=[__file__], verbosity=2)
