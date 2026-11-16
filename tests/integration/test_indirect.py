"""Exercise resolved calls through both native entries and check evidence against linked bytes."""
import json
import os
from pathlib import Path
import platform
import re
import struct
import subprocess
import sys
import unittest

from pe_layout import Layout
from test_stack import FORGE, IMAGE, MASK, GuestExecution, initial_slots, run

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "differential"))
import differential as diff


class IndirectCalls(GuestExecution):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.root = cls.exports["call_indirect"]
        cls.shared = cls.exports["indirect_preserve"]
        cls.leaf = cls.exports["indirect_leaf"]
        cls.recursive = cls.exports["indirect_recurse"]
        cls.original = Path(IMAGE).read_bytes()
        cls.layout = Layout(cls.original)
        pdata, size = cls.layout.directory(3)
        first = cls.layout.file_offset(pdata)
        cls.records = {cls.layout.u32(off): off for off in range(first, first + size, 12)}

    def test_state(self):
        for exe in self.variants("call_indirect", state=True):
            expected = bytearray()
            for i in range(2):
                slots = initial_slots(i)
                left, right = slots[1:3]
                count = 2 + (left >= right)
                slots[:] = [(2 * right + count + i + 1 + 3 * (left & 3)) & MASK, 0,
                            (right + count) & MASK, left & 3, 13,
                            self.image_base + self.leaf, self.image_base + self.recursive]
                expected.extend(struct.pack("<I7QI", 0x01234567, *slots, 0x89abcdef))
            self.assertEqual(run(exe), expected)

    def test_rebase_and_target_mismatch(self):
        for base in (self.image_base, self.image_base + 0x3210000):
            ir = self.work / "targets.ll"
            source = run(os.environ["FORGE_TEST_LIFT_CONTRACT"], "--emit-rebased", IMAGE,
                         hex(self.root), hex(base)).decode()
            ir.write_text(source)
            for exe in self.compile_variants(ir):
                self.expect(exe, 7, 2, 17)
                self.expect(exe, 0, 1, 5)

            # Corrupt only the R11 LEA to the shared helper. The earlier RAX call, the
            # expected VA, and the guest frame stay valid. The recursive callee would return
            # normally on (7, 2), so dispatching there cannot satisfy the trap assertion.
            store = rf"(getelementptr inbounds i64, ptr %registers, i32 6\n  store i64 ){base + self.shared},"
            modified, count = re.subn(store, rf"\g<1>{base + self.recursive},", source)
            self.assertEqual(count, 1)
            ir.write_text(modified)
            for exe in self.compile_variants(ir):
                self.trap(exe, [(7, 2)])
                self.expect(exe, 0, 1, 5)

    def test_nonvolatile_target_and_return_address(self):
        # Save R12, reserve shadow space, call through R12, and return the VA read by the leaf.
        code = bytearray.fromhex("41 54 48 83 ec 20 4c 8d 25")
        code.extend(struct.pack("<i", self.leaf - (self.root + len(code) + 4)))
        code.extend(bytes.fromhex("66 0f 1f 00 41 ff d4"))
        continuation = self.root + len(code)
        code.extend(bytes.fromhex("48 83 c4 20 41 5c c3"))
        image = self.work / "return-address.exe"
        data = bytearray(self.original)
        start = self.layout.file_offset(self.root)
        data[start:start+len(code)] = code
        leaf = self.layout.file_offset(self.leaf)
        data[leaf:leaf+5] = bytes.fromhex("48 8b 04 24 c3")
        image.write_bytes(data)
        ir = self.work / "return-address.ll"
        base = self.image_base + 0x710000
        ir.write_bytes(run(os.environ["FORGE_TEST_LIFT_CONTRACT"], "--emit-rebased", image,
                           hex(self.root), hex(base)))
        for exe in self.compile_variants(ir):
            self.expect(exe, 3, 4, base + continuation)

    def diagnostic(self, edits):
        data = bytearray(self.original)
        for offset, body in edits:
            data[offset:offset + len(body)] = body
        image = self.work / "edited.exe"
        image.write_bytes(data)
        output = self.work / "old.ll"
        output.write_bytes(b"previous IR")
        args = [FORGE, "lift", image, "--rva", hex(self.root), "--signature", "i64(i64,i64)",
                "--output", output, "--diagnostics-format", "json"]
        failed = subprocess.run(args, capture_output=True, timeout=15)
        self.assertEqual((failed.returncode, failed.stdout, output.read_bytes()), (1, b"", b"previous IR"))
        return json.loads(failed.stderr)

    def check_site(self, edits, site, encoded, *, code="LIFT_UNSUPPORTED_CONTROL_FLOW",
                   target=None, opcode="CALL64r", owner=None):
        report = self.diagnostic(edits)
        where = report["context"]
        self.assertEqual((report["stage"], report["category"], report["code"]),
                         ("lifting", "invalid_input" if code == "LIFT_INVALID_CALL_TARGET" else "unsupported", code))
        self.assertEqual((where["entry_rva"], where.get("function_rva"), where["instruction_rva"],
                          where["opcode"], where["bytes"], where["file_offset"], where.get("branch_target")),
                         (hex(self.root), hex(owner) if owner else None, hex(site), opcode, encoded.hex(),
                          self.layout.file_offset(site), target))
        return report

    def test_unproven_calls(self):
        base = self.layout.file_offset(self.root)
        lea = b"\x48\x8d\x05" + struct.pack("<i", self.shared - self.root - 7)
        for prefix, call in [(b"", b"\xff\xd0"), (lea, b"\xff\xd1"),
                             (lea + b"\x48\x89\xc8", b"\xff\xd0"), (lea + b"\xb4\x01", b"\xff\xd0"),
                             (lea + b"\x48\x89\xc1", b"\xff\xd1"), (lea[1:], b"\xff\xd0"),
                             (b"\x48\x8d\x01", b"\xff\xd0"), (lea + b"\x48\x90", b"\xff\xd0"),
                             (b"", b"\xff\x15\x00\x00\x00\x00")]:
            with self.subTest(prefix=prefix.hex(), call=call.hex()):
                self.check_site([(base, prefix + call + b"\xc3")], self.root + len(prefix), call,
                                opcode="CALL64m" if len(call) == 6 else "CALL64r")

        # Unresolvable calls take precedence over an invalid encoding in their continuation.
        for bad in (b"", b"\x48\x8d\x01", lea + b"\xb4\x00"):
            body = bad + b"\xff\xd0\x06"
            self.check_site([(base, body)], self.root + len(bad), b"\xff\xd0")

        # Both a branch directly to CALL and a branch into its padding bypass the producer.
        for offset in (7, 8):
            body = bytes([0x74, offset]) + lea + b"\x90\xff\xd0\xc3"
            self.check_site([(base, body)], self.root + 10, b"\xff\xd0")

        # This backedge is decoded after CALL. Only the final partition knows that the
        # register can arrive at the call without passing through the LEA again.
        body = lea + b"\x90\xff\xd0\x75\xfc\xc3"
        report = self.check_site([(base, body)], self.root + 8, b"\xff\xd0")
        self.assertEqual(report["context"]["block_rva"], hex(self.root + 8))

    def test_validation_and_stability(self):
        site = self.root + 7
        start = self.layout.file_offset(self.root)
        pdata = self.layout.directory(3)[0]
        for target, code in [(-1, "LIFT_INVALID_CALL_TARGET"), (pdata, "LIFT_INVALID_CALL_TARGET"),
                             (self.root + 2, "LIFT_INVALID_CALL_TARGET"),
                             (self.shared + 2, "LIFT_UNSUPPORTED_CONTROL_FLOW")]:
            with self.subTest(target=target):
                body = b"\x48\x8d\x05" + struct.pack("<i", target - site) + b"\xff\xd0\xc3"
                self.check_site([(start, body)], site, b"\xff\xd0", code=code, target=target)

        helper_record = self.records[self.shared]
        # Overlap the helper with the next recorded function, leaving the caller eligible.
        self.check_site([(helper_record + 4, struct.pack("<I", self.recursive + 1))],
                        self.root + 26, b"\xff\xd0", code="LIFT_INVALID_CALL_TARGET", target=self.shared)
        self.check_site([(self.layout.directories + 12*8, struct.pack("<II", self.root + 20, 4))],
                        self.root + 26, b"\xff\xd0", target=self.shared)
        headers = self.layout.opt + struct.unpack_from("<H", self.original, self.layout.pe + 20)[0]
        self.assertEqual(self.original[headers:headers+5], b".text")
        flags = headers + 36
        self.check_site([(flags, struct.pack("<I", self.layout.u32(flags) | 0x80000000))],
                        self.root + 26, b"\xff\xd0", target=self.shared)
        self.check_site([(self.layout.file_offset(self.leaf), b"\x50\xc3")],
                        self.root + 61, bytes.fromhex("41 ff d2"), target=self.leaf)
        # Unknown transfer in a nested recorded callee retains the callee's own instruction.
        self.check_site([(self.layout.file_offset(self.shared), b"\xff\xd0\xc3")],
                        self.shared, b"\xff\xd0", owner=self.shared)

    def test_loader_writes_in_called_bodies(self):
        tls_index = self.layout.file_offset(self.layout.directory(9)[0]) + 16
        # Align the loader's four-byte TLS index with the entire MOV immediate.
        padding = (-(self.shared + 1)) % 4
        helper = b"\x90" * padding + bytes.fromhex("b8 0d 00 00 00 c3")
        witness = self.shared + padding + 1
        edits = [(self.layout.file_offset(self.shared), helper),
                 (tls_index, struct.pack("<Q", self.image_base + witness))]
        for sequence in (("direct",), ("register",), ("direct", "register"), ("register", "direct")):
            with self.subTest(sequence=sequence):
                body = bytearray()
                sites = []
                for kind in sequence:
                    if kind == "register":
                        after = self.root + len(body) + 7
                        body.extend(b"\x48\x8d\x05" + struct.pack("<i", self.shared - after))
                        call, opcode = b"\xff\xd0", "CALL64r"
                    else:
                        after = self.root + len(body) + 5
                        call, opcode = b"\xe8" + struct.pack("<i", self.shared - after), "CALL64pcrel32"
                    sites.append((self.root + len(body), call, opcode))
                    body.extend(call)
                site, call, opcode = sites[0]
                report = self.check_site([*edits, (self.layout.file_offset(self.root), body + b"\xc3")],
                                         site, call, opcode=opcode, target=self.shared)
                self.assertIn(f"loader-written bytes at {witness:#x}", report["message"])

    def test_recorded_root_extent(self):
        tls_index = self.layout.file_offset(self.layout.directory(9)[0]) + 16
        end = self.layout.u32(self.records[self.root] + 4)
        start = self.layout.file_offset(self.root)
        leaf = bytes.fromhex("b8 0d 00 00 00 c3")
        recurse = bytes.fromhex("e8 fb ff ff ff c3")
        for slot, witness in [(self.root - 2, self.root), (self.root + 1, self.root + 1), (end - 1, end - 1)]:
            with self.subTest(slot=slot):
                report = self.diagnostic([(start, leaf), (tls_index, struct.pack("<Q", self.image_base + slot))])
                where = report["context"]
                self.assertEqual((report["code"], where["entry_rva"], where["end_rva"], where["file_offset"]),
                                 ("LIFT_IMAGE_MEMORY", hex(self.root), hex(end), start))
                self.assertIn(f"loader-written bytes at {witness:#x}", report["message"])

        self.check_site([(start, recurse), (tls_index, struct.pack("<Q", self.image_base + end - 1))],
                        self.root, recurse[:5], opcode="CALL64pcrel32", target=self.root)
        data = bytearray(self.original)
        data[start:start+len(leaf)] = leaf
        struct.pack_into("<Q", data, tls_index, self.image_base + end)
        image = self.work / "neighbor.exe"
        image.write_bytes(data)
        run(FORGE, "lift", image, "--rva", hex(self.root), "--signature", "i64(i64,i64)",
            "--output", self.work / "neighbor.ll")

    def test_malformed_loader_metadata(self):
        # Half of an IAT directory cannot establish the loader's write footprint.
        start = self.layout.file_offset(self.root)
        call = b"\xe8" + struct.pack("<i", self.shared - self.root - 5)
        report = self.diagnostic([(start, call + b"\xc3"),
                                  (self.layout.directories + 12*8, struct.pack("<II", self.shared, 0))])
        self.assertEqual((report["stage"], report["code"]), ("pe", "INVALID_PE"))
        self.assertIn("incomplete import address table", report["message"])
        self.assertNotIn("block_rva", report["context"])

    def test_register_call_encodings(self):
        image = self.work / "edited.exe"
        start = self.layout.file_offset(self.root)
        ir = self.work / "encodings" / "lift.ll"
        ir.parent.mkdir(exist_ok=True)
        for prefix in ("f3", "3e", "66", "41 41"):
            with self.subTest(prefix=prefix):
                call = bytes.fromhex(prefix + " ff d0")
                self.check_site([(start, call + b"\xc3")], self.root, call, code="LIFT_UNSUPPORTED_PREFIX")
                selected = diff.analyze(FORGE, image, "call_indirect", self.work)
                with self.assertRaisesRegex(diff.Unsupported, "LIFT_UNSUPPORTED_PREFIX"):
                    diff.lift(FORGE, image, {"signature": "i64(i64,i64)"}, selected, ir)

        for reg, lea, call in [("RAX", "d5 08 8d 05", "d5 00 ff d0"),
                               ("RAX", "40 d5 08 8d 05", "40 d5 00 ff d0"),
                               ("R16", "d5 48 8d 05", "d5 10 ff d0")]:
            with self.subTest(reg=reg):
                target = -1 if reg == "RAX" else self.shared
                site = self.root + len(bytes.fromhex(lea)) + 4
                producer = bytes.fromhex(lea) + struct.pack("<i", target - site)
                encoded = bytes.fromhex(call)
                code = "LIFT_INVALID_CALL_TARGET" if reg == "RAX" else "LIFT_UNSUPPORTED_CONTROL_FLOW"
                self.check_site([(start, producer + encoded + b"\xc3")], site, encoded,
                                code=code, target=target)
                selected = diff.analyze(FORGE, image, "call_indirect", self.work)
                with self.assertRaisesRegex(ValueError, "lifting/" + code):
                    diff.lift(FORGE, image, {"signature": "i64(i64,i64)"}, selected, ir)

        # A modeled REX2 call also executes, and the independent walk agrees on its callee.
        data = bytearray(self.original)
        code = bytes.fromhex("48 83 ec 28 d5 08 8d 05") + struct.pack("<i", self.shared - self.root - 12)
        code += bytes.fromhex("d5 00 ff d0 48 83 c4 28 c3")
        data[start:start+len(code)] = code
        image.write_bytes(data)
        selected = diff.analyze(FORGE, image, "call_indirect", self.work)
        module = diff.read_json(self.work / "inspect.json")["modules"][0]
        self.assertEqual(diff.verified_call_target(image, module, selected, self.root + 12, FORGE,
                                                   require_continuation=True), self.shared)
        diff.lift(FORGE, image, {"signature": "i64(i64,i64)"}, selected, ir)
        for exe in self.compile_variants(ir):
            self.expect(exe, 7, 2, self.image_base + self.shared)

    def test_independent_diagnostic_evidence(self):
        image = self.work / "reported.exe"
        data = bytearray(self.original)
        data[self.layout.file_offset(self.leaf):self.layout.file_offset(self.leaf)+2] = b"\x0f\x0b"
        image.write_bytes(data)
        selected = diff.analyze(FORGE, image, "call_indirect", self.work)
        module = diff.read_json(self.work / "inspect.json")["modules"][0]
        analysis = diff.read_json(self.work / "analysis.json")
        ir = self.work / "verified" / "lift.ll"
        ir.parent.mkdir(exist_ok=True)
        with self.assertRaisesRegex(diff.Unsupported, "LIFT_UNSUPPORTED_INSTRUCTION"):
            diff.lift(FORGE, image, {"signature": "i64(i64,i64)"}, selected, ir)
        # A trap in the continuation ends only that path in the independent caller walk.
        continuation = self.layout.file_offset(self.root + 64)
        data[continuation:continuation+3] = b"\x0f\x0b\xc3"
        image.write_bytes(data)
        with self.assertRaisesRegex(diff.Unsupported, "LIFT_UNSUPPORTED_INSTRUCTION"):
            diff.lift(FORGE, image, {"signature": "i64(i64,i64)"}, selected, ir)
        diagnostic = diff.read_json(self.work / "lifting.log")["context"]
        self.assertEqual((diagnostic["function_rva"], diagnostic["instruction_rva"],
                          diagnostic["call_site_rva"]), (hex(self.leaf), hex(self.leaf), hex(self.root + 61)))
        with self.assertRaisesRegex(ValueError, "CALL evidence|register call evidence"):
            diff.resolve_leaf_window(module, analysis, image, self.leaf + 1, self.root, self.root + 61, FORGE)
        # Preserve the CALL bytes, but redirect the earlier conditional to bypass the second LEA.
        data[self.layout.file_offset(self.root + 29)] = 11
        image.write_bytes(data)
        with self.assertRaisesRegex(ValueError, "unproven register call"):
            diff.verified_call_target(image, module, selected, self.root + 41, FORGE, require_continuation=False)

        # An invalid proven target is checked independently from the reported displacement.
        target = -1
        body = b"\x48\x8d\x05" + struct.pack("<i", target - self.root - 7) + b"\xff\xd0\xc3"
        changed = bytearray(self.original)
        start = self.layout.file_offset(self.root)
        changed[start:start+len(body)] = body
        image.write_bytes(changed)
        with self.assertRaisesRegex(ValueError, "lifting/LIFT_INVALID_CALL_TARGET"):
            diff.lift(FORGE, image, {"signature": "i64(i64,i64)"}, selected, ir)
        forged = diff.read_json(self.work / "lifting.log")
        forged["context"]["branch_target"] = target + 1
        with self.assertRaisesRegex(ValueError, "disagrees with the reachable RIP-relative LEA"):
            diff.parse_diagnostic((json.dumps(forged) + "\n").encode(), image, selected, ir,
                                  register_target=lambda owner, site: diff.verified_call_target(
                                      image, module, owner, site, FORGE, require_continuation=False))


if __name__ == "__main__":
    if (platform.system(), platform.machine()) != ("Darwin", "arm64"):
        sys.exit(77)
    unittest.main(argv=[sys.argv[0]])
