"""Check guest image mapping and faults on both native compilation paths."""
import json
from pathlib import Path
import platform
import struct
import subprocess
import sys
import unittest

from pe_layout import Layout
from test_stack import BASE, FORGE, GuestExecution, IMAGE, MASK, RSP, initial_slots, run


class ImageTests(GuestExecution):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        module = json.loads(run(FORGE, "inspect", IMAGE, "--format", "json"))["modules"][0]
        cls.base = int(module["image_base_va"], 16)
        cls.sections = {s["name"]: s for s in module["sections"]}

    def va(self, section):
        return self.base + int(self.sections[section]["rva"], 16)

    def edit(self, name, edit):
        binary = bytearray(Path(IMAGE).read_bytes())
        layout = Layout(binary)
        table = layout.opt + struct.unpack_from("<H", binary, layout.pe + 20)[0]
        headers = {bytes(binary[p:p+8]).rstrip(b"\0").decode(): p
                   for p in range(table, table + len(layout.sections)*40, 40)}
        edit(binary, layout, headers)
        path = self.work / (name + ".exe")
        path.write_bytes(binary)
        return path

    def reject(self, leaf, reason, image=IMAGE, code="LIFT_IMAGE_MEMORY"):
        output = self.work / "rejected.ll"
        output.write_bytes(b"sentinel")
        proc = subprocess.run([FORGE, "lift", image, "--rva", hex(self.exports[leaf]), "--signature",
                               "i64(i64,i64)", "--diagnostics-format", "json", "--output", output],
                              capture_output=True, timeout=10)
        self.assertEqual((proc.returncode, proc.stdout), (1, b""))
        diagnostic = json.loads(proc.stderr)
        self.assertEqual(diagnostic["code"], code, diagnostic)
        self.assertIn(reason, diagnostic["message"])
        if code.startswith("LIFT_"):
            self.assertIn("instruction_rva", diagnostic["context"])
            self.assertIn("bytes", diagnostic["context"])
        self.assertEqual(output.read_bytes(), b"sentinel")

    def test_fixed(self):
        addr = self.va(".literal")
        for name, expected in (("lea32", addr & 0xffffffff), ("address_only", addr + 0x100000),
                               ("direct32", 0x9a785634), ("direct_rx", 0x7281),
                               ("high_byte", 0x12345678 + 0x3412)):
            for exe in self.variants(name):
                self.expect(exe, 0, 0x12340078, expected)
        for exe in self.variants("image_flags"):
            self.expect(exe, 3, 4, 0x3413)
            self.expect(exe, 4, 3, 0x3412)
        self.reject("bad_write", "immutable")
        self.reject("bad_end", "unsupported image access")
        self.reject("bad_relocation", "relocation")

    def test_dynamic(self):
        addr = self.va(".literal")
        for exe in self.variants("load32"):
            self.expect(exe, addr, 0, 0x78563412)
            self.expect(exe, addr+4, 0, 0xf0debc9a)
            for bad in (addr-1, addr+5, addr+8, addr+15, addr+16, MASK-1,
                        self.va(".mutable"), self.va(".pool")):
                self.trap(exe, [(bad, 0)])
        for exe in self.variants("update"):
            self.trap(exe, [(addr, 0)])
        for exe in self.variants("write32"):
            self.trap(exe, [(addr, 73)])
        for exe in self.variants("select_rx"):
            self.expect(exe, 2, 0, 0x5463)
            self.trap(exe, [(3, 0)])

    def test_unused_read_still_faults_on_its_path(self):
        for exe in self.variants("maybe_read"):
            self.expect(exe, 0, MASK, 0)
            self.expect(exe, 1, self.va(".literal"), 0)
            self.trap(exe, [(1, MASK)])

    def test_register_state(self):
        for exe in self.variants("direct32", state=True):
            expected = bytearray()
            for invocation in range(2):
                slots = initial_slots(invocation)
                slots[0] = 0x9a785634
                expected.extend(struct.pack("<I7QI", 0x01234567, *slots, 0x89abcdef))
            self.assertEqual(run(exe), expected)

    def test_virtual_tail(self):
        def extend(data, layout, headers):
            header = headers[".literal"]
            raw = layout.u32(header + 16)
            struct.pack_into("<I", data, header+8, raw+8)
            data[layout.u32(header+20)+raw-2:layout.u32(header+20)+raw] = b"\x23\x81"
        image = self.edit("virtual", extend)
        tail = self.va(".literal") + self.sections[".literal"]["raw_size"]
        for exe in self.variants("load32", image=image):
            self.expect(exe, tail-2, 0, 0x8123)
            self.expect(exe, tail+4, 0, 0)
            self.trap(exe, [(tail+5, 0)])

    def test_zero_only_section(self):
        def zero(data, layout, headers):
            struct.pack_into("<II", data, headers[".literal"] + 16, 0, 0)
        image = self.edit("zero", zero)
        for exe in self.variants("direct32", image=image):
            self.expect(exe, 0, 0, 0)

    def test_loader_written_bytes(self):
        addr = self.va(".literal")
        def iat(data, layout, headers):
            struct.pack_into("<II", data, layout.directories + 8*12, addr - self.base + 4, 4)
        image = self.edit("iat", iat)
        self.reject("direct32", "loader-written", image)
        for exe in self.variants("load32", image=image):
            self.expect(exe, addr, 0, 0x78563412)
            self.trap(exe, [(addr+1, 0)])
        # Omit the aggregate IAT. A descriptor still names eight bytes filled by the loader.
        def descriptor(data, layout, headers):
            rva = addr - self.base
            pos = layout.u32(headers[".literal"]+20)
            struct.pack_into("<I", data, headers[".literal"]+8, 256)
            struct.pack_into("<II", data, layout.directories+8, rva+32, 40)
            struct.pack_into("<5I", data, pos+32, rva+96, 0, 0, rva+128, rva)
            struct.pack_into("<QQ", data, pos+96, (1 << 63) | 1, 0)
            data[pos+128:pos+134] = b"x.dll\0"
        self.reject("direct32", "loader-written", self.edit("iat-descriptor", descriptor))

    def test_guard_slots(self):
        addr = self.va(".literal")
        # A load config in unused raw storage points at a slot without a base relocation.
        def config(field, size, va):
            def edit(data, layout, headers):
                h = headers[".literal"]
                pos, rva = layout.u32(h+20)+64, layout.u32(h+12)+64
                struct.pack_into("<I", data, h+8, 256)
                struct.pack_into("<II", data, layout.directories+8*10, rva, 152)
                struct.pack_into("<I", data, pos, size)
                struct.pack_into("<Q", data, pos+field, va)
            return self.edit("guard", edit)

        for field in (112, 120):
            image = config(field, field+8, addr)
            self.reject("direct32", "loader-written", image)
            for exe in self.variants("load32", image=image):
                self.trap(exe, [(addr, 0)])
                self.trap(exe, [(addr+7, 0)])
                self.expect(exe, addr+16, 0, 0)
            # Put the slot after the fixture's unrelated relocation so both
            # immediately neighboring doublewords are independently readable.
            for exe in self.variants("load32", image=config(field, field+8, addr+24)):
                self.expect(exe, addr+20, 0, 0)
                self.trap(exe, [(addr+21, 0)])
                self.expect(exe, addr+32, 0, 0)
            for exe in self.variants("direct32", image=config(field, field+4, addr)):
                self.expect(exe, 0, 0, 0x9a785634)
        self.reject("direct32", "guard slot", config(112, 120, addr-1), "INVALID_PE")
        self.reject("direct32", "guard slot", config(120, 128, addr+252), "INVALID_PE")
        for exe in self.variants("direct32", image=config(112, 120, 0)):
            self.expect(exe, 0, 0, 0x9a785634)

    def test_import_thunk_virtual_extent(self):
        def descriptor(delayed, terminator, extent):
            def edit(data, layout, headers):
                h = headers[".literal"]
                raw, pos, rva = layout.u32(h+16), layout.u32(h+20), layout.u32(h+12)
                stub = raw + terminator - 8
                struct.pack_into("<I", data, h+8, raw+extent)
                if delayed:
                    struct.pack_into("<II", data, layout.directories+8*13, rva+32, 64)
                    struct.pack_into("<8I", data, pos+32, 1, rva+128, rva+192, rva+160, rva+stub, 0, 0, 0)
                else:
                    struct.pack_into("<II", data, layout.directories+8, rva+32, 40)
                    struct.pack_into("<5I", data, pos+32, rva+stub, 0, 0, rva+128, rva+160)
                data[pos+128:pos+134] = b"x.dll\0"
                struct.pack_into("<Q", data, pos+stub, (1 << 63) | 1)
                struct.pack_into("<Q", data, pos+160, (1 << 63) | 1)
            return self.edit("thunks", edit)

        for delayed in (False, True):
            for offset in (-8, -4, 0):
                image = descriptor(delayed, offset, 8)
                module = json.loads(run(FORGE, "inspect", image, "--format", "json"))["modules"][0]
                self.assertEqual(module["imports"][0]["symbols"], [{"ordinal": 1}])
                for exe in self.variants("direct32", image=image):
                    self.expect(exe, 0, 0, 0x9a785634)
            image = descriptor(delayed, 0, 7)
            inspect = subprocess.run([FORGE, "inspect", image], capture_output=True, timeout=10)
            self.assertNotEqual(inspect.returncode, 0)
            self.assertIn(b"virtual section", inspect.stderr)
            self.reject("direct32", "virtual section", image, "INVALID_PE")

    def test_stack_origins(self):
        addr = self.va(".literal")
        for name in ("mixed_join", "loop_pointer"):
            for exe in self.variants(name):
                self.expect(exe, 0, 19, 19)
                self.expect(exe, addr, 19, 0x78563412)
        for name in ("new_rsp", "lost_origin"):
            for exe in self.variants(name):
                self.expect(exe, addr, 0, 0x78563412)
        for exe in self.variants("different_offsets"):
            self.expect(exe, 0, 17, 17)
            self.expect(exe, 1, 17, 1)
        for exe in self.variants("stack_fault"):
            self.trap(exe, [(0, 0)])

    def test_provenance_keeps_runtime_bounds(self):
        addr = self.va(".literal")
        def distance(data, layout, headers):
            pos = layout.file_offset(self.exports["escape_stack"]) + 2
            self.assertEqual(struct.unpack_from("<Q", data, pos)[0], 0x123456789abcdef0)
            struct.pack_into("<Q", data, pos, addr - RSP)
        for exe in self.variants("escape_stack", image=self.edit("distance", distance)):
            self.expect(exe, addr, 0, 0x78563412)
            self.trap(exe, [(addr, 1)])

    def test_mapping_limits_and_permissions(self):
        def large(data, layout, headers):
            # Move the last executable pool into an empty RVA range and retarget
            # the RIP displacement of the selected export to it.
            new_rva = 0x100000
            header = headers[".pool"]
            struct.pack_into("<II", data, header+8, 8*1024*1024+1, new_rva)
            struct.pack_into("<I", data, layout.opt+56, 0xb00000)
            for name, length, offset in (("select_rx", 7, 3), ("direct_rx", 7, 3)):
                rva = self.exports[name]
                struct.pack_into("<i", data, layout.file_offset(rva)+offset, new_rva-rva-length)
        image = self.edit("large", large)
        self.reject("select_rx", "exceeds image mapping limit", image)
        for exe in self.variants("direct_rx", image=image):
            self.expect(exe, 0, 0, 0x7281)
        def budget(data, layout, headers):
            header = headers[".literal"]
            struct.pack_into("<II", data, header+8, 32*1024*1024+1, 0x100000)
            struct.pack_into("<I", data, layout.opt+56, 0x2200000)
        large = self.edit("budget", budget)
        self.reject("load32", "exceeds module limit", large)
        self.reject("different_offsets", "exceeds module limit", large)
        for exe in self.variants("frame_join", image=large):
            self.expect(exe, 0, 71, 71)
            self.expect(exe, 1, 72, 72)
        def aliases(data, layout, headers):
            struct.pack_into("<I", data, headers[".pool"]+20, layout.u32(headers[".literal"]+20))
        self.reject("load32", "overlaps another section", self.edit("raw-overlap", aliases), "INVALID_PE")
        def protect(data, layout, headers):
            p = headers[".literal"] + 36
            struct.pack_into("<I", data, p, layout.u32(p) & ~0x40000000)
        self.reject("direct32", "unsupported image access", self.edit("unreadable", protect))
        def overlap(data, layout, headers):
            struct.pack_into("<I", data, headers[".literal"]+12, layout.u32(headers[".text"]+12))
        self.reject("direct32", "overlaps another section", self.edit("overlap", overlap), "INVALID_PE")
        def wrap(data, layout, headers):
            struct.pack_into("<Q", data, layout.opt+24, MASK-4096)
        self.reject("direct32", "overflow", self.edit("overflow", wrap), "INVALID_PE")
        def collision(data, layout, headers):
            struct.pack_into("<Q", data, layout.opt+24, BASE-layout.u32(headers[".literal"]+12))
        image = self.edit("collision", collision)
        for leaf in ("load32", "implicit_push", "implicit_pop", "implicit_leave"):
            self.reject(leaf, "overlaps the guest stack", image)

    def test_overrides(self):
        for prefix in (0x64, 0x67):
            def override(data, layout, headers):
                pos = layout.file_offset(self.exports["direct32"])
                data[pos:pos+7] = bytes([prefix, 0x8b, 0x05, 0, 0, 0, 0])
            self.reject("direct32", "prefix", self.edit(f"prefix-{prefix}", override), "LIFT_UNSUPPORTED_PREFIX")


if __name__ == "__main__":
    if (platform.system(), platform.machine()) != ("Darwin", "arm64"):
        sys.exit(77)
    unittest.main(argv=[sys.argv[0]])
