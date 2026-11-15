"""Check guest image mapping and faults on both native compilation paths."""
import json
import os
from pathlib import Path
import platform
import struct
import subprocess
import sys
import unittest

from image_scaling import ImageScaling, image_stats
from pe_layout import Layout
from test_stack import BASE, FORGE, GuestExecution, IMAGE, LINKER, MASK, RSP, initial_slots, run


def relocation_block(layout, page):
    rva, size = layout.directory(5)
    start = layout.file_offset(rva)
    pos = start
    while pos < start + size:
        if layout.u32(pos) == page:
            return pos
        pos += layout.u32(pos + 4)
    raise ValueError(f"missing relocation block for page {page:x}")


class ImageTests(ImageScaling, GuestExecution):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        module = json.loads(run(FORGE, "inspect", IMAGE, "--format", "json"))["modules"][0]
        cls.base = int(module["image_base_va"], 16)
        cls.sections = {s["name"]: s for s in module["sections"]}

    def va(self, section):
        return self.base + int(self.sections[section]["rva"], 16)

    def rebased_command(self, name, base, image):
        return [os.environ["FORGE_TEST_LIFT_CONTRACT"], "--emit-rebased", image,
                hex(self.exports[name]), hex(base)]

    def rebased(self, name, base, image=IMAGE):
        ir = self.work / f"{name}-rebased.ll"
        command = self.rebased_command(name, base, image)
        ir.write_bytes(run(*command))
        self.assertEqual(run(*command), ir.read_bytes())
        return self.compile_variants(ir)

    def sequence(self, exe, pairs, expected):
        inputs = "".join(f"{a & MASK:x} {b & MASK:x}\n" for a, b in pairs).encode()
        outputs = "".join(f"{value & MASK:x}\n" for value in expected).encode()
        self.assertEqual(run(exe, input=inputs), outputs)

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
        for exe in self.variants("partial_relocation"):
            self.expect(exe, 0, 0, (addr << 8 | 0xf0) & 0xffffffff)

    def test_dynamic(self):
        addr = self.va(".literal")
        for exe in self.variants("load32"):
            self.expect(exe, addr, 0, 0x78563412)
            self.expect(exe, addr+4, 0, 0xf0debc9a)
            self.expect(exe, addr+8, 0, addr & 0xffffffff)
            self.expect(exe, self.va(".mutable"), 0, 0x1234)
            for bad in (addr-1, addr+15, addr+16, MASK-1, self.va(".pool")):
                self.trap(exe, [(bad, 0)])
        for exe in self.variants("update"):
            self.trap(exe, [(addr, 0)])
        for exe in self.variants("write32"):
            self.expect(exe, self.va(".mutable"), 73, 73)
            self.trap(exe, [(addr, 73)])
            self.trap(exe, [(self.va(".pool"), 73)])
        for exe in self.variants("select_rx"):
            self.expect(exe, 2, 0, 0x5463)
            self.trap(exe, [(3, 0)])

    def test_unused_read_still_faults_on_its_path(self):
        for exe in self.variants("maybe_read"):
            self.expect(exe, 0, MASK, 0)
            self.expect(exe, 1, self.va(".literal"), 0)
            self.trap(exe, [(1, MASK)])
        for exe in self.variants("maybe_write"):
            self.expect(exe, MASK, 0, 0)
            self.expect(exe, self.va(".mutable"), 1, 0)
            self.trap(exe, [(MASK, 1)])

    def test_register_state(self):
        for exe in self.variants("direct32", state=True):
            expected = bytearray()
            for invocation in range(2):
                slots = initial_slots(invocation)
                slots[0] = 0x9a785634
                expected.extend(struct.pack("<I7QI", 0x01234567, *slots, 0x89abcdef))
            self.assertEqual(run(exe), expected)
        for exe in self.variants("increment_counter", state=True):
            expected = bytearray()
            for invocation in range(2):
                slots = initial_slots(invocation)
                slots[0] = 0x1235 + invocation
                expected.extend(struct.pack("<I7QI", 0x01234567, *slots, 0x89abcdef))
            self.assertEqual(run(exe), expected)

    def test_ctor_order(self):
        # A mixed initialized/zero-filled section needs the compact module initializer.
        def add_tail(data, layout, headers):
            header = headers[".mutable"]
            struct.pack_into("<I", data, header+8, layout.u32(header+16)+8)
        image = self.edit("constructor-order", add_tail)
        host = self.work / "early-caller.o"
        source = b"""
extern "C" int printf(const char *, ...);
extern "C" long long forge_lifted(long long, long long);
static const long long first = forge_lifted(0, 0);
int main() { printf("%lld %lld\\n", first, forge_lifted(0, 0)); }
"""
        run(*LINKER, "-x", "c++", "-", "-c", "-o", host, input=source)
        for variant in self.variants("increment_counter", image=image):
            lifted = variant.with_suffix(".o")
            for host_first in (True, False):
                with self.subTest(variant=variant.name, host_first=host_first):
                    objects = (host, lifted) if host_first else (lifted, host)
                    exe = self.work / "early-caller"
                    run(*LINKER, *objects, "-o", exe)
                    self.assertEqual(run(exe), b"4661 4662\n")

    def test_rebased_alias(self):
        storage = self.va(".mutable")
        literal = self.va(".literal")
        for delta in (0, 0x32100000, -0x21000000):
            base = self.base + delta
            for exe in self.rebased("pointer_va", base):
                self.expect(exe, 0, 0, storage + delta)
            for exe in self.rebased("partial_relocation", base):
                self.expect(exe, 0, 0, ((literal + delta) << 8 | 0xf0) & 0xffffffff)
            for exe in self.rebased("update_alias", base):
                for _ in range(2):
                    self.sequence(exe, [(0, 0), (5, 0), (-1, 0)], [0x1234, 0x1239, 0x1238])
        for base, message in ((MASK - 4096, "overflow"),
                              (BASE - int(self.sections[".mutable"]["rva"], 16), "overlap")):
            proc = subprocess.run(self.rebased_command("update_alias", base, IMAGE),
                                  capture_output=True, timeout=10)
            self.assertNotEqual(proc.returncode, 0)
            self.assertIn(message, proc.stderr.decode())

    def test_stripped_relocations(self):
        image = Path(IMAGE).with_name("image-fixed.exe")
        layout = Layout(image.read_bytes())
        characteristics = struct.unpack_from("<H", layout.data, layout.pe + 22)[0]
        self.assertTrue(characteristics & 1)  # IMAGE_FILE_RELOCS_STRIPPED
        self.assertEqual(layout.directory(5), (0, 0))

        for variants in (self.variants("pointer_va", image=image),
                         self.rebased("pointer_va", self.base, image)):
            for exe in variants:
                self.expect(exe, 0, 0, self.va(".mutable"))

        selected = self.base + 0x10000000
        proc = subprocess.run(self.rebased_command("pointer_va", selected, image),
                              capture_output=True, timeout=10)
        self.assertEqual((proc.returncode, proc.stdout), (1, b""))
        for detail in ("LIFT_IMAGE_MEMORY", "stripped", hex(selected), hex(self.base)):
            self.assertIn(detail, proc.stderr.decode())

    def test_opaque_store(self):
        for exe in self.variants("opaque_store"):
            self.expect(exe, RSP + 8, 0, 0)
            self.trap(exe, [(self.va(".mutable"), 0)])

    def test_relocation_boundaries(self):
        page = int(self.sections[".mutable"]["rva"], 16)
        def misalign(data, layout, headers):
            rva, size = layout.directory(5)
            pos = layout.file_offset(rva)
            data[pos+2:pos+2+size] = data[pos:pos+size]
            struct.pack_into("<I", data, headers[".reloc"]+8, size+2)
            struct.pack_into("<I", data, layout.directories+8*5, rva+2)
        self.reject("pointer_va", "misaligned", self.edit("unaligned-block", misalign), "INVALID_PE")
        def records(first, second=0):
            def edit(data, layout, headers):
                pos = relocation_block(layout, page)
                self.assertEqual(layout.u32(pos+4), 12)
                struct.pack_into("<HH", data, pos+8, first, second)
            return self.edit("relocation", edit)

        for first, second in ((0xa008, 0xa008), (0xa008, 0xa004), (0xa008, 0x3009)):
            self.reject("pointer_va", "overlap", records(first, second), "INVALID_PE")
        for target in (12, 0x100):
            self.reject("pointer_va", "relocation", records(0xa000 + target), "INVALID_PE")
        image = records(0x3008)
        self.reject("pointer_va", "relocation", image)
        for exe in self.variants("exchange_byte", image=image):
            self.expect(exe, self.base+page, 0, 0x34)
            self.trap(exe, [(self.base+page+8, 0)])
        # Padding may name the same RVA as a real field.
        for exe in self.variants("pointer_va", image=records(0xa008, 8)):
            self.expect(exe, 0, 0, self.base + page)

        def unrelated(data, layout, headers):
            pos = relocation_block(layout, layout.u32(headers[".literal"]+12))
            struct.pack_into("<H", data, pos+10, 0xa008)
        image = self.edit("unselected-fixups", unrelated)
        for exe in self.variants("direct32", image=image):
            self.expect(exe, 0, 0, 0x9a785634)
        self.reject("partial_relocation", "overlap", image, "INVALID_PE")
        def discarded(data, layout, headers):
            unrelated(data, layout, headers)
            pos = relocation_block(layout, layout.u32(headers[".literal"]+12))
            struct.pack_into("<I", data, pos, layout.u32(headers[".reloc"]+12))
        for exe in self.variants("load32", image=self.edit("discarded-fixups", discarded)):
            self.expect(exe, self.va(".literal"), 0, 0x78563412)

    def test_local_relocation_conflict(self):
        addr = self.va(".mutable")

        def conflict(data, layout, headers):
            header = headers[".mutable"]
            # The counter at +0 and a valid pointer at +16 surround a duplicate fixup at +8.
            struct.pack_into("<I", data, header + 8, 24)
            struct.pack_into("<Q", data, layout.u32(header + 20) + 16, addr)
            rva, size = layout.directory(5)
            pos = relocation_block(layout, addr - self.base)
            self.assertEqual(pos + 12, layout.file_offset(rva) + size)
            struct.pack_into("<I4H", data, pos + 4, 16, 0xa008, 0xa008, 0xa010, 0)
            struct.pack_into("<I", data, headers[".reloc"] + 8, size + 4)
            struct.pack_into("<I", data, layout.directories + 8*5 + 4, size + 4)

        image = self.edit("local-relocation-conflict", conflict)
        self.reject("pointer_va", "overlap", image, "INVALID_PE")
        for exe in self.variants("increment_counter", image=image):
            self.sequence(exe, [(0, 0)] * 3, [0x1235, 0x1236, 0x1237])

        delta = 0x10000000
        for exe in self.rebased("load64", self.base + delta, image):
            self.expect(exe, addr + delta, 0, 0x1234)
            self.expect(exe, addr + delta + 16, 0, addr + delta)
        for exe in self.variants("maybe_read", image=image):
            for bad in (addr + 7, addr + 8, addr + 15):
                self.expect(exe, 0, bad, 0)
                self.trap(exe, [(1, bad)])
        for exe in self.variants("maybe_write", image=image):
            for bad in (addr + 7, addr + 8, addr + 15):
                self.expect(exe, bad, 0, 0)
                self.trap(exe, [(bad, 1)])

    def test_relocation_across_zero_tail(self):
        section = self.sections[".mutable"]
        page, raw = int(section["rva"], 16), section["raw_size"]
        def cross(data, layout, headers):
            header = headers[".mutable"]
            struct.pack_into("<I", data, header+8, raw+16)
            struct.pack_into("<I", data, layout.u32(header+20)+raw-4, 0xfffffffd)
            pos = relocation_block(layout, page)
            struct.pack_into("<HH", data, pos+8, 0xa000 + raw-4, 0xa000 + raw+8)
        image = self.edit("cross", cross)
        preferred = self.work / "cross-preferred.ll"
        preferred.write_bytes(run(*self.rebased_command("load64", self.base, image)))
        preferred_stats = image_stats(image, self.base, preferred)
        for delta in (0x10000000, -0x10000000):
            addr = self.base + delta + page + raw
            for exe in self.rebased("load64", self.base+delta, image):
                self.expect(exe, addr-4, 0, 0xfffffffd + delta)
                self.expect(exe, addr+8, 0, delta)
            original = 0xfffffffd + delta
            # Only the positive delta carries into the four tail bytes of the
            # straddling fixup. Both deltas materialize the second eight-byte fixup.
            ir = self.work / "load64-rebased.ll"
            stats = image_stats(image, self.base+delta, ir)
            for key in ("budgeted_initialized_bytes", "emitted_initializer_bytes"):
                self.assertEqual(stats[key], preferred_stats[key] + (12 if delta > 0 else 8))

            if delta > 0:
                # Omit the second tail write in a private copy of the raw module.
                source = ir.read_text()
                target = f"ptr @image_{page:x}, i64 {raw + 8})"
                stores = [line for line in source.splitlines()
                          if "store [8 x i8]" in line and target in line]
                self.assertEqual(len(stores), 1)
                omitted = self.work / "missing-tail-store.ll"
                omitted.write_text(source.replace(stores[0], ""))
                reduced = image_stats(image, self.base+delta, omitted)
                self.assertEqual(reduced["budgeted_initialized_bytes"], stats["budgeted_initialized_bytes"])
                self.assertEqual(reduced["emitted_initializer_bytes"], stats["emitted_initializer_bytes"] - 8)
                for exe in self.compile_variants(omitted):
                    self.expect(exe, addr-4, 0, original)
                    self.expect(exe, addr+8, 0, 0)

                redirected = self.work / "unexpected-tail-store.ll"
                changed = stores[0].replace(f"@image_{page:x}", "@scratch")
                redirected.write_text(source.replace(stores[0], changed) +
                                      f"\n@scratch = private global [{raw+16} x i8] zeroinitializer\n")
                with self.assertRaises(subprocess.CalledProcessError) as failure:
                    image_stats(image, self.base+delta, redirected)
                self.assertIn(b"unexpected image constructor destination", failure.exception.stderr)
            for exe in self.rebased("store_middle", self.base+delta, image):
                self.sequence(exe, [(addr-4, 0x9876), (addr-4, 0xcafe)],
                              [(original & ~(0xffff << 24)) | (word << 24)
                               for word in (0x9876, 0xcafe)])

    def test_zero_prefix_uses_no_explicit_initializer(self):
        raw = self.sections[".mutable"]["raw_size"]
        for zero in (False, True):
            def tail(data, layout, headers):
                header = headers[".mutable"]
                struct.pack_into("<I", data, header+8, raw+16)
                if zero:
                    start = layout.u32(header+20)
                    data[start:start+raw] = bytes(raw)
            image = self.edit(f"prefix-{zero}", tail)
            for exe in self.variants("increment_counter_reg", image=image):
                self.expect(exe, 0, 0, 1 if zero else 0x1235)
            stats = image_stats(image, self.base, self.work / "increment_counter_reg.ll")
            self.assertEqual(stats["selected_sections"], 1)
            self.assertEqual(stats["virtual_bytes"], raw + 16)
            self.assertEqual(stats["budgeted_initialized_bytes"], raw)
            self.assertEqual(stats["emitted_initializer_bytes"], 0 if zero else raw)

    def test_interval_ending_at_maximum_va(self):
        rva = 0x100000
        def highest(data, layout, headers):
            header = headers[".pool"]
            struct.pack_into("<II", data, header+8, 8, rva)
            struct.pack_into("<I", data, header+36, layout.u32(headers[".literal"]+36))
            struct.pack_into("<Q", data, layout.u32(header+20), 0x8877665544332211)
            struct.pack_into("<I", data, layout.opt+56, rva+0x1000)

        image = self.edit("highest", highest)
        for exe in self.rebased("load32", MASK-rva-7, image):
            self.expect(exe, MASK-3, 0, 0x88776655)
            self.trap(exe, [(MASK-2, 0)])
            self.trap(exe, [(0, 0)])

    def test_large_writable_virtual_extent(self):
        start = 0x100000
        def large(size):
            def edit(data, layout, headers):
                header = headers[".mutable"]
                pos = relocation_block(layout, layout.u32(header+12))
                struct.pack_into("<I", data, pos, start)
                struct.pack_into("<II", data, header+8, size, start)
                struct.pack_into("<I", data, layout.opt+56, start+size+0x1000)
            return self.edit("large-writable", edit)
        size = 100 * 1024 * 1024
        addr = self.base + start
        for exe in self.variants("exchange_byte", image=large(size)):
            self.sequence(exe, [(addr, 0), (addr+size-1, 0xab), (addr+size-1, 0)],
                          [0x34, 0, 0xab])
            self.trap(exe, [(addr+size, 0)])
            for suffix in (".ll", ".o"):
                self.assertLess(exe.with_suffix(suffix).stat().st_size, 1024*1024)
        self.reject("exchange_byte", "limit", large(256 * 1024 * 1024 + 1))

        def two_sections(data, layout, headers):
            half = 128 * 1024 * 1024
            header = headers[".mutable"]
            struct.pack_into("<I", data, relocation_block(layout, layout.u32(header+12)), start)
            struct.pack_into("<II", data, header+8, half, start)
            pool = headers[".pool"]
            struct.pack_into("<II", data, pool+8, half+1, start+half)
            struct.pack_into("<I", data, pool+36, layout.u32(header+36))
            struct.pack_into("<I", data, layout.opt+56, start+2*half+0x1000)
        self.reject("exchange_byte", "limit", self.edit("two-writable", two_sections))

        def raw_budget(data, layout, headers):
            size = 32 * 1024 * 1024 + 512
            header = headers[".mutable"]
            struct.pack_into("<I", data, relocation_block(layout, layout.u32(header+12)), start)
            struct.pack_into("<IIII", data, header+8, size, start, size, len(data))
            struct.pack_into("<I", data, layout.opt+56, start+size+0x1000)
            data.extend(bytes(size))
        self.reject("exchange_byte", "limit", self.edit("initialized-budget", raw_budget))

        def independent_budgets(data, layout, headers):
            size = 20 * 1024 * 1024
            ro, rw = headers[".literal"], headers[".mutable"]
            struct.pack_into("<I", data, relocation_block(layout, layout.u32(ro+12)), start)
            struct.pack_into("<I", data, relocation_block(layout, layout.u32(rw+12)), start+size)
            struct.pack_into("<IIII", data, ro+8, size, start, 0, 0)
            struct.pack_into("<IIII", data, rw+8, size, start+size, size, len(data))
            struct.pack_into("<I", data, layout.opt+56, start+2*size)
            data.extend(bytes(size))
        image = self.edit("independent-budgets", independent_budgets)
        run(FORGE, "lift", image, "--rva", hex(self.exports["load32"]), "--signature",
            "i64(i64,i64)", "--output", self.work/"budget.ll")

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
        writable = self.va(".mutable")
        def writable_iat(data, layout, headers):
            struct.pack_into("<II", data, layout.directories+8*12, writable-self.base+8, 8)
        image = self.edit("writable-iat", writable_iat)
        self.reject("pointer_va", "loader-written", image)
        for exe in self.variants("write32", image=image):
            self.expect(exe, writable+4, 73, 73)
            self.trap(exe, [(writable+5, 73)])
        def tls(data, layout, headers):
            header = headers[".literal"]
            page = layout.u32(header+12)
            struct.pack_into("<I", data, header+8, 128)
            struct.pack_into("<II", data, layout.directories+8*9, page+32, 40)
            struct.pack_into("<4Q2I", data, layout.u32(header+20)+32, 0, 0, writable, 0, 0, 0)
            struct.pack_into("<H", data, relocation_block(layout, page)+10, 0xa000+48)
        image = self.edit("tls-index", tls)
        self.reject("increment_counter", "loader-written", image)
        for exe in self.rebased("exchange_byte", self.base+0x1000000, image):
            self.trap(exe, [(writable+0x1000000, 0)])
            self.expect(exe, writable+0x1000004, 0, 0)
        for exe in self.rebased("load64", self.base+0x1000000, image):
            self.trap(exe, [(addr+0x1000000+48, 0)])
            self.expect(exe, addr+0x1000000+72, 0, 0)
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
        # The load configuration stores a preferred VA for the loader-seeded cookie.
        writable = self.va(".mutable")
        image = config(88, 96, writable)
        self.reject("increment_counter", "loader-written", image)
        for exe in self.variants("exchange_byte", image=image):
            self.trap(exe, [(writable+7, 0)])
            self.expect(exe, writable+8, 0, writable & 0xff)
        for exe in self.variants("increment_counter", image=config(88, 92, writable)):
            self.expect(exe, 0, 0, 0x1235)

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
                if offset == 0:
                    for exe in self.variants("load32", image=image):
                        self.trap(exe, [(self.va(".literal")+160, 0)])
                        if delayed:
                            self.trap(exe, [(self.va(".literal")+192, 0)])
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
        computed = ("reloaded_stack_va", "xor_zero_offset", "sub_zero_offset", "sub32_offset")
        def distance(data, layout, headers):
            for name in (*computed, "escape_stack", "joined_stack_va", "constant_sub_offset"):
                start = layout.file_offset(self.exports[name])
                pos = data.index(struct.pack("<Q", 0x123456789abcdef0), start, start + 32)
                struct.pack_into("<Q", data, pos, addr - RSP)
        image = self.edit("distance", distance)
        for exe in self.variants("escape_stack", image=image):
            self.expect(exe, addr, 0, 0x78563412)
            self.trap(exe, [(addr, 1)])
        for exe in self.variants("constant_sub_offset", image=image):
            self.trap(exe, [(0, 0)])
        for name in computed:
            for exe in self.variants(name, image=image):
                self.expect(exe, 0, 0, 0x78563412)
        for exe in self.variants("joined_stack_va", image=image):
            self.expect(exe, 0, 23, 23)
            self.expect(exe, 1, 23, 0x78563412)

    def test_spill_invalidation_and_widening(self):
        literal = self.va(".literal")
        writable = self.va(".mutable")
        for exe in self.variants("partial_spill"):
            self.expect(exe, (writable >> 8) & 0xff, 0, 0x1234)
        for exe in self.variants("spill_numeric_alias"):
            self.expect(exe, 0, 0, 0xf0debc9a)
        for exe in self.variants("indirect_spill_store"):
            self.expect(exe, RSP+8, literal+4, 0xf0debc9a)
            self.expect(exe, writable, 0, 0x78563412)
        for exe in self.variants("incomplete_spill_join"):
            self.expect(exe, 0, writable, 0x1234)
            self.expect(exe, 1, writable, 0x78563412)
        for exe in self.variants("walk_image"):
            self.expect(exe, writable - literal, 0, 0x1234)
            self.trap(exe, [(16, 0)])
        for exe in self.variants("wide_mask"):
            self.expect(exe, 8, 0, literal & 0xff)
            self.expect(exe, 1, 0, 0x34)

    def test_proven_image_addresses_select_only_referenced_data(self):
        def unused_writable(data, layout, headers):
            start, size = 0x100000, 257 * 1024 * 1024
            pool = headers[".pool"]
            struct.pack_into("<II", data, pool+8, size, start)
            struct.pack_into("<I", data, pool+36, layout.u32(headers[".mutable"]+36))
            struct.pack_into("<I", data, layout.opt+56, start+size)

        image = self.edit("unused-writable", unused_writable)
        for exe in self.rebased("low_image_offset", 0x10000000, image):
            self.expect(exe, 0, 0, 0x9a785634)
            self.expect(exe, 1, 0, 0xf0debc9a)
        stats = image_stats(image, 0x10000000, self.work / "low_image_offset-rebased.ll")
        self.assertEqual((stats["selected_sections"], stats["virtual_bytes"]), (1, 7))
        for exe in self.variants("choose_local_or_image", image=image):
            self.expect(exe, 0, 51, 51)
            self.expect(exe, 1, 51, 0x9a785634)
        for leaf in ("partial_spill", "incomplete_spill_join", "walk_image", "wide_mask"):
            self.reject(leaf, "writable virtual limit", image)
        for leaf in ("increment_counter", "increment_counter_reg"):
            for exe in self.variants(leaf, image=image):
                self.sequence(exe, [(0, 0), (0, 0)], [0x1235, 0x1236])

        self.reject("write32", "writable virtual limit", image)
        for exe in self.variants("maybe_write_literal", image=image):
            self.expect(exe, 0, 0, 0x12)
            self.trap(exe, [(1, 0)])

        # A register read of an executable literal still needs a RIP-relative LEA
        # selecting that section; a known address alone does not make code readable.
        def executable_read(data, layout, headers, selected):
            header = headers[".literal"]
            struct.pack_into("<I", data, header+36, layout.u32(headers[".pool"]+36))
            if not selected:
                entry = self.exports["maybe_write_literal"]
                pos = layout.file_offset(entry)
                self.assertEqual(data[pos:pos+3], b"\x4c\x8d\x05")
                # MOV r8, imm32 has the same length as the LEA; use a low guest base.
                addr = 0x10000000 + layout.u32(header+12)
                data[pos:pos+7] = b"\x49\xc7\xc0" + struct.pack("<I", addr)

        for selected in (False, True):
            image = self.edit("known-executable", lambda *args: executable_read(*args, selected))
            for exe in self.rebased("maybe_write_literal", 0x10000000, image):
                if selected:
                    self.expect(exe, 0, 0, 0x12)
                else:
                    self.trap(exe, [(0, 0)])

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
            struct.pack_into("<I", data, relocation_block(layout, layout.u32(header+12)), 0x100000)
            struct.pack_into("<II", data, header+8, 32*1024*1024+1, 0x100000)
            struct.pack_into("<I", data, layout.opt+56, 0x2200000)
        large = self.edit("budget", budget)
        self.reject("load32", "exceeds module limit", large)
        for exe in self.variants("different_offsets", image=large):
            self.expect(exe, 0, 17, 17)
            self.expect(exe, 1, 17, 1)
        self.assertNotIn(b"@image.ranges", (self.work / "different_offsets.ll").read_bytes())
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
