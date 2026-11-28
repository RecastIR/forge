import struct


class Layout:
    """Locate fields in our linked PE32+ fixtures for single-field test edits."""
    def __init__(self, data):
        self.data = data
        self.pe = self.u32(0x3c)
        self.opt = self.pe + 24
        self.directories = self.opt + 112
        table = self.opt + struct.unpack_from("<H", data, self.pe + 20)[0]
        count = struct.unpack_from("<H", data, self.pe + 6)[0]
        self.section_table = table
        self.sections = [struct.unpack_from("<IIII", data, table + 40 * i + 8) for i in range(count)]

    def u32(self, offset):
        return struct.unpack_from("<I", self.data, offset)[0]

    def directory(self, index):
        return struct.unpack_from("<II", self.data, self.directories + 8 * index)

    def dir64_fields(self):
        directory, size = self.directory(5)
        block = self.file_offset(directory)
        end = block + size
        fields = {}
        while block < end:
            page, length = struct.unpack_from("<II", self.data, block)
            assert 8 <= length <= end - block
            for at in range(block + 8, block + length, 2):
                fixup, = struct.unpack_from("<H", self.data, at)
                if fixup >> 12 == 10:
                    fields[page + (fixup & 4095)] = at
            block += length
        return fields

    def section_header(self, rva):
        for index, (size, start, _, _) in enumerate(self.sections):
            if start <= rva < start + size:
                return self.section_table + 40 * index
        raise ValueError(f"unmapped fixture RVA {rva:x}")

    def abut_writable_sections(self, left_rva, right_rva):
        """Extend the first fixture section's zero tail up to its writable neighbor."""
        left = self.section_header(left_rva)
        right = self.section_header(right_rva)
        struct.pack_into("<I", self.data, left + 8, right_rva - left_rva)
        struct.pack_into("<I", self.data, left + 36, self.u32(right + 36))

    def add_unused_section(self, size, flags):
        header = self.section_table + 40 * len(self.sections)
        assert header + 40 <= self.u32(self.opt + 60)
        start = self.u32(self.opt + 56)
        struct.pack_into("<H", self.data, self.pe + 6, len(self.sections) + 1)
        struct.pack_into("<8sIIIIIIHHI", self.data, header, b".unused", size, start,
                         0, 0, 0, 0, 0, 0, flags)
        struct.pack_into("<I", self.data, self.opt + 56, start + size)
        self.sections.append((size, start, 0, 0))

    def file_offset(self, rva):
        for size, start, raw_size, offset in self.sections:
            if start <= rva < start + min(size, raw_size):
                return offset + rva - start
        raise ValueError(f"unmapped fixture RVA {rva:x}")
