"""Verify bounded table edges in the disassembly used to check a reported leaf call."""
from bisect import bisect_right
from pathlib import Path
import re
import struct
import subprocess

from build import CONDITIONS


DWORD = dict(zip("rax rbx rcx rdx rsi rdi rsp rbp".split(), "eax ebx ecx edx esi edi esp ebp".split()))
DWORD.update({f"r{i}": f"r{i}d" for i in range(8, 16)})


class CallerTables:
    def __init__(self, image, module, caller, decode):
        self.image = image
        self.sections = module["sections"]
        self.base = int(module["image_base_va"], 16)
        self.caller = caller
        self.decode = decode
        self.proofs = []
        self.spans = set()
        self.entries = 0

    def targets(self, site, target, graph):
        cursor = site

        def previous():
            nonlocal cursor
            # A complete x86 instruction has at most 15 bytes. Only walk decoded,
            # reachable instructions with an unambiguous end at the current cursor.
            starts = [a for a in range(cursor - 15, cursor) if a in graph and self.decode(a)[1] == cursor]
            if len(starts) != 1:
                raise ValueError("incomplete or overlapping caller dispatch")
            cursor = starts[0]
            return self.decode(cursor)[0].partition("#")[0].strip()

        add = re.fullmatch(r"add (\w+), (\w+)", previous())
        load = re.fullmatch(r"movsxd (\w+), dword ptr \[(\w+) \+ 4\*(\w+)\]", previous())
        lea = re.fullmatch(r"lea (\w+), \[rip(?: ([+-]) (0x[0-9a-f]+|\d+))?\]", previous())
        if not (add and load and lea):
            raise ValueError("unrecognized caller dispatch")
        base, index = lea[1], load[3]
        if (not all(reg in DWORD for reg in (target, base, index)) or base in (target, index)
                or add.groups() != (target, base) or load.groups()[:2] != (target, base)):
            raise ValueError("caller dispatch register mismatch")
        disp = int(lea[3] or "0", 0) * (-1 if lea[2] == "-" else 1)
        table = self.decode(cursor)[1] + disp - self.base

        guard = previous()
        copy = re.fullmatch(r"mov (\w+), (\w+)", guard)
        checked = index
        if copy:
            if copy[1] != DWORD[index] or copy[2] not in DWORD.values():
                raise ValueError("invalid caller dispatch index extension")
            checked = copy[2]
            guard = previous()
        cmp = re.fullmatch(r"cmp (\w+), (0x[0-9a-f]+|\d+)", previous())
        if not guard.startswith("ja ") or not cmp or cmp[1] != checked:
            raise ValueError("unproven caller dispatch bound")
        count = int(cmp[2], 0) + 1
        self.entries += count
        if count > 1024 or self.entries > 4096:
            raise ValueError("caller dispatch exceeds recovery budget")
        self.proofs.append((cursor, site))
        self.spans.add((table, table + 4 * count))

        for section in self.sections:
            delta = table - int(section["rva"], 16)
            if (section["permissions"] == "r--" and delta >= 0
                    and delta + 4 * count <= min(section["raw_size"], section["virtual_size"])):
                with self.image.open("rb") as snapshot:
                    snapshot.seek(section["file_offset"] + delta)
                    raw = snapshot.read(4 * count)
                if len(raw) == 4 * count:
                    break
        else:
            raise ValueError("caller dispatch requires a complete read-only table")
        targets = [table + offset for offset, in struct.iter_unpack("<i", raw)]
        if any(not self.caller.start <= dest < self.caller.end for dest in targets):
            raise ValueError("caller dispatch target outside its recorded function")
        return [self.base + dest for dest in targets]

    def validate(self, graph, forge):
        if not self.proofs:
            return
        explicit = {self.base + self.caller.start}
        for addr, edges in graph.items():
            op = self.decode(addr)[0].partition(" ")[0]
            if op == "jmp":
                explicit.update(edges)
            elif op in CONDITIONS:
                explicit.add(edges[0])
        destinations = sorted(explicit)
        for compare, site in self.proofs:
            first = bisect_right(destinations, compare)
            if first < len(destinations) and destinations[first] <= site:
                raise ValueError("caller edge bypasses the dispatch guard")

        # Use the PE layer solely for loader-written fields, permissions and fixups.
        # The disassembly, index bounds and signed table words above establish the edges.
        binary_dir = Path(forge).resolve().parent
        helper = binary_dir / "tests/recovery_contract"
        if not helper.is_file():  # Multi-configuration CMake layout.
            helper = binary_dir.parent / "tests" / binary_dir.name / "recovery_contract"
        ranges = [(self.caller.start, self.caller.end), *sorted(self.spans)]
        result = subprocess.run([helper, "--check-dispatch-spans", self.image,
                                 *(hex(rva) for pair in ranges for rva in pair)],
                                capture_output=True, text=True, timeout=30)
        if result.returncode:
            raise ValueError(f"unstable caller dispatch: {result.stderr.strip()}")
