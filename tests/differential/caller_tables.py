"""Verify bounded table edges in the disassembly used to check a reported leaf call."""
from bisect import bisect_right
from dataclasses import dataclass
from pathlib import Path
import re
import struct
import subprocess

from build import CONDITIONS


DWORD = dict(zip("rax rbx rcx rdx rsi rdi rsp rbp".split(), "eax ebx ecx edx esi edi esp ebp".split()))
DWORD.update({f"r{i}": f"r{i}d" for i in range(8, 16)})


@dataclass(frozen=True)
class ForwardCall:
    first: int
    last: int
    load: int
    guarded: bool


def forward_call(graph, decode, base, site, reg, predecessors):
    """Read the contiguous forward loop from reachable instructions in the PE snapshot."""
    before = []
    cursor = site
    while len(before) < 8:
        previous = [a for a in predecessors.get(cursor, ()) if decode(a)[1] == cursor]
        if len(previous) != 1:
            break
        cursor, = previous
        before.append(cursor)

    def asm(addr):
        return decode(addr)[0].partition("#")[0].strip()

    def reject():
        raise ValueError(f"unproven register call at {site:x}")

    store = bool(before and re.fullmatch(r"mov qword ptr \[.+\], .+", asm(before[0])))
    prefix = before[1:] if store else before
    if len(prefix) < 7:
        reject()
    skip, test, load, empty, compare, end_def, begin_def = prefix[:7]
    bound = r"lea (\w+), \[rip(?: ([+-]) (0x[0-9a-f]+|\d+))?\]"
    first, last = (re.fullmatch(bound, asm(a)) for a in (begin_def, end_def))
    if not first or not last:
        reject()
    cursor, limit = first[1], last[1]
    saved = {"rbx", "rbp", "rsi", "rdi", "r12", "r13", "r14", "r15"}
    compares = {f"cmp {cursor}, {limit}", f"cmp {limit}, {cursor}"}
    if (cursor not in saved or limit not in saved or cursor == limit or reg in {cursor, limit, "rsp"}
            or asm(compare) not in compares or not asm(empty).startswith("je ")
            or asm(load) != f"mov {reg}, qword ptr [{cursor}]" or asm(test) != f"test {reg}, {reg}"
            or not asm(skip).startswith("je ") or graph[skip][0] != decode(site)[1]):
        reject()
    increment = decode(site)[1]
    latch = decode(increment)[1] if increment in graph else None
    back = decode(latch)[1] if latch in graph else None
    if (back not in graph or asm(increment) not in (f"add {cursor}, 8", f"add {cursor}, 0x8")
            or asm(latch) not in compares or not asm(back).startswith("jne ")
            or graph[back][0] != load or begin_def <= graph[empty][0] < decode(back)[1]):
        reject()

    # A failed range or bypass can still have genuine bound definitions. Require
    # dominance when the caller uses this proof to establish an incoming call edge.
    guarded = not (begin_def < next(iter(graph)) < decode(back)[1])
    protected = [a for a in before if a > begin_def] + [site, increment, latch, back]
    for dest in protected:
        for src in predecessors.get(dest, ()):
            if (src, dest) in ((back, load), (skip, increment)):
                continue
            op = asm(src).partition(" ")[0]
            if decode(src)[1] != dest or op == "jmp" or (op in CONDITIONS and graph[src][0] == dest):
                guarded = False

    def endpoint(addr, lea):
        disp = int(lea[3] or "0", 0) * (-1 if lea[2] == "-" else 1)
        return decode(addr)[1] - base + disp

    return ForwardCall(endpoint(begin_def, first), endpoint(end_def, last), load - base, guarded)


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

    def validate(self, graph, forge, *, register_calls=False, iat_slots=(), forward_target=()):
        if not self.proofs and not register_calls and not iat_slots:
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
        args = [hex(rva) for pair in ranges for rva in pair]
        if forward_target:
            args.extend(["--forward-target", *map(hex, forward_target)])
        if iat_slots:
            args.extend(["--iat-slots", *map(hex, sorted(iat_slots))])
        try:
            result = subprocess.run([helper, "--check-dispatch-spans", self.image, *args],
                                    capture_output=True, text=True, timeout=30)
        except (OSError, subprocess.SubprocessError) as error:
            raise ValueError(f"cannot verify caller PE evidence: {error}") from error
        if result.returncode:
            raise ValueError(f"unstable caller dispatch: {result.stderr.strip()}")
