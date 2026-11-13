"""Compile lifted PE bytes with LLVM. Exercise a native C call on Apple Silicon."""
import itertools
import json
from pathlib import Path
import platform
import operator
import os
import random
import re
import struct
import subprocess
import sys
import tempfile

from pe_layout import Layout

MODE, FORGE, FIXTURES, OPT, LLC, READOBJ, HARNESS_OBJECT, *HARNESS_LINKER = sys.argv[1:]
MASK = (1 << 64) - 1


def run(*args, **kwargs):
    return subprocess.run(args, check=True, capture_output=True, timeout=45, **kwargs).stdout


def check(condition, message):
    if not condition:
        raise AssertionError(message)


def check_ir(path, rva, wrapper):
    module = path.read_text()
    internal = f"define internal void @forge_lifted_{rva:x}("
    check(internal in module, f"{path.name} missing {internal}")
    # O2 can infer return attributes such as noundef and range.
    definitions = [line for line in module.splitlines() if line.startswith("define ") and " @forge_lifted(" in line]
    check(len(definitions) == int(wrapper), f"{path.name} wrapper={wrapper}")
    if wrapper:
        signature = r"^define (?:(?:noundef|range\(i64 -?\d+, -?\d+\)) )*i64 @forge_lifted\(i64 %\w+, i64 %\w+\)"
        check(re.match(signature, definitions[0]), definitions[0])


def report(image):
    return json.loads(run(FORGE, "inspect", image, "--format", "json"))["modules"][0]


def cases(work):
    root = Path(FIXTURES)
    add = root / "add.exe"
    yield "C addition", add, int(report(add)["entry_point_rva"], 16), lambda a, b: a+b
    image = root / "arithmetic.exe"
    exports = {e["names"][0]: int(e["rva"], 16) for e in report(image)["exports"]}

    def signed(x, width=64):
        return x - (1 << width) if x >> (width - 1) else x

    for name, reference in [
            ("entry", lambda a, b: a-b), ("product", lambda a, b: a*b),
            ("expr", lambda a, b: a + b*4 - 7 - 128),
            ("low_product", lambda a, b: (a*b-1) & 0xffffffff),
            ("select_signed", lambda a, b: min(signed(a), signed(b))),
            ("zero32", lambda a, b: 0), ("zero64", lambda a, b: 0),
            ("immediates", lambda a, b: ((a + 8*b - 3 - 0x12345678) & 0xffffffff) - 100000)]:
        yield name, image, exports[name], reference

    # Each branch returns distinct constants even when the compared operands are equal.
    original = image.read_bytes()
    layout = Layout(original)
    conditions = [
        (0x72, operator.lt, False), (0x73, operator.ge, False), (0x74, operator.eq, False),
        (0x75, operator.ne, False), (0x76, operator.le, False), (0x77, operator.gt, False),
        (0x7c, operator.lt, True), (0x7d, operator.ge, True), (0x7e, operator.le, True),
        (0x7f, operator.gt, True)]
    for name, width, prefix, taken, fallthrough in [
            ("select_unsigned", 32, bytes.fromhex("39 d1 72"), MASK, 0),
            ("equal", 64, bytes.fromhex("48 39 d1 75"), 0, 1)]:
        start = layout.file_offset(exports[name])
        check(original.startswith(prefix, start), f"unexpected CMP/Jcc encoding in {name}")
        for opcode, pred, is_signed in conditions:
            data = bytearray(original)
            data[start + len(prefix) - 1] = opcode
            variant = work / f"jcc-{width}-{opcode:x}.exe"
            variant.write_bytes(data)

            def reference(a, b, width=width, pred=pred, is_signed=is_signed,
                          taken=taken, fallthrough=fallthrough):
                mask = (1 << width) - 1
                a, b = a & mask, b & mask
                if is_signed:
                    a, b = signed(a, width), signed(b, width)
                return taken if pred(a, b) else fallthrough

            yield f"Jcc {width} {opcode:x}", variant, exports[name], reference

    # Change only the SUB opcode in the linked PE, preserving its RVA and signature.
    patched = bytearray(image.read_bytes())
    start = Layout(patched).file_offset(exports["entry"])
    check(patched.startswith(bytes.fromhex("48 89 c8 48 29 d0 c3"), start), "unexpected SUB fixture")
    patched[start+4] = 0x01
    image = work / "patched.exe"
    image.write_bytes(patched)
    yield "patched addition", image, exports["entry"], lambda a, b: a+b


def original_results(image, rva, vectors):
    import unicorn as uc
    from unicorn import x86_const as x86
    pe = image.read_bytes()
    layout = Layout(pe)
    base, = struct.unpack_from("<Q", pe, layout.opt+24)
    vm = uc.Uc(uc.UC_ARCH_X86, uc.UC_MODE_64)
    size, start, raw_size, offset = next(s for s in layout.sections if s[1] <= rva < s[1]+s[0])
    vm.mem_map(base+start, (size+4095) & ~4095)
    vm.mem_write(base+start, pe[offset:offset+min(size,raw_size)])
    stack = 0x800000
    stop = 0x900000
    vm.mem_map(stack, 4096)
    vm.mem_map(stop, 4096)
    rsp = stack + 2040  # entry RSP is 8 mod 16, with space for the Windows shadow store
    vm.mem_write(rsp, struct.pack("<Q", stop))
    results = []
    for a, b in vectors:
        vm.reg_write(x86.UC_X86_REG_RSP, rsp)
        vm.reg_write(x86.UC_X86_REG_RCX, a)
        vm.reg_write(x86.UC_X86_REG_RDX, b)
        vm.reg_write(x86.UC_X86_REG_RAX, 0xdeadbeefdeadbeef)
        vm.emu_start(base+rva, stop, count=100)
        check(vm.reg_read(x86.UC_X86_REG_RIP) == stop and vm.reg_read(x86.UC_X86_REG_RSP) == rsp+8,
              f"original function at {rva:#x} did not return for {(a, b)}")
        results.append(vm.reg_read(x86.UC_X86_REG_RAX))
    return results


def check_harness_input(exe, directory):
    empty = subprocess.run([exe], input=b"", capture_output=True, timeout=45)
    check((empty.returncode, empty.stdout, empty.stderr) == (0, b"", b""), ("empty input", empty))
    check(run(exe, input=b"1 2") == b"3\n", "complete pair at EOF")
    for tail in (b"4", b"4 ", b"0x"):
        partial = subprocess.run([exe], input=b"1 2\n" + tail, capture_output=True, timeout=45)
        check((partial.returncode, partial.stdout, partial.stderr) == (1, b"3\n", b""),
              ("incomplete pair at EOF", tail, partial))

    fd = os.open(directory, os.O_RDONLY)
    try:
        unreadable = subprocess.run([exe], stdin=fd, capture_output=True, timeout=45)
    finally:
        os.close(fd)
    check((unreadable.returncode, unreadable.stdout, unreadable.stderr) == (1, b"", b""),
          ("unreadable input", unreadable))


def main():
    if MODE != "codegen" and (platform.system(), platform.machine()) != ("Darwin", "arm64"):
        print("Native execution requires an Apple Silicon host.")
        return 77
    if MODE == "differential":
        try:
            import unicorn
        except ModuleNotFoundError:
            print("Optional Unicorn x86 oracle unavailable.")
            return 77
        print("Unicorn", unicorn.__version__)
    edges = [0, 1, 2, 0x7fffffff, 0x80000000, 0xffffffff, 1 << 32,
             (1 << 63)-2, (1 << 63)-1, 1 << 63, MASK-1, MASK]
    vectors = list(itertools.product(edges, repeat=2))
    rng = random.Random(0xF047E)
    vectors.extend((rng.getrandbits(64), rng.getrandbits(64)) for _ in range(128))
    stdin = "".join(f"{a:x} {b:x}\n" for a, b in vectors)
    with tempfile.TemporaryDirectory() as temp:
        work = Path(temp)
        ir, optimized, obj, exe = (work / f for f in ["lift.ll", "opt.ll", "func.o", "harness"])
        for name, image, rva, reference in cases(work):
            cmd = [FORGE, "lift", image, "--rva", hex(rva), "--output", ir]
            if MODE == "codegen":
                run(*cmd)
                check_ir(ir, rva, wrapper=False)
                run(OPT, "-S", "-passes=default<O2>", ir, "-o", optimized)
                check_ir(optimized, rva, wrapper=False)
                run(LLC, "-filetype=obj", optimized, "-o", obj)
                check(b"Mach-O arm64" in run(READOBJ, "--file-headers", obj), name)
            run(*cmd, "--signature", "i64(i64,i64)")
            check_ir(ir, rva, wrapper=True)
            run(OPT, "-passes=verify", "-disable-output", ir)
            run(OPT, "-S", "-passes=default<O2>", ir, "-o", optimized)
            check_ir(optimized, rva, wrapper=True)
            expected = [reference(a, b) & MASK for a, b in vectors]
            if MODE == "differential":
                expected = original_results(image, rva, vectors)
            for source in ([ir, optimized] if MODE == "native" else [optimized]):
                run(LLC, "-filetype=obj", source, "-o", obj)
                check(b"Mach-O arm64" in run(READOBJ, "--file-headers", obj), name)
                if MODE == "codegen":
                    continue
                run(*HARNESS_LINKER, HARNESS_OBJECT, obj, "-o", exe)
                if MODE == "native" and name == "C addition" and source == ir:
                    check_harness_input(exe, work)
                actual = [int(s, 16) for s in run(exe, input=stdin, text=True).splitlines()]
                check(len(actual) == len(expected), (name, source.name, len(actual), len(expected)))
                for pair, got, want in zip(vectors, actual, expected):
                    if got != want:
                        raise AssertionError((name, source.name, pair, hex(got), hex(want)))
            print(name, hex(rva), MODE, len(vectors) if MODE != "codegen" else "OK")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except subprocess.CalledProcessError as error:
        print(error.stderr, file=sys.stderr)
        raise
