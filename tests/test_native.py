"""Compile lifted PE bytes with LLVM. Exercise a native C call on Apple Silicon."""
import itertools
import json
from pathlib import Path
import platform
import operator
import random
import struct
import subprocess
import sys
import tempfile

from pe_layout import Layout

MODE, FORGE, FIXTURES, OPT, LLC, READOBJ, CXX = sys.argv[1:]
MASK = (1 << 64) - 1


def run(*args, **kwargs):
    return subprocess.run(args, check=True, capture_output=True, timeout=45, **kwargs).stdout


def report(image):
    return json.loads(run(FORGE, "inspect", image, "--format", "json"))["modules"][0]


def cases(work):
    root = Path(FIXTURES)
    add = root / "add.exe"
    yield "C addition", add, int(report(add)["entry_point_rva"], 16), lambda a, b: a+b
    image = root / "arithmetic.exe"
    exports = {e["names"][0]: int(e["rva"], 16) for e in report(image)["exports"]}

    def signed(x):
        return x - (1 << 64) if x >> 63 else x

    for name, reference in [
            ("entry", lambda a, b: a-b), ("product", lambda a, b: a*b),
            ("expr", lambda a, b: a + b*4 - 7 - 128),
            ("low_product", lambda a, b: (a*b-1) & 0xffffffff),
            ("select_signed", lambda a, b: min(signed(a), signed(b))),
            ("select_unsigned", lambda a, b: -int((a & 0xffffffff) < (b & 0xffffffff))),
            ("equal", lambda a, b: int(a == b)),
            ("immediates", lambda a, b: ((a + 8*b - 3 - 0x12345678) & 0xffffffff) - 100000)]:
        yield name, image, exports[name], reference

    # Exercise all ten accepted condition codes with the same two branch targets.
    original = image.read_bytes()
    select = exports["select_signed"]
    branch = Layout(original).file_offset(select) + 3
    assert original[branch] == 0x7d
    for opcode, pred, is_signed in [
            (0x72, operator.lt, False), (0x73, operator.ge, False), (0x74, operator.eq, False),
            (0x75, operator.ne, False), (0x76, operator.le, False), (0x77, operator.gt, False),
            (0x7c, operator.lt, True), (0x7e, operator.le, True), (0x7f, operator.gt, True)]:
        data = bytearray(original)
        data[branch] = opcode
        variant = work / f"jcc-{opcode:x}.exe"
        variant.write_bytes(data)

        def select_reference(a, b, pred=pred, is_signed=is_signed):
            take = pred(signed(a), signed(b)) if is_signed else pred(a, b)
            return b if take else a

        yield f"Jcc {opcode:x}", variant, select, select_reference

    # Change only the SUB opcode in the linked PE, preserving its RVA and signature.
    patched = bytearray(image.read_bytes())
    start = Layout(patched).file_offset(exports["entry"])
    assert patched[start:start+7] == bytes.fromhex("48 89 c8 48 29 d0 c3")
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
        assert vm.reg_read(x86.UC_X86_REG_RIP) == stop and vm.reg_read(x86.UC_X86_REG_RSP) == rsp+8
        results.append(vm.reg_read(x86.UC_X86_REG_RAX))
    return results


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
        if MODE != "codegen":
            run(CXX, "-arch", "arm64", "-std=c++20", "-c", Path(__file__).with_name("native_harness.cpp"),
                "-o", work/"harness.o")
        for name, image, rva, reference in cases(work):
            cmd = [FORGE, "lift", image, "--rva", hex(rva), "--output", ir]
            if MODE == "codegen":
                run(*cmd)
                assert "define internal void @forge_lifted_" in ir.read_text()
                assert "define i64 @forge_lifted(" not in ir.read_text()
                run(OPT, "-S", "-passes=default<O2>", ir, "-o", optimized)
                assert "define internal" in optimized.read_text()
                run(LLC, "-filetype=obj", optimized, "-o", obj)
                assert b"Mach-O arm64" in run(READOBJ, "--file-headers", obj)
            run(*cmd, "--signature", "i64(i64,i64)")
            assert "define i64 @forge_lifted(" in ir.read_text()
            run(OPT, "-passes=verify", "-disable-output", ir)
            run(OPT, "-S", "-passes=default<O2>", ir, "-o", optimized)
            expected = [reference(a, b) & MASK for a, b in vectors]
            if MODE == "differential":
                expected = original_results(image, rva, vectors)
            for source in ([ir, optimized] if MODE == "native" else [optimized]):
                run(LLC, "-filetype=obj", source, "-o", obj)
                assert b"Mach-O arm64" in run(READOBJ, "--file-headers", obj)
                if MODE == "codegen":
                    continue
                run(CXX, "-arch", "arm64", work/"harness.o", obj, "-o", exe)
                actual = [int(s, 16) for s in run(exe, input=stdin, text=True).splitlines()]
                assert len(actual) == len(expected)
                for pair, got, want in zip(vectors, actual, expected):
                    assert got == want, (name, source.name, pair, hex(got), hex(want))
            print(name, hex(rva), MODE, len(vectors) if MODE != "codegen" else "OK")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except subprocess.CalledProcessError as error:
        print(error.stderr, file=sys.stderr)
        raise
