"""Build SDK-free Windows machine-code fixtures with deterministic timestamps."""
import argparse
from pathlib import Path
import subprocess
import tempfile


def generate(output, mc, link, dlltool, clang):
    output.mkdir(parents=True, exist_ok=True)
    metadata = Path(__file__).with_name("metadata.s").read_text()
    stub = ".text\n.globl entry\nentry:\n  retq\n"
    helper = ".text\n.globl __delayLoadHelper2\n__delayLoadHelper2:\n  retq\n"
    contract = "api-ms-win-core-file-l1-2-0.dll"
    definitions = {
        "Physics.DLL": ["Named=entry @1", "ByOrdinal=entry @7 NONAME", "Forward=KERNEL32.Sleep"],
        "Late.dll": ["Later=entry"],
        "ForgeAbi.dll": ["Pair", "Triple", "Four", "Six", "WriteProbe", "Address", "Handle", "Bad", "TailByte"],
        "Bridge.dll": ["Bridge=entry"],
        "Middle.dll": ["Middle=entry"],
        "MissingLeaf.dll": ["Leaf"],
        "KERNEL32.dll": ["Sleep", "SetLastError", "GetLastError", "lstrlenA"],
        "vcruntime140.dll": ["Runtime"],
        contract: ["Contract"],
    }
    with tempfile.TemporaryDirectory() as folder:
        work = Path(folder)

        def run(*args):
            subprocess.run(args, cwd=work, check=True)

        for dll, exports in definitions.items():
            # Import libraries use the public spelling, including NONAME ordinals.
            public = [line.split("=")[0] + (" " + line.split(" ", 1)[1] if " " in line else "")
                      for line in exports]
            definition = work / (dll + ".def")
            definition.write_text("LIBRARY " + dll + "\nEXPORTS\n" + "\n".join(public) + "\n")
            run(dlltool, "-m", "i386:x86-64", "-d", definition, "-l", dll + ".lib")

        def image(filename, assembly=stub, imports=(), delays=(), exports=(), link_flags=()):
            assembly += helper if delays else ""
            for _, symbol in imports:
                assembly += "\n.section .rdata,\"dr\"\n.quad __imp_" + symbol + "\n"
            source = work / "image.s"
            source.write_text(assembly)
            run(mc, "-triple=x86_64-pc-windows-msvc", "-filetype=obj", source, "-o", "image.obj")
            flags = ["/entry:entry", "/subsystem:console"]
            if filename in definitions:
                definition = work / "exports.def"
                definition.write_text("EXPORTS\n" + "\n".join(definitions[filename]) + "\n")
                flags = ["/dll", "/noentry", "/def:exports.def", "/implib:unused.lib"]
            run(link, "/nodefaultlib", "/timestamp:0", *flags, *link_flags, *("/export:" + name for name in exports), "/out:" + filename, "image.obj",
                *dict.fromkeys(dll + ".lib" for dll, _ in imports),
                *("/delayload:" + dll for dll in delays))
            (output / filename).write_bytes((work / filename).read_bytes())

        sources = Path(__file__).resolve().parent
        for name in ("executable-return", "executable-call", "executable-data", "executable-fault"):
            image(f"{name}.exe", (sources / f"{name}.s").read_text())
        image("executable-last-error.exe", (sources / "executable-last-error.s").read_text(),
              [("KERNEL32.dll", name) for name in ("SetLastError", "GetLastError")])
        # Remap debug paths so builds in different source directories produce identical PEs.
        for name in ("add", "inlined"):
            run(clang, "--target=x86_64-windows-msvc", "-O2", "-fwrapv", "-gdwarf-4", "-g",
                "-fdebug-compilation-dir=.", f"-ffile-prefix-map={sources}=.", "-S",
                sources / f"{name}.c", "-o", f"{name}.s")
            with (work / f"{name}.s").open("a") as assembly:
                assembly.write((sources / "leaf-range.s").read_text())
            run(mc, "-triple=x86_64-windows-msvc", "-filetype=obj", f"{name}.s", "-o", f"{name}.obj")
            run(link, "/nodefaultlib", "/timestamp:0", "/debug:dwarf", "/entry:entry", "/subsystem:console",
                f"/out:{name}.exe", f"{name}.obj")
            (output / f"{name}.exe").write_bytes((work / f"{name}.exe").read_bytes())
        cfg_leaves = sources.parent / "differential/fixtures/control_flow/cfg_cases.S"
        image("cfg.exe", (sources / "cfg.s").read_text() + cfg_leaves.read_text())
        jump_table = cfg_leaves.with_name("jump_table.S")
        image("jump.exe", (sources / "jump.s").read_text() + jump_table.read_text(),
              exports=["entry", "two_tables", "table_budget", "width_paths", "table_caller", "case_caller"])
        image("jump-dvrt.exe", (sources / "jump-dvrt.s").read_text(), exports=["entry", "direct_only"])
        image_assembly = (sources / "image.s").read_text()
        image("image.exe", image_assembly)
        image("image-fixed.exe", image_assembly, link_flags=["/fixed"])
        ranges = (sources / "image-ranges.s").read_text()
        for fields in (8, 64, 512):
            image(f"image-ranges-{fields}.exe", f".set fields, {fields}\n" + ranges,
                  exports=["entry"], link_flags=["/base:0x10000000"])
        leaf_calls = sources.parent / "differential/fixtures/functions/call_leaves.S"
        indirect = leaf_calls.with_name("call_indirect.S")
        image("indirect.exe", metadata + indirect.read_text(),
              exports=["indirect_preserve", "indirect_leaf", "indirect_recurse"])
        image("stack.exe", (sources / "stack.s").read_text())
        # A separate file-backed section lets CLI tests exercise both limits and boundary types.
        probe = ('.section .probe,"xr"\n.space 65568, 0xcc\n.quad entry\n.space 12, 0xcc\n'
                 '.seh_proc leaf_fence\nleaf_fence:\n.seh_endprologue\nret\n.seh_endproc\n.byte 0x0f\n')
        image("leaves.exe", stub + leaf_calls.read_text() + probe)
        last_error = (sources.parent / "differential/fixtures/imports/last_error.S").read_text()
        imports = [("KERNEL32.dll", name) for name in ("SetLastError", "GetLastError", "Sleep")]
        image("last-error.exe", stub + ".globl last_error_set\n" + last_error, imports + [("Physics.DLL", "Named")], exports=["last_error_set"])
        image("last-error-delay.exe", stub + last_error, imports, delays=["KERNEL32.dll"])
        string_length = (sources.parent / "differential/fixtures/imports/lstrlen.S").read_text()
        image("lstrlen.exe", stub + string_length,
              [("KERNEL32.dll", name) for name in ("SetLastError", "GetLastError", "lstrlenA")])
        abi_imports = [("ForgeAbi.dll", name) for name in definitions["ForgeAbi.dll"]]
        image("service-abi.exe", (sources / "service-abi.s").read_text(),
              abi_imports + [("KERNEL32.dll", name) for name in ("SetLastError", "GetLastError", "lstrlenA")],
              exports=["pair", "triple", "four", "echo_bits", "six", "bad_stack", "bad_sig", "void_result",
                       "write_call", "write_nested", "disjoint_record", "nested_disjoint", "nested_overlap", "nested_optional",
                       "unmapped", "stale_spill", "disjoint_spill", "image_output", "readonly_output",
                       "counted_boundary", "counted_with_load", "fixed_boundary", "counted_gap", "stack_count", "zero_count"])
        image("checked-memory.exe", (sources / "checked-memory.s").read_text(), [("KERNEL32.dll", "GetLastError")],
              exports=["entry", "guard_then_service", "bridge_value,data", "bridge_constant,data"])
        image("import-call.exe", (sources / "import-call.s").read_text(), [("Physics.DLL", "Named")])
        image("chained.exe", (sources / "chained.s").read_text())
        image("unicode.exe", stub + '.section ".donnée","dr"\n.byte 1\n.section ".界区","dr"\n.byte 1\n')
        image("arithmetic.exe", (sources / "arithmetic.s").read_text(),
              exports=["entry", "product", "expr", "low_product", "select_signed", "select_unsigned",
                       "equal", "immediates", "zero64", "zero32"])
        image("minimal.exe")
        image("Physics.DLL")
        image("metadata.exe", metadata, [("Physics.DLL", "Named"), ("Physics.DLL", "ByOrdinal"),
                                         ("KERNEL32.dll", "Sleep")])
        image("delay.exe", imports=[("Physics.DLL", "Named"), ("Physics.DLL", "ByOrdinal")],
              delays=["Physics.DLL"])
        image("delay-contract.exe", imports=[(contract, "Contract")], delays=[contract])
        image("contract.exe", imports=[(contract, "Contract")])
        image("runtime.exe", imports=[("vcruntime140.dll", "Runtime")])
        image("Bridge.dll", imports=[("Middle.dll", "Middle")])
        image("Middle.dll", imports=[("Late.dll", "Later")])
        image("Late.dll", imports=[("Bridge.dll", "Bridge"), ("MissingLeaf.dll", "Leaf")])
        image("graph.exe", imports=[("Bridge.dll", "Bridge"), ("Late.dll", "Later")], delays=["Late.dll"])
        image("optional.exe", imports=[("Late.dll", "Later")], delays=["Late.dll"])
        (work / "x86.s").write_text(".text\n.globl _entry\n_entry:\n  retl\n")
        run(mc, "-triple=i686-pc-windows-msvc", "-filetype=obj", "x86.s", "-o", "x86.obj")
        run(link, "/machine:x86", "/safeseh:no", "/nodefaultlib", "/entry:entry",
            "/subsystem:console", "/timestamp:0", "/out:i386.exe", "x86.obj")
        (output / "i386.exe").write_bytes((work / "i386.exe").read_bytes())


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path)
    parser.add_argument("--mc", default="llvm-mc")
    parser.add_argument("--link", default="lld-link")
    parser.add_argument("--dlltool", default="llvm-dlltool")
    parser.add_argument("--clang", default="clang")
    args = parser.parse_args()
    generate(args.output, args.mc, args.link, args.dlltool, args.clang)
