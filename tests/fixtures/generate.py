"""Build small static-analysis inputs; nothing produced here is executed."""
import argparse
from pathlib import Path
import subprocess
import tempfile


def generate(output, mc, link, dlltool):
    output.mkdir(parents=True, exist_ok=True)
    metadata = Path(__file__).with_name("metadata.s").read_text()
    stub = ".text\n.globl entry\nentry:\n  retq\n"
    helper = ".text\n.globl __delayLoadHelper2\n__delayLoadHelper2:\n  retq\n"
    contract = "api-ms-win-core-file-l1-2-0.dll"
    definitions = {
        "Physics.DLL": ["Named=entry @1", "ByOrdinal=entry @7 NONAME", "Forward=KERNEL32.Sleep"],
        "Late.dll": ["Later=entry"],
        "Bridge.dll": ["Bridge=entry"],
        "Middle.dll": ["Middle=entry"],
        "MissingLeaf.dll": ["Leaf"],
        "KERNEL32.dll": ["Sleep"],
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

        def image(filename, assembly=stub, imports=(), delays=()):
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
            run(link, "/nodefaultlib", "/timestamp:0", *flags, "/out:" + filename, "image.obj",
                *dict.fromkeys(dll + ".lib" for dll, _ in imports),
                *("/delayload:" + dll for dll in delays))
            (output / filename).write_bytes((work / filename).read_bytes())

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
    args = parser.parse_args()
    generate(args.output, args.mc, args.link, args.dlltool)
