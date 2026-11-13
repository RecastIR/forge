"""Run clang-tidy with LLVM 23's co-allocated IR operand storage annotated."""
import json
from pathlib import Path
import subprocess
import sys
import tempfile


# LLVM User::operator new reserves storage immediately before the object.
# ArrayBound models the C++ object as its own allocation and diagnoses valid
# negative offsets into that prefix. Match the upstream expressions exactly so
# changes to the implementation receive normal analysis.
OPERAND_ACCESS = {
    "User.h": {
        ": OperandTraits<U>::op_begin(const_cast<U*>(that))[Idx];",
        "return *(reinterpret_cast<const Use *const *>(this) - 1);",
        "Use *&getHungOffOperands() { return *(reinterpret_cast<Use **>(this) - 1); }",
    },
    "InstrTypes.h": {"DEFINE_TRANSPARENT_OPERAND_ACCESSORS(CmpInst, Value)"},
}


def main(include, tidy, *args):
    with tempfile.TemporaryDirectory() as temp:
        folder = Path(temp)
        files = []
        for name, expressions in OPERAND_ACCESS.items():
            header = Path(include) / "llvm/IR" / name
            lines = header.read_text().splitlines(keepends=True)
            amended = [line.rstrip() + " // NOLINT(clang-analyzer-security.ArrayBound)\n"
                       if line.strip() in expressions else line for line in lines]
            if amended != lines:
                copy = folder / name
                copy.write_text("".join(amended))
                files.append({"type": "file", "name": str(header), "external-contents": str(copy)})
        overlay = folder / "llvm-operands.json"
        overlay.write_text(json.dumps({"version": 0, "use-external-names": False, "roots": files}))
        return subprocess.run([tidy, *args, f"--vfsoverlay={overlay}"]).returncode


if __name__ == "__main__":
    sys.exit(main(*sys.argv[1:]))
