"""Run clang-tidy with LLVM 23's co-allocated IR operand storage annotated."""
import json
from pathlib import Path
import subprocess
import sys
import tempfile

from style import changed_sources, native


ADVISORY_CHECKS = ("readability-identifier-naming", "readability-avoid-nested-conditional-operator")

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


def check_changed_style(tidy, database, sources, changes):
    filters = []
    inputs = []
    for path, ranges in changes.items():
        if not native(path):
            continue
        name = str(path.absolute())
        entry = {"name": name}
        if ranges is not None:
            entry["lines"] = ranges
        filters.append(entry)
        if path.suffix == ".cpp":
            inputs.append(name)
    if not filters:
        return 0
    # clang-tidy diagnoses headers while parsing their including translation units.
    if len(inputs) != len(filters):
        inputs = sources
    return subprocess.run([tidy, "-p", database, "--checks=-*," + ",".join(ADVISORY_CHECKS),
                           "--line-filter=" + json.dumps(filters), *inputs]).returncode


def main(include, tidy, database_flag, database, *sources):
    changes = changed_sources()
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
        # Check braces and correctness across complete translation units. Only
        # naming and nested conditionals use the changed-line filter.
        disable_advisories = ",".join("-" + check for check in ADVISORY_CHECKS)
        result = subprocess.run([tidy, database_flag, database, "--checks=" + disable_advisories,
                                 *sources, f"--vfsoverlay={overlay}"])
        if result.returncode:
            return result.returncode
        return check_changed_style(tidy, database, sources, changes)


if __name__ == "__main__":
    sys.exit(main(*sys.argv[1:]))
