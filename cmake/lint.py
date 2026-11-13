"""Run clang-tidy with LLVM 23's co-allocated IR operand storage annotated."""
import json
from pathlib import Path
import re
import subprocess
import sys
import tempfile

from style import changed_sources, native, sources


CHANGED_LINE_CHECKS = ("readability-identifier-naming", "readability-avoid-nested-conditional-operator")

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


def check_changed_style(command, translation_units, changes):
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
        inputs = translation_units
    return subprocess.run([*command, "--checks=-*," + ",".join(CHANGED_LINE_CHECKS),
                           "--line-filter=" + json.dumps(filters), *inputs]).returncode


def main(include, tidy, database_flag, database, *translation_units):
    changes = changed_sources()
    headers = [str(path.absolute()) for path in sources() if native(path) and path.suffix == ".h"]
    header_filter = "^(" + "|".join(map(re.escape, headers)) + ")$" if headers else "^$"
    with tempfile.TemporaryDirectory() as temp:
        folder = Path(temp)
        # clang-tidy filters the spelling used by the include, which can contain
        # "..". Give each owned header its canonical name without changing its contents.
        files = [{"type": "file", "name": path, "external-contents": path, "use-external-name": True}
                 for path in headers]
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
        command = [tidy, database_flag, database, f"--config-file={Path.cwd() / '.clang-tidy'}",
                   f"--header-filter={header_filter}", f"--vfsoverlay={overlay}"]
        # Keep function-level diagnostics visible at declarations outside the diff.
        disable_changed_line_checks = ",".join("-" + check for check in CHANGED_LINE_CHECKS)
        result = subprocess.run([*command, "--checks=" + disable_changed_line_checks, *translation_units])
        if result.returncode:
            return result.returncode
        return check_changed_style(command, translation_units, changes)


if __name__ == "__main__":
    sys.exit(main(*sys.argv[1:]))
