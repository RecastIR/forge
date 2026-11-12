"""Validate fixture contracts before exposing their build inputs to CMake."""
import argparse
from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import re
import sys

SUITE = Path(__file__).resolve().parent
FIXTURE_ID = re.compile(r"[a-z][a-z0-9_]*/[a-z][a-z0-9_]*")


def unique_keys(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key {key!r}")
        result[key] = value
    return result


def field(obj, name, kind):
    if type(obj) is not dict or type(obj.get(name)) is not kind:
        raise ValueError(f"{name} must be a {kind.__name__}")
    return obj[name]


def validate(case, root):
    if field(case, "schema_version", int) != 1:
        raise ValueError("expected schema_version 1")
    if not FIXTURE_ID.fullmatch(field(case, "id", str)):
        raise ValueError("id must be a lowercase category/name")
    if not field(case, "description", str).strip():
        raise ValueError("description must describe the fixture")
    source = field(case, "source", str)
    if not re.fullmatch(r"fixtures/(?:[A-Za-z0-9_-]+/)*[A-Za-z0-9_-]+\.(?:c|cpp)", source):
        raise ValueError(f"invalid relative fixture source {source!r}")
    path = (root / source).resolve(strict=True)
    if not path.is_file() or not path.is_relative_to(root / "fixtures"):
        raise ValueError(f"source outside fixture tree or not a file: {source!r}")
    binary = field(case, "binary", str)
    if (not re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9_-]*\.exe", binary)
            or re.fullmatch(r"(con|prn|aux|nul|com[1-9]|lpt[1-9])\.exe", binary, re.IGNORECASE)):
        raise ValueError("binary must be a portable .exe basename")
    for arg in field(case, "args", list):
        if type(arg) is not str or "\0" in arg:
            raise ValueError("args must contain strings without NUL")
        arg.encode("utf-8")
    expected = field(case, "expected", dict)
    if not 0 <= field(expected, "exit_code", int) <= 0xffffffff:
        raise ValueError("expected.exit_code must fit a Windows process exit code")
    for stream in ("stdout", "stderr"):
        field(expected, stream, str).encode("utf-8")


@dataclass(frozen=True)
class Manifest:
    case: dict
    path: str
    sha256: str


def load_catalog(root=SUITE):
    root = root.resolve()
    ids = set()
    binaries = set()
    cases = []
    for path in sorted((root / "manifests").rglob("*.json")):
        try:
            if not path.resolve(strict=True).is_relative_to(root / "manifests"):
                raise ValueError("manifest outside manifests directory")
            data = path.read_bytes()
            case = json.loads(data.decode("utf-8"), object_pairs_hook=unique_keys)
            validate(case, root)
            if case["id"] in ids:
                raise ValueError(f"duplicate id {case['id']!r}")
            if case["binary"].lower() in binaries:
                raise ValueError(f"duplicate binary {case['binary']!r}")
            ids.add(case["id"])
            binaries.add(case["binary"].lower())
            cases.append(Manifest(case, path.relative_to(root).as_posix(), hashlib.sha256(data).hexdigest()))
        except (ValueError, OSError, RuntimeError) as error:
            raise ValueError(f"{path}: {error}") from error
    if not cases:
        raise ValueError(f"{root / 'manifests'}: no fixture manifests")
    sources = {p.relative_to(root).as_posix() for p in (root / "fixtures").rglob("*")
               if p.suffix in (".c", ".cpp") and p.is_file()}
    missing = sources.difference(manifest.case["source"] for manifest in cases)
    if missing:
        raise ValueError(f"sources without manifests: {', '.join(sorted(missing))}")
    return cases


def load_cases(root=SUITE):
    return [manifest.case for manifest in load_catalog(root)]


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--catalog", action="store_true", help="print validated build inputs as JSON")
    args = parser.parse_args()
    try:
        cases = load_cases()
    except ValueError as error:
        sys.exit(str(error))
    if args.catalog:
        print(json.dumps([{key: case[key] for key in ("source", "binary")} for case in cases]))
    else:
        print(f"Validated {len(cases)} fixture manifests.")
