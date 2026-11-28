"""Capture raw x64 VirtualQuery records from the exact producer PEs on Windows and Wine."""
import hashlib
import json
import os
from pathlib import Path
import platform
import struct
import subprocess
import sys

from crt_streams import launch, producer_inputs

HERE = Path(__file__).resolve().parent
RECORD = struct.Struct("<IIQQQQ64sQ")
REFERENCE = "virtual-query-reference.exe"
QUERY = "executable-virtual-query.exe"
TRANSITIONS = "executable-virtual-query-transitions.exe"
ADDRESS = "executable-virtual-query-address.exe"


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def cases():
    yield ADDRESS, [], []
    yield QUERY, [], list(range(1, 21))
    yield TRANSITIONS, [], list(range(31, 38))
    for kind in ("headers", "gap"):
        yield f"executable-virtual-query-{kind}.exe", [], [41, 42]
    for index in range(33):
        markers = [100 + index]
        if 10 <= index <= 14 or 23 <= index <= 25 or index >= 27:
            markers.append(200 + index)
        if index >= 30:
            markers.append(300 + index)
        yield REFERENCE, [f"{index:02}"], markers


def decode(stdout, markers):
    if len(stdout) != len(markers) * RECORD.size:
        raise ValueError(f"expected {len(markers)} complete records, received {len(stdout)} bytes")
    rows = []
    for expected, record in zip(markers, RECORD.iter_unpack(stdout)):
        marker, error, result, image, query, length, window, output = record
        if marker != 0x51a70000 + expected:
            raise ValueError(f"missing VirtualQuery call {expected}, got {marker:#x}")
        rows.append(dict(id=expected, error=error, result=result, image=image, query=query,
                         length=length, bytes=window.hex(), output=output))
    return rows


def contract(rows, image_size):
    """Rebase only proven image VAs. Keep raw bytes (including padding) everywhere else."""
    normalized = []
    for row in rows:
        base = row["image"]
        window = bytearray.fromhex(row["bytes"])
        image_fields = []
        for offset in (8, 16):
            if row["result"] >= offset:
                va, = struct.unpack_from("<Q", window, offset)
                if base <= va < base + image_size:
                    struct.pack_into("<Q", window, offset, va - base)
                    image_fields.append(offset - 8)
        query = row["query"]
        query = {"rva": query - base} if base <= query < base + image_size else {"va": query}
        normalized.append(dict(id=row["id"], error=row["error"], result=row["result"],
                               query=query, length=row["length"], image_fields=image_fields,
                               bytes=window.hex()))
    return normalized


def image_size(pe):
    data = pe.read_bytes()
    header, = struct.unpack_from("<I", data, 60)
    return struct.unpack_from("<I", data, header + 24 + 56)[0]


def reference(backend, directory):
    """Derive comparable records from the retained independent child streams."""
    evidence = json.loads((HERE / f"virtual-query-{backend}.json").read_bytes())
    names = (HERE / "virtual-query-inputs.txt").read_text().splitlines()
    manifest = "".join(f"{evidence['inputs'][name]}  {name}\n" for name in names)
    if (set(names) != set(evidence["inputs"])
            or hashlib.sha256(manifest.encode()).hexdigest() != evidence["manifest"]):
        raise ValueError(f"inconsistent {backend} producer manifest")
    expected = dict(inputs=evidence["inputs"], cases={})
    for name, args, markers in cases():
        key = " ".join([name, *args])
        child = evidence["cases"][key]
        if child["status"] != 42 or child["stderr"]:
            raise ValueError(f"incomplete {backend} reference for {key}")
        rows = decode(bytes.fromhex(child["stdout"]), markers)
        expected["cases"][key] = contract(rows, image_size(directory / name))
    if expected["cases"].keys() != evidence["cases"].keys():
        raise ValueError(f"inconsistent {backend} child inventory")
    return expected


def identity(wine):
    environment = dict(host=platform.platform(), run=os.getenv("GITHUB_RUN_ID"))
    if wine:
        root = Path("/usr/lib/x86_64-linux-gnu/wine/x86_64-windows")
        environment.update(image=os.environ["FORGE_REFERENCE_IMAGE"],
                           wine=subprocess.check_output([wine, "--version"], text=True).strip())
    else:
        root = Path(os.environ["SystemRoot"]) / "System32"
        environment.update(image=os.getenv("ImageVersion"), build=platform.version())
    environment["dlls"] = {name: digest(root / name) for name in ("kernel32.dll", "kernelbase.dll", "ntdll.dll")}
    return environment


def observe(directory, destination, wine):
    directory = directory.resolve()
    destination.mkdir(parents=True, exist_ok=True)
    declared = producer_inputs(directory)
    names = (HERE / "virtual-query-inputs.txt").read_text().splitlines()
    inputs = {name: digest(directory / name) for name in names}
    if (inputs != declared or set(names) != {pe for pe, _, _ in cases()}
            or set(names) != {path.name for path in directory.glob("*.exe")}):
        raise ValueError("query PE inventory or producer digest mismatch")
    backend = "wine" if wine else "windows"
    raw = dict(environment=identity(wine), manifest=os.environ["PE_MANIFEST_SHA256"], inputs=inputs, cases={})
    observed = dict(inputs=inputs, cases={})
    failures = []
    for name, args, markers in cases():
        key = " ".join([name, *args])
        pe = directory / name
        try:
            child = launch(pe, args, wine, capture_output=True)
            raw["cases"][key] = dict(status=child.returncode, stdout=child.stdout.hex(), stderr=child.stderr.hex())
            if child.returncode != 42 or child.stderr:
                raise ValueError(f"exit {child.returncode}, stderr {child.stderr!r}")
            rows = decode(child.stdout, markers)
            raw["cases"][key]["records"] = rows
            observed["cases"][key] = contract(rows, image_size(pe))
        except (ValueError, OSError, RuntimeError, subprocess.SubprocessError) as error:
            failures.append(f"{key}: {error}")
    for filename, report in (("raw", raw), ("observed", observed)):
        (destination / f"{filename}.json").write_text(json.dumps(report, indent=2) + "\n")
    if failures:
        raise ValueError("\n".join(failures))
    expected = reference(backend, directory)
    if observed != expected:
        raise ValueError(f"{backend} VirtualQuery contract mismatch; see raw.json and observed.json")


if __name__ == "__main__":
    observe(Path(sys.argv[1]), Path(sys.argv[2]), os.getenv("FORGE_WINE"))
