"""Capture redirected legacy streams from the same producer PE on Windows and Wine."""
import hashlib
import json
import os
from pathlib import Path
import struct
import subprocess
import sys
import tempfile


def summarize(data):
    return data.hex() if len(data) < 64 else f"{len(data)} bytes sha256={hashlib.sha256(data).hexdigest()}"


def observe(directory, destination):
    pe = (directory / "crt-stream-reference.exe").resolve()
    manifest = (directory / "SHA256SUMS").read_bytes()
    digest = hashlib.sha256(pe.read_bytes()).hexdigest()
    if (hashlib.sha256(manifest).hexdigest() != os.environ["PE_MANIFEST_SHA256"]
            or f"{digest}  {pe.name}" not in manifest.decode().splitlines()):
        raise ValueError("stream reference input hash mismatch")
    destination.mkdir(parents=True, exist_ok=True)
    observed = {}
    for redirect in ("pipe", "file"):
        for case in range(36):
            args = [pe, f"{case:02}"]
            prefix = destination / f"{redirect}-{case:02}"
            out, err = prefix.with_suffix(".stdout"), prefix.with_suffix(".stderr")
            if redirect == "file":
                with out.open("wb") as stdout, err.open("wb") as stderr:
                    run = subprocess.run(args, stdout=stdout, stderr=stderr, timeout=20)
            else:
                run = subprocess.run(args, capture_output=True, timeout=20)
                out.write_bytes(run.stdout)
                err.write_bytes(run.stderr)
            records, stream = (out, err) if case % 2 else (err, out)
            fields = list(struct.iter_unpack("<12Q", records.read_bytes()))
            status = run.returncode & 0xffffffff
            observed[prefix.name] = dict(status=status, records=fields, output=summarize(stream.read_bytes()))
            print(prefix.name, hex(status), fields[3:], observed[prefix.name]["output"], flush=True)
    (destination / "observations.json").write_text(json.dumps(observed, indent=2))


if __name__ == "__main__":
    observe(Path(sys.argv[1]), Path(sys.argv[2]))
