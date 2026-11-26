"""Capture independent full-width VirtualProtect observations from the producer's PEs."""
import hashlib
import json
import os
from pathlib import Path
import struct
import subprocess
import sys


def check_observation(backend, case, status, stdout, stderr):
    table = json.loads(Path(__file__).with_name("virtual-protect.json").read_text())
    expected = struct.pack("<7I", *table[backend][case])
    if (status, stdout, stderr) != (42, expected, b""):
        raise ValueError(f"{backend} case {case}: {status:#x} {stdout.hex()} {stderr.hex()}")


def observe(directory):
    manifest = (directory / "SHA256SUMS").read_bytes()
    if hashlib.sha256(manifest).hexdigest() != os.environ["PE_MANIFEST_SHA256"]:
        raise ValueError("producer manifest mismatch")
    for name, cases in (("virtual-protect-reference.exe", range(44)),
                        ("executable-virtual-protect.exe", [None]),
                        ("executable-virtual-protect-denied.exe", [None])):
        pe = (directory / name).resolve()
        digest = hashlib.sha256(pe.read_bytes()).hexdigest()
        if f"{digest}  {name}" not in manifest.decode().splitlines():
            raise ValueError(f"{name} checksum mismatch")
        for case in cases:
            args = [] if case is None else [f"{case:02}"]
            run = subprocess.run([pe, *args], capture_output=True, timeout=30)
            status = run.returncode & 0xffffffff
            fields = struct.unpack("<7I", run.stdout) if len(run.stdout) == 28 else ()
            print(name, digest, case, hex(status), fields, run.stdout.hex(), run.stderr.hex(), flush=True)
            if name == "executable-virtual-protect-denied.exe":
                assert (status, run.stdout, run.stderr) == (0xc0000005, b"", b"")
            elif case is None:
                assert (status, run.stdout, run.stderr) == (42, b"", b"")
            elif not (status == 42 and fields and fields[0] == 4096 or status == 0xc0000005):
                raise ValueError(f"unexpected observer outcome for case {case}")


if __name__ == "__main__":
    observe(Path(sys.argv[1]))
