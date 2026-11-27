"""Observe detached legacy abort using the same full-DWORD child observer on both hosts."""
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import subprocess
import sys
import tempfile

from crt_streams import producer_inputs

VARIANTS = ("direct", "buffered", "control", "initializer", "cleanup")


def modes(variant):
    if variant == "direct":
        return ("pipe", "file", "absent-stderr", "broken-stderr")
    if variant in ("buffered", "control"):
        return ("pipe", "file", "merged")
    return ("pipe",)


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def guest_path(path, wine):
    return ("Z:" if wine else "") + str(path.resolve()).replace("/", "\\")


def observe(directory, destination, wine):
    directory = directory.resolve()
    declared = producer_inputs(directory)
    dest = destination.resolve() / "abort-observations"
    dest.mkdir(parents=True)
    backend = "wine" if wine else "windows"
    environment = dict(host=platform.platform(), run=os.getenv("GITHUB_RUN_ID"),
                       launch="DETACHED_PROCESS, STARTF_USESTDHANDLES, inherited error mode, no debugger")
    if wine:
        environment.update(version=subprocess.check_output([wine, "--version"], text=True).strip(),
                           package=subprocess.check_output(["dpkg-query", "-W", "wine64", "libwine"], text=True).strip(),
                           wine_debug=os.getenv("WINEDEBUG"), dll_overrides=os.getenv("WINEDLLOVERRIDES"))
    else:
        dll = Path(os.environ["SystemRoot"]) / "System32/msvcrt.dll"
        environment.update(dll=str(dll), sha256=digest(dll), image=os.getenv("ImageVersion"),
                           version=subprocess.check_output(["powershell", "-NoProfile", "-Command",
                               "(Get-Item $env:SystemRoot/System32/msvcrt.dll).VersionInfo.FileVersion"],
                               text=True).strip())

    inputs, rows = {}, {}
    with tempfile.TemporaryDirectory() as tmp:
        parent = Path(tmp) / "capture.exe"
        source = Path(__file__).with_name("amsg-exit") / "capture.c"
        subprocess.run(["x86_64-w64-mingw32-gcc-win32" if wine else "gcc", "-std=c11", "-O2",
                        str(source), "-o", str(parent)], check=True)
        for variant in VARIANTS:
            pe = directory / f"crt-abort-{variant}.exe"
            inputs[pe.name] = digest(pe)
            if declared.get(pe.name) != inputs[pe.name]:
                raise ValueError(f"producer mismatch for {pe.name}")
            for mode in modes(variant):
                key = f"{variant}-{mode}"
                work = dest / key
                cmd = ([wine] if wine else []) + [str(parent), guest_path(pe, wine), mode, guest_path(work, wine)]
                subprocess.run(cmd, check=True, timeout=45)
                match = re.fullmatch(r"exit=(\d+)\s*", (work / "observation.txt").read_text())
                if not match:
                    raise ValueError(f"{key}: missing child termination status")
                stdout = (work / "stdout.bin").read_bytes()
                if not stdout.startswith(b"RB"):
                    raise ValueError(f"{key}: child did not reach its call marker: {stdout!r}")
                stderr = ((work / "stderr.bin").read_bytes().hex()
                          if mode in ("pipe", "file") else None)
                rows[key] = dict(status=int(match[1]), stdout=stdout.hex(), stderr=stderr)
                print(backend, key, rows[key], flush=True)
    report = dict(environment=environment, inputs=inputs, cases=rows)
    (dest / "results.json").write_text(json.dumps(report, indent=2) + "\n")


if __name__ == "__main__":
    observe(Path(sys.argv[1]), Path(sys.argv[2]), os.environ.get("FORGE_WINE"))
