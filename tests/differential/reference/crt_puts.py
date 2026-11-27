"""Raw redirected observations of the SDK-free legacy puts executables."""
import hashlib
import json
import os
from pathlib import Path
import re

from crt_streams import summarize

VARIANTS = ("hello", "mixed", "exit", "exitprocess", "null", "fault", "direct", "newline")


def baseline():
    return json.loads(Path(__file__).with_name("crt-puts.json").read_bytes())


def check_input(pe):
    digest = hashlib.sha256(pe.read_bytes()).hexdigest()
    if digest != baseline()["inputs"][pe.name]:
        raise ValueError(f"unexpected {pe.name} checksum {digest}")
    return digest


def observation(backend, variant, status, stdout, stderr):
    if backend == "wine" and variant in ("fault", "null"):
        # Check both debugger boundaries before dropping the volatile dump.
        report = re.match(rb"Unhandled exception: page fault on read access to 0x([0-9a-f]+) in 64-bit code", stdout)
        notice = re.fullmatch(rb"wine: Unhandled page fault on read access to ([0-9A-Fa-f]+) at address "
                              rb"[0-9A-Fa-f]+ \(thread [0-9A-Fa-f]+\), starting debugger\.\.\.\n", stderr)
        if not report or not notice or int(report[1], 16) != int(notice[1], 16) or b"Q\r\n" in stdout:
            raise ValueError(f"{variant}: unexpected Wine diagnostic boundary")
        if (int(report[1], 16) == 0) != (variant == "null"):
            raise ValueError(f"{variant}: unexpected Wine fault address")
        return dict(status=status, stdout="Wine read fault", stderr="Wine debugger notice")
    return dict(status=status, stdout=summarize(stdout), stderr=summarize(stderr))


def check_observation(backend, variant, mode, status, stdout, stderr):
    key = variant if mode in ("pipe", "file") else f"{variant}-{mode}"
    row = observation(backend, variant, status, stdout, stderr)
    wanted = baseline()[backend][key]
    if row != wanted:
        raise ValueError(f"puts {backend} {variant}-{mode}: observed {row}, expected {wanted}")
    return row


def observe_puts(directory, destination, wine, declared, launch, windows_failure):
    backend = "wine" if wine else "windows"
    observations = {}
    for variant in VARIANTS:
        pe = (directory / f"crt-puts-{variant}.exe").resolve()
        digest = check_input(pe)
        if digest != declared[pe.name]:
            raise ValueError(f"unexpected producer checksum for {pe.name}")
        modes = ["file", "pipe"]
        if variant in ("direct", "newline", "mixed"):
            modes.extend(("readonly", "broken"))
            if not wine:
                modes.extend(("missing", "full", "short", "prefix"))
        for mode in modes:
            key = f"{variant}-{mode}"
            prefix = destination / ("puts-" + key)
            out, err = prefix.with_suffix(".stdout"), prefix.with_suffix(".stderr")
            if mode == "pipe":
                result = launch(pe, [], wine, capture_output=True)
                out.write_bytes(result.stdout)
                err.write_bytes(result.stderr)
            elif mode == "file":
                with out.open("wb") as stdout, err.open("wb") as stderr:
                    result = launch(pe, [], wine, stdout=stdout, stderr=stderr)
            elif mode == "readonly":
                with pe.open("rb") as reader, err.open("wb") as stderr:
                    result = launch(pe, [], wine, stdout=reader, stderr=stderr)
                out.write_bytes(b"")
            elif wine and mode == "broken":
                read, write = os.pipe()
                os.close(read)
                with os.fdopen(write, "wb") as writer, err.open("wb") as stderr:
                    result = launch(pe, [], wine, stdout=writer, stderr=stderr)
                out.write_bytes(b"")
            else:
                with err.open("wb") as stderr:
                    result, output = windows_failure(pe, [], mode, stderr)
                out.write_bytes(output)
            stdout, stderr = out.read_bytes(), err.read_bytes()
            status = result.returncode & 0xffffffff
            row = check_observation(backend, variant, mode, status, stdout, stderr)
            observations[key] = row
            print(f"puts {backend} {key} {digest} {row}", flush=True)
    (destination / "puts-observations.json").write_text(json.dumps(observations, indent=2) + "\n")
