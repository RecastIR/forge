"""Observations from the SDK-free C va_start wrapper and legacy DLL import."""
import hashlib
import json
import os
import sys
from functools import cache
from pathlib import Path

from crt_streams import launch, producer_inputs, summarize, windows_output_failure

VARIANTS = ("empty", "mixed", "numbers", "pointer", "boundary", "large",
            "null_format", "null_string", "unknown", "null_stream", "edges", "mapped")


@cache
def baseline():
    return json.loads(Path(__file__).with_name("crt-vfprintf.json").read_bytes())


def check_input(pe):
    digest = hashlib.sha256(pe.read_bytes()).hexdigest()
    if digest != baseline()["inputs"][pe.name]:
        raise ValueError(f"unexpected {pe.name} checksum {digest}")
    return digest


def check_observation(backend, variant, mode, status, stdout, stderr):
    key = variant if mode in ("pipe", "file") else f"{variant}-{mode}"
    row = dict(status=status, stdout=summarize(stdout), stderr=summarize(stderr))
    wanted = baseline()[backend][key]
    if row != wanted:
        raise ValueError(f"vfprintf {backend} {variant}-{mode}: observed {row}, expected {wanted}")
    return row


def observe(directory, destination, wine):
    declared = producer_inputs(directory)
    destination.mkdir(parents=True, exist_ok=True)
    backend = "wine" if wine else "windows"
    observations = {}

    for variant in VARIANTS:
        pe = (directory / f"crt-vfprintf-{variant}.exe").resolve()
        digest = check_input(pe)
        if declared.get(pe.name) != digest:
            raise ValueError(f"producer checksum mismatch for {pe.name}")
        modes = ["pipe", "file"]
        if not wine and variant in ("boundary", "large", "empty"):
            modes += ["broken", "short", "missing", "full"]
        for mode in modes:
            key = variant + "-" + mode
            prefix = destination / ("vfprintf-" + key)
            out, err = prefix.with_suffix(".stdout"), prefix.with_suffix(".stderr")
            if mode == "pipe":
                run = launch(pe, [], wine, capture_output=True)
                out.write_bytes(run.stdout)
                err.write_bytes(run.stderr)
            elif mode == "file":
                with out.open("wb") as stdout, err.open("wb") as stderr:
                    run = launch(pe, [], wine, stdout=stdout, stderr=stderr)
            else:
                with err.open("wb") as stderr:
                    run, output = windows_output_failure(pe, [], mode, stderr)
                out.write_bytes(output)
            row = check_observation(backend, variant, mode, run.returncode & 0xffffffff,
                                    out.read_bytes(), err.read_bytes())
            observations[key] = dict(pe=digest, **row)
            print("vfprintf", key, observations[key], flush=True)
    ordinary = {f"{variant}-{mode}" for variant in VARIANTS for mode in ("pipe", "file")}
    failures = baseline()[backend].keys() - set(VARIANTS)
    if observations.keys() != ordinary | failures:
        raise ValueError(f"{backend}: incomplete vfprintf observations")
    (destination / "vfprintf-observations.json").write_text(json.dumps(observations, indent=2))


if __name__ == "__main__":
    observe(Path(sys.argv[1]), Path(sys.argv[2]), os.environ.get("FORGE_WINE"))
