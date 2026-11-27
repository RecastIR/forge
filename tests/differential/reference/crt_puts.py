"""Raw redirected observations of the SDK-free legacy puts executables."""
import hashlib
import json
from pathlib import Path

VARIANTS = ("hello", "mixed", "exit", "exitprocess", "null", "fault", "direct", "newline")


def observe_puts(directory, destination, wine, declared, launch, windows_failure):
    backend = "wine" if wine else "windows"
    observations = {}
    for variant in VARIANTS:
        pe = (directory / f"crt-puts-{variant}.exe").resolve()
        digest = hashlib.sha256(pe.read_bytes()).hexdigest()
        if digest != declared[pe.name]:
            raise ValueError(f"unexpected producer checksum for {pe.name}")
        modes = ["file", "pipe"]
        if not wine and variant in ("direct", "newline", "mixed"):
            modes.extend(("missing", "readonly", "broken", "short", "prefix"))
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
            else:
                with err.open("wb") as stderr:
                    result, output = windows_failure(pe, [], mode, stderr)
                out.write_bytes(output)
            stdout, stderr = out.read_bytes(), err.read_bytes()
            status = result.returncode & 0xffffffff
            def fingerprint(data):
                return data.hex() if len(data) < 128 else f"{len(data)} bytes sha256={hashlib.sha256(data).hexdigest()}"
            row = dict(status=status, stdout=fingerprint(stdout), stderr=fingerprint(stderr))
            observations[key] = row
            print(f"puts {backend} {key} {digest} {row}", flush=True)
    (destination / "puts-observations.json").write_text(json.dumps(observations, indent=2) + "\n")
