"""Observations from the SDK-free C va_start wrapper and legacy DLL import."""
import hashlib
import json

VARIANTS = ("empty", "mixed", "numbers", "pointer", "boundary", "large",
            "null_format", "null_string", "unknown")


def observe(directory, destination, wine, declared, launch, windows_failure):
    from crt_streams import summarize
    observations = {}
    for variant in VARIANTS:
        pe = (directory / f"crt-vfprintf-{variant}.exe").resolve()
        digest = hashlib.sha256(pe.read_bytes()).hexdigest()
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
                    run, output = windows_failure(pe, [], mode, stderr)
                out.write_bytes(output)
            row = dict(pe=digest, status=run.returncode & 0xffffffff,
                       stdout=summarize(out.read_bytes()), stderr=summarize(err.read_bytes()))
            observations[key] = row
            print("vfprintf", key, row, flush=True)
    (destination / "vfprintf-observations.json").write_text(json.dumps(observations, indent=2))
