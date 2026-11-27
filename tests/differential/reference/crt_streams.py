"""Capture redirected legacy streams from the same producer PE on Windows and Wine."""
import hashlib
import json
import os
from pathlib import Path
import struct
import subprocess
import sys


def summarize(data):
    return data.hex() if len(data) < 64 else f"{len(data)} bytes sha256={hashlib.sha256(data).hexdigest()}"


def observe(directory, destination, wine=None):
    pe = (directory / "crt-stream-reference.exe").resolve()
    manifest = (directory / "SHA256SUMS").read_bytes()
    digest = hashlib.sha256(pe.read_bytes()).hexdigest()
    if (hashlib.sha256(manifest).hexdigest() != os.environ["PE_MANIFEST_SHA256"]
            or f"{digest}  {pe.name}" not in manifest.decode().splitlines()):
        raise ValueError("stream reference input hash mismatch")
    destination.mkdir(parents=True, exist_ok=True)
    observed = {}
    if not wine:
        dll = Path(os.environ["SystemRoot"]) / "System32/msvcrt.dll"
        version = subprocess.check_output(["powershell", "-NoProfile", "-Command",
            "(Get-Item $env:SystemRoot/System32/msvcrt.dll).VersionInfo.FileVersion"], text=True).strip()
        print("Windows MSVCRT", version, hashlib.sha256(dll.read_bytes()).hexdigest(), digest, flush=True)
    for redirect in ("pipe", "file"):
        for case in range(48):
            args = [pe, f"{case:02}"]
            if wine:
                args = [wine, *args]
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
            raw = records.read_bytes()
            if run.returncode not in (42, 255):
                # The Wine debugger may also write a crash report to the child stream.
                raw = raw[:3 * 96]
            if case // 2 == 18:
                raw = raw[:4 * 96]  # The native fatal diagnostic can share the log descriptor.
            fields = list(struct.iter_unpack("<12Q", raw))
            status = run.returncode & 0xffffffff
            observed[prefix.name] = dict(status=status, records=fields, output=summarize(stream.read_bytes()))
            print(prefix.name, hex(status), fields[3:], observed[prefix.name]["output"], flush=True)
    for pe_name in ("crt-stream-return.exe", "crt-stream-exit.exe", "crt-stream-state.exe", "crt-stream-sections.exe"):
        focus = (directory / pe_name).resolve()
        checksum = hashlib.sha256(focus.read_bytes()).hexdigest()
        if f"{checksum}  {pe_name}" not in manifest.decode().splitlines():
            raise ValueError(f"{pe_name} checksum mismatch")
        args = [wine, focus] if wine else [focus]
        for merged in (False, True):
            run = subprocess.run(args, stdout=subprocess.PIPE,
                                 stderr=subprocess.STDOUT if merged else subprocess.PIPE, timeout=20)
            key = pe_name + ("-merged" if merged else "")
            observed[key] = dict(status=run.returncode, stdout=run.stdout.hex(),
                                 stderr=(run.stderr or b"").hex())
            print(key, checksum, observed[key], flush=True)
    if not wine:
        observed.update(output_failures(pe, destination))
    (destination / "observations.json").write_text(json.dumps(observed, indent=2))


def output_failures(pe, directory):
    """Keep the diagnostic channel independent of the deliberately unusable stdout."""
    import msvcrt
    rows = {}
    for name in ("missing", "broken", "short"):
        for case in (0, 16):
            with (directory / f"{name}-{case}.records").open("wb") as log:
                if name == "missing":
                    info = subprocess.STARTUPINFO()
                    info.dwFlags |= subprocess.STARTF_USESTDHANDLES
                    info.hStdInput = info.hStdOutput = 0
                    info.hStdError = msvcrt.get_osfhandle(log.fileno())
                    os.set_handle_inheritable(info.hStdError, True)
                    run = subprocess.run([pe, f"{case:02}"], startupinfo=info, close_fds=False,
                                         timeout=20)
                    output = b""
                else:
                    read, write = os.pipe()
                    with os.fdopen(write, "wb", buffering=0) as writer:
                        if name == "broken":
                            os.close(read)
                        else:
                            os.set_blocking(write, False)
                            # Reserve seven physical bytes for the child. The first
                            # translated block includes NUL, LF and CRLF.
                            filled = 0
                            while filled < 1 << 20:
                                try:
                                    n = writer.write(b"F" * 4096)
                                except OSError:
                                    break
                                if not n:
                                    break
                                filled += n
                            if not 7 < filled < 1 << 20 or os.read(read, 7) != b"F" * 7:
                                raise ValueError("nonblocking pipe did not reach its capacity")
                        run = subprocess.run([pe, f"{case:02}"], stdout=writer, stderr=log, timeout=20)
                    output = b""
                    if name == "short":
                        with os.fdopen(read, "rb") as reader:
                            remaining = reader.read()
                        if not remaining.startswith(b"F" * (filled - 7)):
                            raise ValueError("child modified pipe prefix")
                        output = remaining[filled - 7:]
            fields = list(struct.iter_unpack("<12Q", Path(log.name).read_bytes()))
            key = f"{name}-{case}"
            rows[key] = dict(status=run.returncode & 0xffffffff, records=fields, output=output.hex())
            print(key, rows[key], flush=True)
    return rows


if __name__ == "__main__":
    observe(Path(sys.argv[1]), Path(sys.argv[2]), os.environ.get("FORGE_WINE"))
