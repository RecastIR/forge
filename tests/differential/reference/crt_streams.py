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
    backend = "wine" if wine else "windows"
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
            if wine and status == 5:
                if b"page fault" not in (out.read_bytes() + err.read_bytes()).lower():
                    raise ValueError(f"{prefix.name}: missing Wine page fault diagnostic")
                observed[prefix.name]["output"] = "wine page fault"
            elif case // 2 == 18:
                observed[prefix.name]["log_suffix"] = records.read_bytes()[len(raw):].hex()
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
    baseline = Path(__file__).with_name(f"crt-stream-{backend}.json")
    expected = json.loads(baseline.read_bytes())
    if digest != expected["observer"]:
        raise ValueError(f"{backend}: unexpected observer PE {digest}")
    # JSON normalizes the unpacked tuples to arrays. Both redirections must match
    # each independently captured row, including statuses and output hashes.
    for key, row in json.loads(json.dumps(observed)).items():
        case = key.split("-", 1)[1] if key.startswith(("pipe-", "file-")) else key
        if row != expected["cases"][case]:
            raise ValueError(f"{backend} {key}: observed {row}, expected {expected['cases'][case]}")
    print(f"{backend}: verified {len(observed)} observations")


def output_failures(pe, directory):
    """Keep the diagnostic channel independent of the deliberately unusable stdout."""
    import _winapi
    import msvcrt
    rows = {}
    for name in ("missing", "broken", "short", "prefix"):
        for case in ((16,) if name == "prefix" else (0, 16)):
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
                    if name == "prefix":
                        r_handle, w_handle = _winapi.CreatePipe(None, 16384)
                        read = msvcrt.open_osfhandle(r_handle, os.O_RDONLY | os.O_BINARY)
                        write = msvcrt.open_osfhandle(w_handle, os.O_WRONLY | os.O_BINARY)
                    else:
                        read, write = os.pipe()
                    with os.fdopen(write, "wb", buffering=0) as writer:
                        if name == "broken":
                            os.close(read)
                        else:
                            os.set_blocking(write, False)
                            # The DLL fills a 5120-byte staging area until at least
                            # 5119 physical bytes are ready or the input is exhausted.
                            room = 5119 if name == "prefix" else 7
                            filled = 0
                            while filled < 1 << 20:
                                try:
                                    n = writer.write(b"F" * 4096)
                                except OSError:
                                    break
                                if not n:
                                    break
                                filled += n
                            if not room < filled < 1 << 20 or os.read(read, room) != b"F" * room:
                                raise ValueError("nonblocking pipe did not reach its capacity")
                        run = subprocess.run([pe, f"{case:02}"], stdout=writer, stderr=log, timeout=20)
                    output = b""
                    if name in ("short", "prefix"):
                        with os.fdopen(read, "rb") as reader:
                            remaining = reader.read()
                        if not remaining.startswith(b"F" * (filled - room)):
                            raise ValueError("child modified pipe prefix")
                        output = remaining[filled - room:]
            fields = list(struct.iter_unpack("<12Q", Path(log.name).read_bytes()))
            key = f"{name}-{case}"
            rows[key] = dict(status=run.returncode & 0xffffffff, records=fields, output=summarize(output))
            print(key, rows[key], flush=True)
    return rows


if __name__ == "__main__":
    observe(Path(sys.argv[1]), Path(sys.argv[2]), os.environ.get("FORGE_WINE"))
