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


def evidence(backend):
    return json.loads(Path(__file__).with_name(f"crt-stream-{backend}.json").read_bytes())


def block_records(cases, setup=None):
    """Project the three independent C observations onto the assembly fixture's record layout."""
    output = cases[f"{setup}-16" if setup else "16"]
    initial = output["records"][:3]
    rows = []
    for case, index in (("06", 1), ("18", 0), (None, 1)):
        row = (cases[case] if case else output)["records"][3]
        rows.append(struct.pack("<Q4I", *row[:3], row[7], initial[index][8]))
    return b"".join(rows)


def focused_output(backend, name, directory):
    baseline = evidence(backend)
    pe = directory / f"crt-stream-{name}.exe"
    if hashlib.sha256(pe.read_bytes()).hexdigest() != baseline["inputs"][pe.name]:
        raise ValueError(f"unexpected {name} PE")
    if name == "block":
        return 42, b"A\0\r\n\r\r\nZ" + bytes(8186), block_records(baseline["cases"])
    row = baseline["cases"][pe.name]
    return row["status"], bytes.fromhex(row["stdout"]), bytes.fromhex(row["stderr"])


def launch(pe, args, wine, **streams):
    if not wine:
        with open(os.devnull, "rb") as stdin:
            return subprocess.run([pe, *args], stdin=stdin, timeout=20, **streams)

    app = "Z:" + str(pe).replace("/", "\\")
    with tempfile.TemporaryDirectory() as temporary:
        work = Path(temporary)
        (work / "command.bin").write_bytes(subprocess.list2cmdline([app, *args]).encode("utf-16-le"))
        run = subprocess.run([wine, r"Z:\opt\forge\capture.exe", app, "65536", "inherit"],
                             cwd=work, timeout=30, **streams)
        if run.returncode or not (work / "ready").is_file():
            raise RuntimeError(f"Wine capture parent failed before reporting {pe.name} {args}: {run.returncode}")
        status, = struct.unpack("<I", (work / "exit.bin").read_bytes())
        return subprocess.CompletedProcess([pe, *args], status, run.stdout, run.stderr)


def stream_observation(case, status, stdout, stderr, expected, wine):
    record = struct.Struct("<12Q")
    records, output = (stdout, stderr) if case % 2 else (stderr, stdout)
    end = len(expected["records"]) * record.size
    if len(records) < end:
        raise ValueError("missing CRT stream records")
    fields = list(record.iter_unpack(records[:end]))
    suffix = records[end:]
    row = dict(status=status, records=fields, output=summarize(output))
    if wine and status == 0xc0000005:
        # Wine writes the debugger report to stdout and the launch notice to stderr.
        report, notice = (suffix, output) if case % 2 else (output, suffix)
        if not (report.startswith(b"Unhandled exception: page fault on ") and
                notice.startswith(b"wine: Unhandled page fault on ")):
            raise ValueError("unexpected bytes at Wine debugger boundary")
        row["output"] = "wine page fault"
    elif case // 2 == 18:
        row["log_suffix"] = suffix.hex()
    elif suffix:
        raise ValueError("unexpected bytes after CRT stream records")
    return row


def observe(directory, destination, wine=None):
    pe = (directory / "crt-stream-reference.exe").resolve()
    manifest = (directory / "SHA256SUMS").read_bytes()
    digest = hashlib.sha256(pe.read_bytes()).hexdigest()
    backend = "wine" if wine else "windows"
    expected = evidence(backend)
    if hashlib.sha256(manifest).hexdigest() != os.environ["PE_MANIFEST_SHA256"]:
        raise ValueError("producer manifest checksum mismatch")
    declared = {name: sha for sha, name in (line.split("  ", 1) for line in manifest.decode().splitlines())}
    for name, checksum in {pe.name: expected["observer"], **expected["inputs"]}.items():
        if declared.get(name) != checksum or hashlib.sha256((directory / name).read_bytes()).hexdigest() != checksum:
            raise ValueError(f"{backend}: {name} checksum mismatch")
    destination.mkdir(parents=True, exist_ok=True)
    from crt_puts import observe_puts
    observe_puts(directory, destination, wine, declared, launch, windows_output_failure)
    observed = {}
    if not wine:
        dll = Path(os.environ["SystemRoot"]) / "System32/msvcrt.dll"
        version = subprocess.check_output(["powershell", "-NoProfile", "-Command",
            "(Get-Item $env:SystemRoot/System32/msvcrt.dll).VersionInfo.FileVersion"], text=True).strip()
        print("Windows MSVCRT", version, hashlib.sha256(dll.read_bytes()).hexdigest(), digest, flush=True)
    for redirect in ("pipe", "file"):
        for case in range(48):
            args = [f"{case:02}"]
            prefix = destination / f"{redirect}-{case:02}"
            out, err = prefix.with_suffix(".stdout"), prefix.with_suffix(".stderr")
            if redirect == "file":
                with out.open("wb") as stdout, err.open("wb") as stderr:
                    run = launch(pe, args, wine, stdout=stdout, stderr=stderr)
            else:
                run = launch(pe, args, wine, capture_output=True)
                out.write_bytes(run.stdout)
                err.write_bytes(run.stderr)
            status = run.returncode & 0xffffffff
            try:
                row = stream_observation(case, status, out.read_bytes(), err.read_bytes(),
                                         expected["cases"][args[0]], wine)
            except ValueError as exc:
                raise ValueError(f"{prefix.name}: {exc}") from exc
            observed[prefix.name] = row
            print(prefix.name, hex(status), row["records"][3:], row["output"], flush=True)
    for pe_name in ("crt-stream-return.exe", "crt-stream-exit.exe", "crt-stream-state.exe", "crt-stream-sections.exe"):
        focus = (directory / pe_name).resolve()
        checksum = hashlib.sha256(focus.read_bytes()).hexdigest()
        for merged in (False, True):
            run = launch(focus, [], wine, stdout=subprocess.PIPE,
                         stderr=subprocess.STDOUT if merged else subprocess.PIPE)
            key = pe_name + ("-merged" if merged else "")
            observed[key] = dict(status=run.returncode, stdout=run.stdout.hex(),
                                 stderr=(run.stderr or b"").hex())
            print(key, checksum, observed[key], flush=True)
    invalid = (directory / "crt-stream-invalid.exe").resolve()
    if not wine:
        run = launch(invalid, [], wine, capture_output=True)
        if (run.returncode & 0xffffffff, run.stdout, run.stderr) != (0xc0000005, b"", b""):
            raise ValueError(f"invalid FILE: {run.returncode:#x} {run.stdout.hex()} {run.stderr.hex()}")
    block = (directory / "crt-stream-block.exe").resolve()
    run = launch(block, [], wine, capture_output=True)
    if (run.returncode, run.stdout, run.stderr) != focused_output(backend, "block", directory):
        raise ValueError(f"{backend}: direct transfer record mismatch {run.stderr.hex()}")
    if not wine:
        observed.update(output_failures(pe, destination))
        output_failures(block, destination, block=True)
    (destination / "observations.json").write_text(json.dumps(observed, indent=2))
    # JSON normalizes the unpacked tuples to arrays. Both redirections must match
    # each independently captured row, including statuses and output hashes.
    checked = set()
    for key, row in json.loads(json.dumps(observed)).items():
        case = key.split("-", 1)[1] if key.startswith(("pipe-", "file-")) else key
        checked.add(case)
        if row != expected["cases"][case]:
            raise ValueError(f"{backend} {key}: observed {row}, expected {expected['cases'][case]}")
    if checked != expected["cases"].keys():
        raise ValueError(f"{backend}: missing observations {expected['cases'].keys() - checked}")
    print(f"{backend}: verified {len(observed)} observations")


def windows_output_failure(pe, args, name, log):
    import _winapi
    import msvcrt
    if name == "missing":
        info = subprocess.STARTUPINFO()
        info.dwFlags |= subprocess.STARTF_USESTDHANDLES
        info.hStdInput = info.hStdOutput = 0
        info.hStdError = msvcrt.get_osfhandle(log.fileno())
        os.set_handle_inheritable(info.hStdError, True)
        run = subprocess.run([pe, *args], startupinfo=info, close_fds=False,
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
                room = {"prefix": 5119, "short": 7, "full": 0}[name]
                filled = 0
                while filled < 1 << 20:
                    try:
                        n = writer.write(b"F" * 4096)
                    except OSError:
                        break
                    if not n:
                        break
                    filled += n
                if not room < filled < 1 << 20 or (room and os.read(read, room) != b"F" * room):
                    raise ValueError("nonblocking pipe did not reach its capacity")
            run = launch(pe, args, None, stdout=writer, stderr=log)
        output = b""
        if name in ("short", "prefix", "full"):
            with os.fdopen(read, "rb") as reader:
                remaining = reader.read()
            if not remaining.startswith(b"F" * (filled - room)):
                raise ValueError("child modified pipe prefix")
            output = remaining[filled - room:]
    return run, output


def output_failures(pe, directory, block=False):
    """Keep the diagnostic channel independent of the deliberately unusable stdout."""
    rows = {}
    for name in ("missing", "broken", "short", "prefix"):
        for case in ((16,) if block or name == "prefix" else (0, 16)):
            with (directory / (("block-" if block else "") + f"{name}-{case}.records")).open("wb") as log:
                run, output = windows_output_failure(pe, [f"{case:02}"], name, log)
            raw = Path(log.name).read_bytes()
            if block:
                cases = evidence("windows")["cases"]
                baseline = cases[f"{name}-16"]
                # The C observer adds two independent Win32 markers after the CRT call.
                wanted = "" if name == "short" else baseline["output"]
                if (run.returncode, summarize(output), raw) != (42, wanted, block_records(cases, name)):
                    raise ValueError(f"block {name}: {run.returncode} {summarize(output)} {raw.hex()}")
                continue
            fields = list(struct.iter_unpack("<12Q", raw))
            key = f"{name}-{case}"
            rows[key] = dict(status=run.returncode & 0xffffffff, records=fields, output=summarize(output))
            print(key, rows[key], flush=True)
    return rows


if __name__ == "__main__":
    observe(Path(sys.argv[1]), Path(sys.argv[2]), os.environ.get("FORGE_WINE"))
