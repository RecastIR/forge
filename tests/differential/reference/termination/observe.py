"""Capture the focused, producer-hashed legacy CRT PEs on Windows or pinned Wine."""
import argparse
from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path, PureWindowsPath
import platform
import shutil
import struct
import subprocess
from zipfile import ZipFile


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def startup_fields(data):
    record_size = 104 + 3 * 8 + 4 + 3 * 260 * 2
    if len(data) != 4 * record_size:
        raise ValueError("incomplete before/after A/W records")
    rows = []
    for offset in range(0, len(data), record_size):
        info = data[offset:offset + 104]
        handles = struct.unpack_from("<3Q", info, 80)
        original = struct.unpack_from("<3Q", data, offset + 104)
        rows.append(dict(cb=struct.unpack_from("<I", info)[0], padding=[info[4:8].hex(), info[68:72].hex()],
                         pointer_present=[bool(struct.unpack_from("<Q", info, i)[0]) for i in (8, 16, 24, 72)],
                         window=list(struct.unpack_from("<8I2H", info, 32)),
                         handles=[dict(original=[i for i, value in enumerate(original) if h == value],
                                       sentinel=h == 0xbcbcbcbcbcbcbcbc, invalid=h == 2**64-1, null=h == 0)
                                  for h in handles], last_error=struct.unpack_from("<I", data, offset + 128)[0],
                         text=[data[offset + 132 + n * 520:offset + 132 + (n + 1) * 520]
                               .decode("utf-16le", errors="replace").split("\0", 1)[0] for n in range(3)]))
    return rows


def guest_path(pe, wine):
    return "Z:" + str(pe).replace("/", "\\") if wine else str(pe)


def observe(pe, work, clear, wine):
    work.mkdir()
    if wine and not clear:
        shared = Path(os.environ["WINEPREFIX"]) / "drive_c/work"
        app = guest_path(pe, wine)
        (work / "command.bin").write_bytes((app + "\0").encode("utf-16le"))
        subprocess.run([wine, r"Z:\opt\forge\capture.exe", app, "65536"], cwd=work,
                       check=True, timeout=150, stdout=subprocess.DEVNULL)
        status, = struct.unpack("<I", (work / "exit.bin").read_bytes())
        for name in ("record.bin", "buffered.bin"):
            if (shared / name).exists():
                shutil.move(shared / name, work / name)
    else:
        child = subprocess.run([wine, str(pe)] if wine else [str(pe)], cwd=work,
                               capture_output=not clear, timeout=120)
        status = child.returncode & 0xffffffff
        if not clear:
            (work / "stdout.bin").write_bytes(child.stdout)
            (work / "stderr.bin").write_bytes(child.stderr)
    row = {"exit_code": status}
    for name in ("stdout", "stderr", "buffered"):
        path = work / (name + ".bin")
        if path.exists():
            row[name + "_hex"] = path.read_bytes().hex()
    if pe.name.startswith("crt-term-"):
        row["callback_trace"] = bytes.fromhex(row["stdout_hex"]).decode("ascii")
    if pe.name.startswith("crt-observe-") and status != 77:
        data = (work / "record.bin").read_bytes()
        if "startup" in pe.name:
            row["startup"] = startup_fields(data)
        elif "stream" in pe.name:
            row["file_observations"] = list(struct.unpack("<" + "I" * (len(data) // 4), data))
        else:
            names = ("null_result", "null_last_error", "null_errno", "failure", "accepted",
                     "last_error", "errno", "executed", "cleanup_errno")
            row["registration"] = dict(zip(names, struct.unpack("<9I", data)))
    return row


def comparable(rows, *, launch_path):
    observations = deepcopy(rows)
    # Job limits constrain memory, while the exact number of successful allocations
    # also depends on heap layout. The number of callbacks must equal that count.
    pressure = observations["crt-observe-pressure-captured"]["registration"]
    accepted = pressure.pop("accepted")
    executed = pressure.pop("executed")
    if not 0 < accepted <= 4_000_000 or accepted != executed:
        raise ValueError(f"pressure probe accepted {accepted} handlers and ran {executed}")
    if not pressure["failure"] and accepted != 4_000_000:
        raise ValueError("pressure probe stopped before allocation failure or its limit")

    for mode in ("clear", "captured"):
        for row in observations[f"crt-observe-startup-{mode}"]["startup"]:
            # A runner work directory is part of the process title on these launches.
            title = row["text"][2]
            path = PureWindowsPath(title)
            if not path.is_absolute() or (launch_path is not None and title != launch_path):
                raise ValueError(f"{mode} startup title {title!r} differs from launch path {launch_path!r}")
            row["text"][2] = path.name
    return observations


def verify(results, reference, launch_path):
    with ZipFile(reference) as archive:
        reviewed = json.loads(archive.read("results.json"))
    if reviewed["pe_sha256"] != results["pe_sha256"]:
        raise ValueError("the captured PEs differ from the reviewed reference")
    # Old reviewed captures predate launch-path metadata. Their raw titles remain in the archive.
    expected = comparable(reviewed["observations"], launch_path=reviewed["environment"].get("startup_probe_path"))
    actual = comparable(results["observations"], launch_path=launch_path)
    if set(actual) != set(expected):
        raise ValueError("incomplete capture inventory")
    for case, observation in expected.items():
        if actual[case] != observation:
            raise ValueError(f"{case} differs from the reviewed reference: {actual[case]!r}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("inputs", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--wine")
    parser.add_argument("--reference", type=Path, help="reviewed raw capture archive to compare")
    parser.add_argument("--manifest-sha256", required=True)
    args = parser.parse_args()
    manifest = args.inputs / "SHA256SUMS"
    if digest(manifest) != args.manifest_sha256:
        raise ValueError("producer manifest digest mismatch")
    expected = Path(__file__).with_name("inputs.txt").read_text().splitlines()
    hashes = {name: value for value, name in (line.split() for line in manifest.read_text().splitlines())}
    if set(hashes) != set(expected) or any(digest(args.inputs / name) != hashes[name] for name in expected):
        raise ValueError("producer fixture inventory or hash mismatch")
    env = {"platform": platform.platform(), "image_version": os.getenv("ImageVersion"),
           "run": os.getenv("GITHUB_RUN_ID"), "commit": os.getenv("GITHUB_SHA")}
    if args.wine:
        env["wine"] = subprocess.check_output([args.wine, "--version"], text=True).strip()
    else:
        dll = Path(os.environ["SystemRoot"]) / "System32/msvcrt.dll"
        env["crt_sha256"] = digest(dll)
        env["crt_version"] = subprocess.check_output(
            ["powershell", "-NoProfile", "-Command", "(Get-Item $env:SystemRoot/System32/msvcrt.dll).VersionInfo.FileVersion"],
            text=True).strip()
    launch_path = guest_path((args.inputs / "crt-observe-startup.exe").resolve(), args.wine)
    env["startup_probe_path"] = launch_path
    args.output.mkdir(parents=True, exist_ok=False)
    results = {"environment": env, "pe_sha256": hashes, "observations": {}}
    for name in expected:
        modes = ("captured", "clear") if "startup" in name else ("captured",)
        for mode in modes:
            key = name[:-4] + "-" + mode
            results["observations"][key] = observe((args.inputs / name).resolve(), args.output / key,
                                                   mode == "clear", args.wine)
            (args.output / "results.json").write_text(json.dumps(results, indent=2) + "\n")

    if args.reference:
        verify(results, args.reference, launch_path)
    else:
        comparable(results["observations"], launch_path=launch_path)


if __name__ == "__main__":
    main()
