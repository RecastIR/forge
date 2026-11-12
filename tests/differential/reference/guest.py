"""Container entry point. Only the framed result goes to Docker stdout."""
import json
import os
from pathlib import Path
import struct
import subprocess
import sys
import time

from build import inspect_image
from protocol import READY, STREAM_LIMIT

WINE = "/usr/lib/wine/wine64"
WINE_ENV = ("HOME", "PATH", "LC_ALL", "TZ", "WINEPREFIX", "WINEARCH", "WINEDEBUG",
            "WINEDLLOVERRIDES", "ROSETTA_ADVERTISE_AVX")


def execute(binary, args):
    path = Path("/input") / binary
    try:
        inspect_image(path)
    except (ValueError, subprocess.CalledProcessError) as error:
        raise ValueError(f"invalid or unsupported PE binary: {error}") from error
    env = {key: os.environ[key] for key in WINE_ENV}
    version = subprocess.check_output([WINE, "--version"], text=True, env=env).strip()
    app = "Z:\\input\\" + binary
    command = subprocess.list2cmdline([app, *args]).encode("utf-16-le")
    if len(command) > 32766 * 2:
        raise ValueError("Windows command line exceeds 32767 UTF-16 code units including NUL")
    control = Path("/tmp/forge-capture")
    control.mkdir()
    os.chdir(control)
    Path("command.bin").write_bytes(command)
    wine = subprocess.Popen([WINE, r"Z:\opt\forge\capture.exe", app, str(STREAM_LIMIT)],
                            stdin=subprocess.DEVNULL, stdout=sys.stderr, env=env)
    while not Path("ready").exists() and wine.poll() is None:
        time.sleep(0.01)
    if not Path("ready").is_file():
        raise ValueError(f"Wine startup failure (launcher status {wine.wait()})")
    out = sys.stdout.buffer
    out.write(READY)
    out.flush()
    if wine.wait() != 0:
        raise ValueError(f"Wine capture failure (launcher status {wine.returncode})")
    status, = struct.unpack("<I", Path("exit.bin").read_bytes())
    streams = []
    for filename in ("stdout.bin", "stderr.bin"):
        with open(filename, "rb") as capture:
            data = capture.read(STREAM_LIMIT + 1)
        if len(data) > STREAM_LIMIT:
            raise ValueError(f"output-size limit exceeded: {filename}")
        streams.append(data)
    header = dict(exit_code=status, wine_version=version,
                  stdout_size=len(streams[0]), stderr_size=len(streams[1]))
    out.write(json.dumps(header).encode("ascii") + b"\n")
    for stream in streams:
        out.write(stream)


if __name__ == "__main__":
    try:
        execute(sys.argv[1], sys.argv[2:])
    except (OSError, ValueError, struct.error, subprocess.SubprocessError) as error:
        sys.exit(str(error))
