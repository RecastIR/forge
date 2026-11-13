"""Compile a generated module through the Forge CMake project and observe its harness."""
from contextlib import nullcontext, suppress
import errno
import os
from pathlib import Path
import platform
import selectors
import signal
import subprocess
import tempfile
import time

from comparison import Observation
from manifests import SUITE

from docker_wine import EXECUTION_TIMEOUT
from protocol import STREAM_LIMIT

OPTIMIZED_IR = Path("native/tests/optimized.ll")


class ExecutionFailure(ValueError):
    def __init__(self, outcome, message, status=None):
        super().__init__(message)
        self.outcome = outcome
        self.status = status


def kill_group(process):
    with suppress(ProcessLookupError):
        try:
            os.killpg(process.pid, signal.SIGKILL)
            return
        except PermissionError as error:
            if error.errno != errno.EPERM or platform.system() != "Darwin":
                raise
        # macOS can report EPERM when the only group member is exiting.
        # Reap it if possible, then signal the group again for any descendants.
        with suppress(subprocess.TimeoutExpired):
            process.wait(timeout=0.1)
        os.killpg(process.pid, signal.SIGKILL)


def command(args, log, stdout=None, *, timeout=180):
    with log.open("ab") as errors, (stdout.open("wb") if stdout else nullcontext(errors)) as output:
        with subprocess.Popen(args, stdout=output, stderr=errors, start_new_session=True) as process:
            try:
                status = process.wait(timeout=timeout)
            except BaseException:
                kill_group(process)
                process.wait()
                raise
    if status:
        with log.open("rb") as stream:
            stream.seek(max(0, log.stat().st_size - 4096))
            tail = stream.read().decode("utf-8", "backslashreplace")
        raise ValueError(f"{args[0]} exited {status} ({log.name})\n{tail}")


def build(ir, harness, work, config, variant):
    if (platform.system(), platform.machine()) != ("Darwin", "arm64"):
        raise ValueError("native differential execution requires macOS arm64")
    tree = work / "native"
    log = work / "compilation.log"
    name = "differential_" + harness
    configure = ["cmake", "-S", SUITE.parents[1], "-B", tree, "-DBUILD_TESTING=OFF",
                 f"-DFORGE_DIFFERENTIAL_IR={ir}", f"-DFORGE_DIFFERENTIAL_VARIANT={variant}",
                 f"-DCMAKE_BUILD_TYPE={config.capitalize()}"]
    build_target = ["cmake", "--build", tree, "--config", config.capitalize(), "--target"]
    for phase, args in (("configuration", configure), ("object compilation", [*build_target, name + "_objects"]),
                        ("linking", [*build_target, name])):
        with log.open("a") as stream:
            print(f"\n--- {phase} ---", file=stream)
        try:
            command(args, log)
        except (OSError, ValueError, subprocess.SubprocessError) as error:
            raise ValueError(f"native {phase} failed: {error}") from error
    executable = tree / "bin" / name
    if not executable.is_file() or not os.access(executable, os.X_OK):
        raise ValueError(f"native linking did not produce an executable harness: {executable} ({log.name})")
    return executable, work / OPTIMIZED_IR if variant == "o2" else ir


def execute(executable, args, work, *, timeout=EXECUTION_TIMEOUT, limit=STREAM_LIMIT):
    streams = {"stdout": bytearray(), "stderr": bytearray()}
    try:
        with tempfile.TemporaryDirectory(dir=work) as cwd, subprocess.Popen(
                [executable, *args], cwd=cwd, stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True,
                env=dict(LC_ALL="C", TZ="UTC", HOME=cwd, TMPDIR=cwd, PATH="/usr/bin:/bin")) as process:
            deadline = time.monotonic() + timeout
            try:
                with selectors.DefaultSelector() as select:
                    select.register(process.stdout, selectors.EVENT_READ, "stdout")
                    select.register(process.stderr, selectors.EVENT_READ, "stderr")
                    while select.get_map():
                        remaining = deadline - time.monotonic()
                        if remaining <= 0:
                            raise ExecutionFailure("timeout", "native execution timeout")
                        for key, _ in select.select(remaining):
                            chunk = os.read(key.fd, 65536)
                            if not chunk:
                                select.unregister(key.fd)
                                continue
                            data = streams[key.data]
                            room = limit - len(data)
                            data.extend(chunk[:room])
                            if len(chunk) > room:
                                raise ExecutionFailure("output_limit", f"{key.data} output-size limit exceeded "
                                                       f"({limit} bytes)")
                try:
                    status = process.wait(timeout=max(0, deadline - time.monotonic()))
                except subprocess.TimeoutExpired as error:
                    raise ExecutionFailure("timeout", "native execution timeout") from error
            finally:
                kill_group(process)
            if status < 0:
                raise ExecutionFailure("signaled", f"native harness terminated by signal {-status}", status)
            if status:
                raise ExecutionFailure("harness_error", f"native harness exited {status}", status)
    finally:
        for name, data in streams.items():
            (work / (name + ".bin")).write_bytes(data)
    return Observation(status, bytes(streams["stdout"]), bytes(streams["stderr"]))
