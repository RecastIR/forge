"""Compile a generated module through the Forge CMake project and observe its harness."""
import os
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


class ExecutionFailure(ValueError):
    def __init__(self, outcome, message, status=None):
        super().__init__(message)
        self.outcome = outcome
        self.status = status


def command(args, log, stdout=None):
    with log.open("ab") as errors:
        if stdout is None:
            result = subprocess.run(args, stdout=errors, stderr=errors, timeout=180)
        else:
            with stdout.open("wb") as output:
                result = subprocess.run(args, stdout=output, stderr=errors, timeout=180)
    if result.returncode:
        with log.open("rb") as stream:
            stream.seek(max(0, log.stat().st_size - 4096))
            tail = stream.read().decode("utf-8", "backslashreplace")
        raise ValueError(f"{args[0]} exited {result.returncode} ({log.name})\n{tail}")


def build(ir, harness, work, config):
    if (platform.system(), platform.machine()) != ("Darwin", "arm64"):
        raise ValueError("native differential execution requires macOS arm64")
    tree = work / "native"
    log = work / "compilation.log"
    name = "differential_" + harness
    command(["cmake", "-S", SUITE.parents[1], "-B", tree, "-DBUILD_TESTING=OFF",
             f"-DFORGE_DIFFERENTIAL_IR={ir}", f"-DCMAKE_BUILD_TYPE={config.capitalize()}"], log)
    command(["cmake", "--build", tree, "--config", config.capitalize(), "--target", name], log)
    return tree / "bin" / name


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
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
            if status < 0:
                raise ExecutionFailure("signaled", f"native harness terminated by signal {-status}", status)
            if status:
                raise ExecutionFailure("harness_error", f"native harness exited {status}", status)
    finally:
        for name, data in streams.items():
            (work / (name + ".bin")).write_bytes(data)
    return Observation(status, bytes(streams["stdout"]), bytes(streams["stderr"]))
