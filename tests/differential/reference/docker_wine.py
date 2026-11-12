"""Build the pinned image and supervise one disposable Wine container at a time."""
import os
from pathlib import Path
import selectors
import subprocess
import sys
import time
import uuid

from protocol import READY, WIRE_LIMIT, decode

STARTUP_TIMEOUT = 120
EXECUTION_TIMEOUT = 10
DIAGNOSTIC_LIMIT = 65536


class CleanupFailure(RuntimeError):
    """Stop the suite when a previous invocation may still be running."""


def command(args, **kwargs):
    return subprocess.check_output(args, text=True, **kwargs).strip()


def build_image(suite):
    image = command(["docker", "build", "--platform", "linux/amd64", "--target", "reference",
                     "-q", "-f", suite / "toolchain/Dockerfile", suite])
    platform = command(["docker", "image", "inspect", "--format", "{{.Os}}/{{.Architecture}}", image])
    if platform != "linux/amd64":
        raise ValueError(f"unexpected Wine image platform {platform!r}")
    host = command(["docker", "info", "--format", "{{.Architecture}}"])
    return dict(container_image_id=image, container_platform=platform, docker_host_arch=host)


def supervise(process, startup_timeout=STARTUP_TIMEOUT, execution_timeout=EXECUTION_TIMEOUT):
    payload = bytearray()
    diagnostic = bytearray()
    deadline = time.monotonic() + startup_timeout
    started = False
    with selectors.DefaultSelector() as selector:
        selector.register(process.stdout, selectors.EVENT_READ, "capture")
        selector.register(process.stderr, selectors.EVENT_READ, "diagnostics")
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                stage = "execution timeout" if started else "Wine startup timeout"
                raise ValueError(f"{stage}: {diagnostic.decode('utf-8', 'backslashreplace')}")
            for key, _ in selector.select(remaining):
                chunk = os.read(key.fd, 65536)
                if not chunk:
                    selector.unregister(key.fd)
                elif key.data == "diagnostics":
                    diagnostic.extend(chunk)
                    if b"assertion failed [x86_avx_state_ptr" in diagnostic:
                        raise ValueError("Rosetta aborted while restoring Wine's signal context")
                    del diagnostic[:-DIAGNOSTIC_LIMIT]
                else:
                    payload.extend(chunk)
                    if len(payload) > WIRE_LIMIT:
                        raise ValueError("capture protocol output-size limit exceeded")
                    if not started and payload.startswith(READY):
                        started = True
                        deadline = time.monotonic() + execution_timeout
    try:
        status = process.wait(timeout=max(0, deadline - time.monotonic()))
    except subprocess.TimeoutExpired as error:
        raise ValueError("execution timeout" if started else "Wine startup timeout") from error
    if status:
        detail = diagnostic.decode("utf-8", "backslashreplace").strip()
        raise ValueError(f"Wine container failed ({status}): {detail}")
    try:
        return decode(payload)
    except ValueError as error:
        raise ValueError(f"invalid Wine capture: {error}; {diagnostic.decode('utf-8', 'backslashreplace')}") from error


def execute(image, binary, args, *, container_env=()):
    name = "forge-reference-" + uuid.uuid4().hex
    options = ["docker", "create", "--name", name, "--platform", "linux/amd64", "--network", "none",
               "--hostname", "forge-reference", "--log-driver", "none", "--cap-drop", "ALL",
               "--security-opt", "no-new-privileges", "--pids-limit", "128",
               "--tmpfs", "/tmp:rw,nosuid,nodev,size=64m",
               "-v", f"{Path(binary).resolve()}:/input/{binary.name}:ro"]
    for entry in container_env:
        options.extend(["-e", entry])
    deadline = time.monotonic() + STARTUP_TIMEOUT
    try:
        command([*options, image, binary.name, *args], timeout=STARTUP_TIMEOUT)
        with subprocess.Popen(["docker", "start", "-a", name], stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE, stdin=subprocess.DEVNULL) as process:
            try:
                result = supervise(process, startup_timeout=deadline - time.monotonic())
            finally:
                if process.poll() is None:
                    process.kill()
        state = command(["docker", "inspect", "--format", "{{.State.ExitCode}}", name], timeout=10)
        if state != "0":
            raise ValueError(f"Wine container terminated with status {state}")
        return result
    finally:
        primary_error = sys.exc_info()[1]
        try:
            removed = subprocess.run(["docker", "rm", "-f", name], capture_output=True, text=True, timeout=30)
            if removed.returncode and "No such container" not in removed.stderr:
                raise OSError(removed.stderr.strip())
        except (OSError, subprocess.SubprocessError) as error:
            detail = f" after {primary_error}" if primary_error else ""
            raise CleanupFailure(f"container cleanup failed for {name}{detail}: {error}") from error
