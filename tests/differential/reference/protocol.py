"""Bounded wire format between the disposable container and the publisher."""
from dataclasses import dataclass
import json

READY = b"READY\n"
STREAM_LIMIT = 1024 * 1024
HEADER_LIMIT = 1024
WIRE_LIMIT = len(READY) + HEADER_LIMIT + 1 + 2 * STREAM_LIMIT


@dataclass(frozen=True)
class Capture:
    exit_code: int
    stdout: bytes
    stderr: bytes
    wine_version: str


def decode(data):
    if not data.startswith(READY):
        raise ValueError("missing Wine loader readiness record")
    end = data.find(b"\n", len(READY), len(READY) + HEADER_LIMIT + 1)
    if end == -1:
        raise ValueError("invalid capture header")
    header = json.loads(data[len(READY):end])
    if (type(header) is not dict or type(header.get("exit_code")) is not int
            or not 0 <= header["exit_code"] <= 0xffffffff
            or not isinstance(header.get("wine_version"), str) or not header["wine_version"]):
        raise ValueError("invalid capture status or Wine version")
    lengths = [header.get(name) for name in ("stdout_size", "stderr_size")]
    if any(type(n) is not int or not 0 <= n <= STREAM_LIMIT for n in lengths):
        raise ValueError("invalid capture stream lengths")
    start = end + 1
    if len(data) - start != sum(lengths):
        raise ValueError("incomplete or oversized capture payload")
    split = start + lengths[0]
    return Capture(header["exit_code"], bytes(data[start:split]), bytes(data[split:]), header["wine_version"])
