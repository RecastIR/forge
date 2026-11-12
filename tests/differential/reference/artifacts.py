"""Reopen a v1 publication from a trusted reference root without invoking Wine."""
import json
import os
import re
import stat

from comparison import Observation
from manifests import field, unique_keys
from protocol import STREAM_LIMIT
from run import compare, runner_version, sha256

# The original v1 publisher at b83c0f3 performed the same strict comparison inline.
TASK3_PUBLISHER = "1+sha256.4820c6fea7bcac32962ed3e13ae4254b9eb2f95270855c734e8d9601fc59a24d"


# Task 4 publisher before extracting verified_export and recording failure diagnostics.
TASK4_PUBLISHER = "1+sha256.daa8437a1f0dfe26c4eaee5e0df7df52fdb331db71e46a05c57bb4253c413b5e"


def directory(root, relative):
    if root.is_symlink():
        raise ValueError(f"symbolic link at artifact root: {root}")
    path = root.resolve(strict=True) / relative
    if path.resolve(strict=True) != path:
        raise ValueError(f"symbolic link in artifact path: {path}")
    return path


def read_file(path, limit):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_size > limit:
            raise ValueError(f"invalid artifact type or size: {path}")
        with os.fdopen(fd, "rb", closefd=False) as stream:
            data = stream.read(limit + 1)
        if len(data) != info.st_size:
            raise ValueError(f"artifact changed while reading: {path}")
        return data
    finally:
        os.close(fd)


def reference(root, manifest, config, binary_hash):
    folder = directory(root, config + "/" + manifest.case["id"])
    record = read_file(folder / "result.json", 65536)
    meta = json.loads(record.decode("utf-8"), object_pairs_hook=unique_keys)
    required = dict(schema_version=1, status="passed", fixture_id=manifest.case["id"],
                    build_config=config, manifest_file=manifest.path, manifest_sha256=manifest.sha256,
                    binary_sha256=binary_hash, execution_backend="wine", container_platform="linux/amd64")
    for key, wanted in required.items():
        if field(meta, key, type(wanted)) != wanted:
            raise ValueError(f"reference {key} mismatch (expected {wanted!r}, found {meta[key]!r})")
    if field(meta, "runner_version", str) not in (runner_version(), TASK3_PUBLISHER, TASK4_PUBLISHER):
        raise ValueError("unrecognized Wine runner_version")
    for key in ("wine_version", "docker_host_arch"):
        if not field(meta, key, str).strip():
            raise ValueError(f"missing reference {key}")
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", field(meta, "container_image_id", str)):
        raise ValueError("invalid reference container_image_id")
    if os.environ.get("GITHUB_ACTIONS") == "true" and meta["docker_host_arch"] not in ("amd64", "x86_64"):
        raise ValueError("canonical Wine references require a Linux amd64 Docker host")
    status = field(meta, "exit_code", int)
    if not 0 <= status <= 0xffffffff:
        raise ValueError("invalid Windows exit_code")
    streams = {}
    for name in ("stdout", "stderr"):
        filename = name + ".bin"
        if field(meta, name + "_file", str) != filename:
            raise ValueError(f"invalid reference {name}_file")
        data = read_file(folder / filename, STREAM_LIMIT)
        if (field(meta, name + "_size", int) != len(data)
                or field(meta, name + "_sha256", str) != sha256(data)):
            raise ValueError(f"reference {filename} size or SHA-256 mismatch")
        streams[name] = data
    observed = Observation(status, **streams)
    compare(manifest.case["expected"], observed)
    identity = {k: meta[k] for k in ("execution_backend", "wine_version", "container_image_id",
                                      "container_platform", "docker_host_arch", "runner_version",
                                      "manifest_file", "manifest_sha256")}
    return observed, dict(identity, path=config + "/" + manifest.case["id"], result_sha256=sha256(record))
