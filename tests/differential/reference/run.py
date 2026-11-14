"""Validate and publish Wine references from the exported Windows fixture builds."""
import argparse
from contextlib import contextmanager
import fcntl
import hashlib
import json
import os
from pathlib import Path
import signal
import stat
import subprocess
import sys
import tempfile

from docker_wine import CleanupFailure, execute

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from fixture_images import reference_environment
from comparison import Observation, describe, differences
from manifests import FIXTURE_ID, SUITE, load_catalog

BUILD = (SUITE.parents[1] / (os.environ.get("BUILD_ROOT") or "build")).resolve()
BINARIES = BUILD / "fixtures/windows-x64"
REFERENCES = BUILD / "differential/reference/windows-x64/wine"


def selection(argv):
    parser = argparse.ArgumentParser(description=__doc__)
    configs = parser.add_mutually_exclusive_group(required=True)
    configs.add_argument("--all", action="store_true", help="run every Debug and Release fixture")
    configs.add_argument("--config", choices=("debug", "release"))
    parser.add_argument("--fixture", metavar="CATEGORY/NAME")
    args = parser.parse_args(argv)
    if args.fixture is not None and (args.all or not FIXTURE_ID.fullmatch(args.fixture)):
        parser.error("--fixture requires a lowercase category/name and one --config")
    return (["debug", "release"] if args.all else [args.config]), args.fixture


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def runner_version():
    # Image ID covers the guest and Windows parent; include the host-side implementation too.
    digest = hashlib.sha256()
    for path in (Path(__file__), Path(__file__).with_name("docker_wine.py"),
                 Path(__file__).with_name("protocol.py"), SUITE / "manifests.py", SUITE / "comparison.py",
                 SUITE / "fixture_images.py"):
        digest.update(path.read_bytes())
        digest.update(b"\0")
    return "1+sha256." + digest.hexdigest()


@contextmanager
def publication(output, configs, fixture):
    output.parent.mkdir(parents=True, exist_ok=True)
    with (output.parent / ".wine.lock").open("a+b") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        # Withdraw old results before validating inputs or attempting to start Docker.
        with tempfile.TemporaryDirectory(prefix=".wine-", dir=output.parent) as tmp:
            staging = Path(tmp)
            for config in configs:
                target = output / config
                if fixture:
                    target /= fixture
                if target.resolve() != target.absolute():
                    raise ValueError(f"refusing symbolic link in reference path: {target}")
                if target.exists():
                    target.rename(staging / ("old-" + config))
            yield staging


def read_export(path):
    # Build exports are plain files. Reject links, devices and FIFOs before reading.
    if not stat.S_ISREG(path.lstat().st_mode):
        raise ValueError(f"expected a regular fixture export file: {path}")
    return path.read_bytes()


def verified_export(directory, config, binary):
    source = directory / config / binary
    hint = f"./tools/build-windows-fixtures.sh --config {config}"
    try:
        data = read_export(source)
    except FileNotFoundError as error:
        raise ValueError(f"missing executable {source}; build with {hint}") from error
    checksums = source.parent / "SHA256SUMS"
    try:
        lines = read_export(checksums).decode("ascii").splitlines()
    except FileNotFoundError as error:
        raise ValueError(f"missing {checksums}; build with {hint}") from error
    digest = sha256(data)
    rows = [line for line in lines if line.partition("  ")[2] == binary]
    if rows != [f"{digest}  {binary}"]:
        raise ValueError(f"checksum failure for {source}; rebuild with {hint}")
    return data, digest


def snapshot(directory, config, binary, staging):
    data, digest = verified_export(directory, config, binary)
    path = staging / binary
    path.write_bytes(data)
    path.chmod(0o444)
    return path, digest


def compare(expected, capture):
    errors = differences(Observation.from_manifest(expected), capture)
    if errors:
        raise ValueError("\n".join(map(describe, errors)))


def publish(directory, target, manifest, config, capture, binary_hash, provenance):
    result = dict(schema_version=1, fixture_id=manifest.case["id"], build_config=config,
                  execution_backend="wine", status="passed", exit_code=capture.exit_code,
                  binary_sha256=binary_hash, manifest_file=manifest.path, manifest_sha256=manifest.sha256,
                  wine_version=capture.wine_version, **provenance)
    try:
        with tempfile.TemporaryDirectory(dir=directory) as tmp:
            staged = Path(tmp) / "result"
            staged.mkdir()
            for name in ("stdout", "stderr"):
                data = getattr(capture, name)
                filename = name + ".bin"
                (staged / filename).write_bytes(data)
                result[name + "_file"] = filename
                result[name + "_size"] = len(data)
                result[name + "_sha256"] = sha256(data)
            (staged / "result.json").write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
            target.parent.mkdir(parents=True, exist_ok=True)
            staged.rename(target)
    except OSError as error:
        raise ValueError(f"reference artifact write failure: {error}") from error


def run(configs, fixture, *, suite=SUITE, binaries=BINARIES, output=REFERENCES):
    passed = 0
    with publication(output, configs, fixture) as staging:
        try:
            catalog = load_catalog(suite)
        except ValueError as error:
            raise ValueError(f"invalid fixture manifest: {error}") from error
        selected = [m for m in catalog if fixture is None or m.case["id"] == fixture]
        if not selected:
            raise ValueError(f"unknown fixture {fixture!r}")
        failures = output.parent / "failures"
        provenance = None
        setup_failure = None
        for config in configs:
            for manifest in selected:
                case = manifest.case
                label = f"{case['id']} [{config}]"
                failed_case = failures / config / case["id"]
                if failed_case.resolve() != failed_case.absolute():
                    raise ValueError(f"refusing symbolic link in diagnostic path: {failed_case}")
                if failed_case.exists():
                    failed_case.rename(staging / ("old-failure-" + config + "-" + case["binary"]))
                capture = digest = None
                try:
                    with tempfile.TemporaryDirectory() as tmp:
                        binary, digest = snapshot(binaries, config, case["binary"], Path(tmp))
                        if provenance is None and setup_failure is None:
                            try:
                                provenance = dict(reference_environment(suite), runner_version=runner_version())
                            except (OSError, ValueError, subprocess.SubprocessError) as error:
                                setup_failure = f"Wine environment setup failed: {error}"
                        if setup_failure:
                            raise ValueError(setup_failure)
                        capture = execute(provenance["container_image_id"], binary, case["args"])
                    compare(case["expected"], capture)
                    publish(staging, output / config / case["id"], manifest, config,
                            capture, digest, provenance)
                except CleanupFailure as error:
                    raise CleanupFailure(f"FAIL {label}\n{error}") from error
                except (OSError, ValueError, subprocess.SubprocessError) as error:
                    try:
                        failed_case.mkdir(parents=True)
                        diagnostic = dict(fixture_id=case["id"], build_config=config, error=str(error),
                                          binary_sha256=digest, manifest_sha256=manifest.sha256, backend=provenance)
                        if capture is not None:
                            diagnostic["observed_exit_code"] = capture.exit_code
                            for stream in ("stdout", "stderr"):
                                (failed_case / (stream + ".bin")).write_bytes(getattr(capture, stream))
                        (failed_case / "failure.json").write_text(json.dumps(diagnostic, indent=2) + "\n")
                    except OSError as write_error:
                        print(f"Could not preserve {label} diagnostics: {write_error}", file=sys.stderr)
                    print(f"FAIL {label}\n{error}", file=sys.stderr, flush=True)
                else:
                    passed += 1
                    print(f"PASS {label}", flush=True)
    total = len(configs) * len(selected)
    print(f"{passed}/{total} Wine references passed.", flush=True)
    return 0 if passed == total else 1


def interrupt(signum, frame):
    raise KeyboardInterrupt


if __name__ == "__main__":
    signal.signal(signal.SIGTERM, interrupt)
    try:
        sys.exit(run(*selection(sys.argv[1:])))
    except OSError as error:
        sys.exit(f"reference artifact write failure: {error}")
    except (ValueError, CleanupFailure) as error:
        sys.exit(str(error))
    except KeyboardInterrupt:
        sys.exit(130)
