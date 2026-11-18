"""Compare standalone ARM64 executables built from conventional Windows C startup fixtures."""
import argparse
import json
import os
from pathlib import Path
import platform
import re
import subprocess
import sys
import tempfile

from comparison import describe, differences
from manifests import SUITE, load_catalog

sys.path.insert(0, str(SUITE / "reference"))
from artifacts import reference
from run import BINARIES, BUILD, REFERENCES, snapshot
import native


def verify_executable(path):
    if not path.is_file() or not os.access(path, os.X_OK):
        raise ValueError("Forge did not publish an executable")
    archs = subprocess.check_output(["/usr/bin/lipo", "-archs", path], text=True).strip()
    header = subprocess.check_output(["/usr/bin/otool", "-hv", path], text=True)
    if archs != "arm64" or not re.search(r"^MH_MAGIC_64\s+ARM64\s+[^\n]*\bEXECUTE\b", header, re.MULTILINE):
        raise ValueError(f"expected a standalone ARM64 Mach-O executable, found {archs!r}")
    links = subprocess.check_output(["/usr/bin/otool", "-L", path], text=True).splitlines()[1:]
    if any(re.search(r"wine|rosetta|libforge", dep, re.IGNORECASE) for dep in links):
        raise ValueError(f"unexpected standalone executable dependencies: {links}")


def run_case(forge, manifest, config, work):
    case = manifest.case
    stages = dict.fromkeys(("reference", "translation", "artifact", "execution", "comparison"), "not_run")
    report = dict(fixture_id=case["id"], config=config, args=case["args"], stages=stages)
    stage = "reference"
    try:
        with tempfile.TemporaryDirectory(dir=work) as staging:
            pe, digest = snapshot(BINARIES, config, case["binary"], Path(staging))
            wanted, provenance = reference(REFERENCES, manifest, config, digest)
            report.update(binary_sha256=digest, reference=provenance)
            stages[stage] = "passed"

            stage = "translation"
            executable = work / "translated"
            native.command([forge, "lift", pe, "--executable", "--output", executable,
                            "--diagnostics-format", "json"], work / "compiler.stderr", work / "compiler.stdout")
            stages[stage] = "passed"

        stage = "artifact"
        verify_executable(executable)
        stages[stage] = "passed"

        stage = "execution"
        actual = native.execute(executable, case["args"], work, require_zero=False)
        report["native_exit_code"] = actual.exit_code
        stages[stage] = "passed"

        stage = "comparison"
        mismatches = differences(wanted, actual)
        if mismatches:
            raise ValueError("\n".join(map(describe, mismatches)))
        stages[stage] = "passed"
        report["status"] = "passed"
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        stages[stage] = "failed"
        report.update(status="failed", diagnostic=str(error))
        if stage == "translation":
            # The CLI writes its complete structured report separately. Keep the
            # summary readable even for binaries carrying several dozen imports.
            try:
                details = json.loads((work / "compiler.stderr").read_bytes())
                report["diagnostic"] = f"{details['code']}: {details['message']}"
            except (OSError, ValueError, TypeError, KeyError):
                pass
    (work / "result.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", choices=("debug", "release"), help="default: both PE configurations")
    parser.add_argument("--fixture", help="select one startup fixture, e.g. startup/argv")
    parser.add_argument("--forge", type=Path, default=BUILD / "dev/forge")
    args = parser.parse_args()
    if (platform.system(), platform.machine()) != ("Darwin", "arm64"):
        parser.exit(1, "Standalone native execution requires an ARM64 macOS host.\n")
    cases = [m for m in load_catalog() if m.case["id"].startswith("startup/")
             and (args.fixture is None or args.fixture == m.case["id"])]
    if not cases:
        parser.error("no matching startup fixtures")
    output = BUILD / "differential/startup"
    output.mkdir(parents=True, exist_ok=True)
    folder = Path(tempfile.mkdtemp(prefix="run-", dir=output))
    print(f"Results: {folder}", flush=True)
    failed = 0
    for config in ([args.config] if args.config else ["debug", "release"]):
        for manifest in cases:
            label = f"{config}/{manifest.case['id']}"
            work = folder / label
            work.mkdir(parents=True)
            report = run_case(args.forge.resolve(), manifest, config, work)
            if report["status"] == "passed":
                print(f"PASS {label}", flush=True)
            else:
                failed += 1
                print(f"FAIL {label}: {report['diagnostic']}", file=sys.stderr, flush=True)
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
