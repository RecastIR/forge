"""Compare function-level native executions with validated Windows observations."""
import argparse
import fcntl
import json
import os
from pathlib import Path
import platform
import re
import shutil
import signal
import subprocess
import sys

from comparison import describe, differences
from manifests import FIXTURE_ID, SUITE, field, load_catalog, unique_keys

sys.path.insert(0, str(SUITE / "reference"))
from artifacts import directory, reference
from run import BINARIES, BUILD, REFERENCES, interrupt, sha256, snapshot, verified_export
import native

OUTPUT = BUILD / "differential/windows-x64"
DEFAULT_FORGE = BUILD / "forge"
STAGES = ("reference_validation", "analysis", "lifting", "native_compilation",
          "native_execution", "comparison")


CONFIGS = ("debug", "release")
TARGET = "macos-arm64"


class Unsupported(ValueError):
    pass


def read_json(path):
    return json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=unique_keys)


def write_json(path, data):
    temporary = path.with_suffix(".tmp")
    temporary.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    temporary.replace(path)


def case_definitions(catalog, path):
    cases = read_json(path)
    if not isinstance(cases, list):
        raise ValueError("differential cases must be a list")
    ids = {m.case["id"] for m in catalog}
    definitions = {}
    for case in cases:
        name = field(case, "fixture_id", str)
        if name not in ids or name in definitions:
            raise ValueError(f"unknown or duplicate differential fixture {name!r}")
        configs = case.get("configs", list(CONFIGS))
        if (not isinstance(configs, list) or not configs or any(c not in CONFIGS for c in configs)
                or len(set(configs)) != len(configs)):
            raise ValueError(f"invalid differential configs for {name}")
        keys = set(case) - {"configs"}
        if keys == {"fixture_id", "blocked_reason"} and field(case, "blocked_reason", str).strip():
            definitions[name] = case
            continue
        if (keys != {"fixture_id", "scope", "export", "signature", "harness"}
                or case.get("scope") != "function" or case.get("signature") != "i64(i64,i64)"
                or not re.fullmatch(r"[A-Za-z_]\w*", field(case, "export", str), flags=re.ASCII)
                or not re.fullmatch(r"[a-z][a-z0-9_]*", field(case, "harness", str))):
            raise ValueError(f"invalid differential function contract for {name}")
        definitions[name] = case
    return definitions


def resolve_export(inspection, analysis, name):
    if (field(inspection, "schema_version", int) != 1 or field(analysis, "schema_version", int) != 1
            or inspection["inspection"] != {"status": "completed", "root_module": 0}):
        raise ValueError("unsupported or incomplete Forge analysis report")
    exports = [entry for entry in inspection["modules"][0]["exports"] if name in entry["names"]]
    if len(exports) != 1 or "forwarder" in exports[0]:
        raise ValueError(f"expected one local export named {name}, found {exports!r}")
    rva = int(exports[0]["rva"], 16)
    rows = [row for row in analysis["functions"] if int(row["start_rva"], 16) == rva]
    if not rows:
        raise Unsupported(f"export {name} at {rva:#x} has no discovered function range")
    if len(rows) != 1 or rows[0]["status"] not in ("valid", "unsupported") or "overlap_diagnostic" in rows[0]:
        raise ValueError(f"ambiguous or invalid function range for {name} at {rva:#x}")
    if rows[0]["liftable"] is not True:
        raise Unsupported(f"export {name} at {rva:#x} is ineligible for lifting: {rows[0]}")
    return hex(rva)


def analyze(forge, image, symbol, work):
    inspect_path, analysis_path = work / "inspect.json", work / "analysis.json"
    native.command([forge, "inspect", image, "--format", "json"], work / "inspect.log", inspect_path)
    native.command([forge, "analyze", image, "--functions", "--format", "json"],
                   work / "analysis.log", analysis_path)
    return resolve_export(read_json(inspect_path), read_json(analysis_path), symbol)


def lift(forge, image, case, rva, ir):
    try:
        native.command([forge, "lift", image, "--rva", rva, "--signature", case["signature"],
                        "--output", ir], ir.parent.parent / "lifting.log")
    except ValueError as error:
        # The CLI also reports file errors and verifier failures. Only explicit capability
        # diagnostics issued by the lifter identify a capability error.
        if re.search(r": LIFT_ERROR: 0x[\da-fA-F]+: .*(?:unsupported |native wrapper requires "
                     r"undefined|backward edge|segment-relative LEA|condition flags require|"
                     r"function bytes overlap base relocation|return with undefined|"
                     r"experimental lift limit)", str(error)):
            raise Unsupported(str(error)) from error
        raise


def run_case(manifest, case, config, binaries, references, forge, work):
    report = dict(schema_version=1, fixture_id=manifest.case["id"], build_config=config,
                  status="uncovered", scope=None)
    enabled = case is not None and "blocked_reason" not in case
    report.update(run_id=os.environ.get("FORGE_TEST_RUN_ID"), stages={"reference_validation": "not_run"})
    if enabled:
        report.update(scope=case["scope"], function=case["export"], signature=case["signature"],
                      native_target=f"{platform.system()}/{platform.machine()}",
                      stages=dict.fromkeys(STAGES, "not_run"))
    stage = "reference_validation"
    stages = report["stages"]
    try:
        directory(binaries, config)
        if enabled:
            image, digest = snapshot(binaries, config, manifest.case["binary"], work)
        else:
            _, digest = verified_export(binaries, config, manifest.case["binary"])
        report["binary_sha256"] = digest
        wanted, report["reference"] = reference(references, manifest, config, digest)
        stages[stage] = "passed"

        if not enabled:
            if case:
                report.update(status="blocked", diagnostic=case["blocked_reason"])
            return report

        stage = "analysis"
        report["forge_sha256"] = sha256(forge.read_bytes())
        rva = analyze(forge, image, case["export"], work)
        report["function_rva"] = rva
        stages[stage] = "passed"

        stage = "lifting"
        if wanted.exit_code:
            raise Unsupported(f"function harness cannot convey Windows termination status {wanted.exit_code}")
        ir = work / "generated/lifted.ll"
        ir.parent.mkdir()
        lift(forge, image, case, rva, ir)
        stages[stage] = "passed"

        stage = "native_compilation"
        executable = native.build(ir, case["harness"], work, config)
        stages[stage] = "passed"

        stage = "native_execution"
        actual = native.execute(executable, manifest.case["args"], work)
        report["native_exit_code"] = actual.exit_code
        report["execution_outcome"] = "completed"
        stages[stage] = "passed"

        stage = "comparison"
        mismatches = differences(wanted, actual)
        if mismatches:
            report.update(status="behavioral_failure", differences=mismatches,
                          failure_categories=[e["field"] + "_mismatch" for e in mismatches])
            stages[stage] = "failed"
        else:
            report["status"] = stages[stage] = "passed"
    except (OSError, ValueError, KeyError, IndexError, TypeError, subprocess.SubprocessError) as error:
        if isinstance(error, native.ExecutionFailure):
            report["execution_outcome"] = error.outcome
            if error.status is not None:
                report["native_process_status"] = error.status
        capability = isinstance(error, Unsupported)
        report.update(status="infrastructure_failure", diagnostic=str(error),
                      failure_categories=["unsupported_lifting_capability" if capability else stage + "_failure"])
        stages[stage] = "failed"
    return report


def contains_path(parent, path):
    resolved = path.resolve()
    if resolved.is_relative_to(parent.resolve()):
        return True
    try:
        identity = parent.stat()
    except FileNotFoundError:
        return False
    # A case-insensitive volume can retain two spellings for the same directory.
    # Inspect the resolved ancestry as well as the path used to reach a symlink.
    for ancestor in dict.fromkeys((resolved, *resolved.parents, *path.absolute().parents)):
        try:
            if os.path.samestat(identity, ancestor.stat()):
                return True
        except FileNotFoundError:
            continue
    return False


def run(config, fixture=None, *, binaries=BINARIES, references=REFERENCES, output=OUTPUT,
        forge=DEFAULT_FORGE, suite=SUITE):
    if config not in ("debug", "release") or (fixture is not None and not FIXTURE_ID.fullmatch(fixture)):
        raise ValueError("invalid configuration or fixture ID")
    folder = output / config
    output.mkdir(parents=True, exist_ok=True)
    with (output / ("." + config + ".lock")).open("a+b") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        for source in (binaries / config, references / config):
            if contains_path(folder, source) or contains_path(source, folder):
                raise ValueError(f"differential output overlaps input artifacts: {source}")
        target = folder / fixture if fixture else folder
        if target.absolute() != target.resolve():
            raise ValueError(f"refusing symbolic link in output path: {target}")
        summary_path = folder / "suite.json"
        if contains_path(target, forge) or contains_path(summary_path, forge):
            raise ValueError(f"differential output overlaps selected Forge executable: {forge}")
        folder.mkdir(exist_ok=True)
        summary_path.unlink(missing_ok=True)
        if target.exists():
            shutil.rmtree(target)
        folder.mkdir(exist_ok=True)
        summary = dict(schema_version=1, build_config=config, selection=fixture or "all",
                       status="failed", executed=0, passed=0, uncovered=0, blocked=0, cases=[],
                       run_id=os.environ.get("FORGE_TEST_RUN_ID"))
        try:
            catalog = load_catalog(suite)
            definitions = case_definitions(catalog, suite / "cases.json")
            selected = [m for m in catalog if fixture is None or m.case["id"] == fixture]
            if not selected:
                raise ValueError(f"unknown fixture {fixture!r}")
            for manifest in selected:
                name = manifest.case["id"]
                work = folder / name
                work.mkdir(parents=True)
                case = definitions.get(name)
                if case and config not in case.get("configs", CONFIGS):
                    case = None
                result = run_case(manifest, case, config, binaries, references, forge, work)
                write_json(work / "result.json", result)
                status = result["status"]
                summary["cases"].append(dict(fixture_id=name, status=status, scope=result["scope"],
                                             report=name + "/result.json"))
                summary["passed"] += status == "passed"
                summary["uncovered"] += status == "uncovered"
                summary["blocked"] += status == "blocked"
                summary["executed"] += result.get("stages", {}).get("native_execution") == "passed"
                label = f"{status.upper()} {name} [{config}]"
                print(f"{label} {result['scope']}" if result["scope"] else label)
                if "stages" in result:
                    print("  " + ", ".join(f"{k}={v}" for k, v in result["stages"].items()))
                if "reference" in result and result["scope"]:
                    print(f"  {result['reference']['wine_version']} -> {result['native_target']}, "
                          f"{result['function']} {result.get('function_rva', '(unresolved)')}")
                if "diagnostic" in result:
                    print(result["diagnostic"])
                for mismatch in result.get("differences", []):
                    print(describe(mismatch))
            if not summary["executed"]:
                raise ValueError("zero differential cases executed")
            if summary["passed"] + summary["uncovered"] + summary["blocked"] == len(selected):
                summary["status"] = "passed"
        except (OSError, ValueError) as error:
            summary["diagnostic"] = str(error)
            print(error, file=sys.stderr)
        write_json(summary_path, summary)
        print(f"{summary['passed']} passed, {summary['executed']} executed, "
              f"{summary['uncovered']} reference only, {summary['blocked']} blocked. Report: {summary_path}")
        return int(summary["status"] != "passed")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--all", action="store_true")
    group.add_argument("--fixture", metavar="CATEGORY/NAME")
    parser.add_argument("--config", required=True, choices=("debug", "release"))
    parser.add_argument("--reference-root", type=Path, default=REFERENCES)
    parser.add_argument("--binary-root", type=Path, default=BINARIES)
    parser.add_argument("--forge", type=Path, default=DEFAULT_FORGE, metavar="PATH",
                        help="Forge executable (default: repository build/forge)")
    options = parser.parse_args(argv)
    return run(options.config, options.fixture, references=options.reference_root,
               binaries=options.binary_root, forge=options.forge.resolve())


if __name__ == "__main__":
    signal.signal(signal.SIGTERM, interrupt)
    try:
        sys.exit(main())
    except (ValueError, OSError) as error:
        sys.exit(str(error))
    except KeyboardInterrupt:
        sys.exit(130)
