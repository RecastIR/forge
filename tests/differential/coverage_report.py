"""Reconcile a full run with the fixture catalog and the reviewed coverage obligations."""
import argparse
from collections import Counter
import json
import os
from pathlib import Path
import re
import subprocess
import sys

import differential as diff
from artifacts import directory, file_sha256, read_file, reference
from comparison import Observation, describe, differences
from manifests import field, unique_keys
from protocol import STREAM_LIMIT
from run import verified_export

STATUSES = ("passed", "failed", "error", "reference_only", "blocked")
JOB_STAGES = {
    "macos-dev": ("debug", "dev_oracles"),
    "macos-sanitize": ("sanitize", "sanitize_oracles"),
    "macos-presets": ("formatting", "lint", "release", "xcode_debug", "xcode_release_build", "xcode_release_ctest", "layout"),
    "windows-fixtures": ("build", "capture", "wine_tests"),
    "differential": ("debug", "release", "negative_tests"),
}
FORGE_PRODUCERS = {"debug": "macos-sanitize", "release": "macos-dev"}
INVALID = (ValueError, OSError, KeyError, TypeError)


def require(condition, message):
    if not condition:
        raise ValueError(message)


def check_baseline(path, definitions):
    baseline = diff.read_json(path)
    require(field(baseline, "schema_version", int) == 1, "unsupported coverage baseline")
    required = set()
    for item in field(baseline, "required_cases", list):
        key = tuple(field(item, k, str) for k in ("id", "config", "target"))
        require(set(item) == {"id", "config", "target"} and key not in required, f"invalid baseline row {key}")
        required.add(key)
    enabled = {(name, config, diff.TARGET) for (name, config), case in definitions.items() if "blocked_reason" not in case}
    require(enabled == required, f"baseline disagrees with definitions: missing {sorted(required - enabled)}, "
                                 f"unlisted {sorted(enabled - required)}")


def build_metadata(binaries, config):
    folder = directory(binaries, config)
    build = diff.read_json(folder / "build.json")
    require(field(build, "schema_version", int) == 1 and build["build_config"] == config
            and build["reproducible"] is True and re.fullmatch(r"sha256:[0-9a-f]{64}", build["toolchain_image_id"])
            and build["checksums_sha256"] == diff.sha256((folder / "SHA256SUMS").read_bytes()),
            f"invalid {config} build provenance or checksum file")
    return build


def suite_index(folder, config, run_id, expected, errors):
    suite = diff.read_json(folder / "suite.json")
    require(field(suite, "schema_version", int) == 1 and suite["build_config"] == config
            and suite["selection"] == "all" and suite["run_id"] == run_id,
            "expected a fresh, full differential suite for this configuration")
    index = {}
    for item in field(suite, "cases", list):
        name = field(item, "fixture_id", str)
        require(name not in index and item["report"] == name + "/result.json", f"invalid suite entry {name}")
        index[name] = item
    if index.keys() != expected:
        errors.append(f"{config} suite membership: missing {sorted(expected - index.keys())}, "
                      f"unexpected {sorted(index.keys() - expected)}")
    return suite, index


def inspect_variant(folder, variant, evidence, identity, canonical_digest, wanted):
    require(all(evidence.get(k) == value for k, value in identity.items())
            and evidence.get("variant") == variant, "variant identity or run ID mismatch")
    require(evidence.get("canonical_ir_sha256") == canonical_digest, "canonical IR digest mismatch")
    stages = field(evidence, "stages", dict)
    require(set(stages) == set(diff.NATIVE_STAGES), "missing variant stages")
    if stages["native_compilation"] != "passed":
        raise ValueError(evidence.get("diagnostic") or "native compilation incomplete")

    work = directory(folder, variant)
    input_digest = canonical_digest
    if variant == "o2":
        input_digest = file_sha256(directory(work, diff.native.OPTIMIZED_IR))
    require(evidence.get("compiler_ir_sha256") == input_digest, "compiler input IR digest mismatch")
    if stages["native_execution"] != "passed" or evidence.get("execution_outcome") != "completed":
        raise ValueError(evidence.get("diagnostic") or "native execution incomplete")

    actual = Observation(field(evidence, "native_exit_code", int),
                         read_file(work / "stdout.bin", STREAM_LIMIT), read_file(work / "stderr.bin", STREAM_LIMIT))
    mismatch = differences(wanted, actual)
    if not mismatch:
        require(evidence["status"] == "passed" and stages["comparison"] == "passed"
                and "native_process_status" not in evidence and actual.exit_code == 0
                and not evidence.get("differences") and not evidence.get("failure_categories"),
                "comparison result disagrees with captured behavior")
    return mismatch


def inspect_result(row, case, record, entry, folder, wanted, run_id, expected_forge):
    name = row["fixture_id"]
    require(field(record, "schema_version", int) == 1 and record["fixture_id"] == name
            and record["build_config"] == row["config"] and record["run_id"] == run_id,
            "case identity or run ID mismatch")
    require((entry["status"], entry["scope"]) == (record["status"], record["scope"]),
            "suite and case disagree")
    stages = field(record, "stages", dict)
    row["stages"] = stages
    if record["status"] == "infrastructure_failure" and "variants" not in record:
        raise ValueError(record.get("diagnostic") or "runner stage failure")
    require(record["binary_sha256"] == row["binary_sha256"] and record["reference"] == row["reference"]
            and stages["reference_validation"] == "passed", "PE or validated reference identity mismatch")
    if case is None or "blocked_reason" in case:
        expected = "blocked" if case else "uncovered"
        require(record["status"] == expected and record["scope"] is None and set(stages) == {"reference_validation"},
                f"unexpected execution or classification for {name}")
        if case:
            require(record["diagnostic"] == case["blocked_reason"], "blocking reason disagrees with case definition")
            row.update(status="blocked", reason=case["blocked_reason"])
        else:
            row["status"] = "reference_only"
        return

    require(record["scope"] == case["scope"] and record["function"] == case["export"]
            and record["signature"] == case["signature"] and record["native_target"] == "Darwin/arm64",
            "function contract or native target mismatch")
    require(re.fullmatch("[0-9a-f]{64}", field(record, "forge_sha256", str)), "missing Forge digest")
    if expected_forge is not None:
        require(record["forge_sha256"] == expected_forge, "Forge executable differs from the tested native build")
    row["forge_sha256"] = record["forge_sha256"]
    require(set(stages) == set(diff.STAGES) and all(stages[s] == "passed" for s in diff.STAGES[:3]),
            "shared reference, analysis or lifting stage incomplete")
    if record["status"] == "infrastructure_failure":
        row["variants"] = record.get("variants", {})
    try:
        canonical_digest = file_sha256(directory(folder, diff.CANONICAL_IR))
    except INVALID as error:
        raise ValueError(f"baseline and o2: canonical IR: {error}") from error
    identity = dict(fixture_id=name, build_config=row["config"], binary_sha256=row["binary_sha256"], run_id=run_id)
    variants = field(record, "variants", dict)
    require(not (variants.keys() - set(diff.VARIANTS)), "unexpected native variant")
    errors, failures = [], []
    for variant in diff.VARIANTS:
        try:
            mismatch = inspect_variant(folder, variant, field(variants, variant, dict), identity,
                                       canonical_digest, wanted)
            row["executed"] = True
            failures.extend(f"{variant}: {describe(item)}" for item in mismatch)
        except INVALID as error:
            errors.append(f"{variant}: {error}")
    if errors:
        raise ValueError("\n".join(errors + failures))
    if failures:
        row.update(status="failed", reason="\n".join(failures))
    else:
        require(record["status"] == "passed" and all(stages[s] == "passed" for s in diff.NATIVE_STAGES)
                and not record.get("failure_categories"), "fixture result disagrees with variant evidence")
        row["status"] = "passed"


def aggregate(run_id, revision, jobs, *, suite_root=diff.SUITE, binaries=diff.BINARIES,
              references=diff.REFERENCES, output=diff.OUTPUT, forge_digests=None, prerequisite_errors=()):
    report = dict(schema_version=1, revision=revision, run_id=run_id, target=diff.TARGET, jobs=jobs,
                  fixture_count=0, enabled_case_count=0, gate="failed", configurations={}, cases=[],
                  errors=list(prerequisite_errors))
    errors = report["errors"]
    for job, outcome in jobs.items():
        if outcome != "success":
            errors.append(f"{job}: {outcome}")
    try:
        catalog = diff.load_catalog(suite_root)
        report["fixture_count"] = len(catalog)
        definitions = diff.case_definitions(catalog, suite_root / "cases.json")
        report["enabled_case_count"] = len({name for (name, _), case in definitions.items()
                                            if "blocked_reason" not in case})
    except INVALID as error:
        errors.append(str(error))
        return report
    try:
        check_baseline(suite_root / "coverage-baseline.json", definitions)
    except INVALID as error:
        errors.append(str(error))

    names = {m.case["id"] for m in catalog}
    for config in diff.CONFIGS:
        folder = output / config
        counts = dict.fromkeys(STATUSES, 0)
        categories = {}
        scopes = dict(function=0, application=0)
        summary = dict(counts=counts, by_category=categories, passing_by_scope=scopes, references_validated=0)
        report["configurations"][config] = summary
        trusted_inputs = jobs.get("windows-fixtures", "success") == "success"
        try:
            require(trusted_inputs, "fixture producer did not complete successfully")
            summary["build"] = build_metadata(binaries, config)
        except INVALID as error:
            errors.append(f"{config} build: {error}")
        suite, index = None, {}
        try:
            suite, index = suite_index(folder, config, run_id, names, errors)
        except INVALID as error:
            errors.append(f"{config} suite: {error}")
        executed = 0
        for manifest in catalog:
            name = manifest.case["id"]
            case = definitions.get((name, config))
            category = name.split("/")[0]
            row = dict(fixture_id=name, category=category, config=config, target=diff.TARGET, status="error",
                       scope=case.get("scope") if case else None, reference_status="invalid",
                       report=f"{config}/{name}/result.json")
            try:
                if not trusted_inputs:
                    row["reference_status"] = "unavailable"
                    raise ValueError("fixture producer did not publish trusted inputs")
                directory(binaries, config)
                _, row["binary_sha256"] = verified_export(binaries, config, manifest.case["binary"])
                wanted, row["reference"] = reference(references, manifest, config, row["binary_sha256"])
                row["reference_status"] = "validated"
                summary["references_validated"] += 1
                require(name in index, "missing full-suite evidence")
                work = directory(output, config + "/" + name)
                record = diff.read_json(work / "result.json")
                inspect_result(row, case, record, index[name], work, wanted, run_id,
                               forge_digests[config] if forge_digests is not None else None)
            except INVALID as error:
                row["reason"] = str(error)
            executed += row.get("executed", False)
            counts[row["status"]] += 1
            categories.setdefault(category, Counter())[row["status"]] += 1
            if row["status"] == "passed":
                scopes[row["scope"]] += 1
            report["cases"].append(row)
        summary["executed"] = executed
        if not counts["passed"]:
            errors.append(f"{config}: zero successful differential executions")
        if suite:
            expected = dict(executed=executed, passed=counts["passed"], uncovered=counts["reference_only"],
                            blocked=counts["blocked"])
            if suite.get("status") != "passed" or any(type(suite.get(k)) is not int or suite[k] != v
                                                      for k, v in expected.items()):
                errors.append(f"{config}: failed or inconsistent suite totals")
    if not errors and all(row["status"] not in ("failed", "error") for row in report["cases"]):
        report["gate"] = "passed"
    return report


def markdown(report):
    lines = [f"## Forge differential coverage — {report['gate'].upper()}", "",
             f"Revision `{report['revision']}` · {report['target']} · {report['fixture_count']} fixtures",
             ""]
    for job, outcome in report["jobs"].items():
        stages = report.get("job_stages", {}).get(job, {})
        details = ", ".join(f"{k}={v}" for k, v in stages.items())
        lines.append(f"- {job}: {outcome}" + (f" ({details})" if details else ""))
    lines.extend(["", "| Configuration / category | References | " + " | ".join(STATUSES) + " |",
                  "|---|---|" + "---|" * len(STATUSES)])
    for config, item in report["configurations"].items():
        for label, counts in [(config, item["counts"]), *sorted(item["by_category"].items())]:
            refs = f"{item['references_validated']}/{report['fixture_count']}" if label == config else ""
            lines.append(f"| {label} | {refs} | " + " | ".join(str(counts.get(k, 0)) for k in STATUSES) + " |")
    for config, item in report["configurations"].items():
        scopes = item["passing_by_scope"]
        build = "reproducible" if "build" in item else "missing or invalid"
        lines.append(f"\n{config} PE build: {build}. Passing executions: "
                     f"{scopes['function']} function, {scopes['application']} application.")
    for error in report["errors"]:
        lines.append(f"\n- {error}")
    for row in report["cases"]:
        if row["status"] in ("failed", "error", "blocked"):
            lines.append(f"\n- {row['config']} `{row['fixture_id']}` ({row['status']}): {row.get('reason', '')[:800]}")
    lines.append("\nDiagnostics: `build/differential/windows-x64/<config>/<fixture-id>/`.")
    return "\n".join(lines) + "\n"


def hosted_report(raw_needs, current_run, revision, **paths):
    errors = []
    try:
        needs = json.loads(raw_needs, object_pairs_hook=unique_keys)
        require(isinstance(needs, dict), "expected an object")
    except (ValueError, TypeError) as error:
        errors.append(f"invalid GitHub needs: {error}")
        needs = {}

    jobs, stages, outputs = {}, {}, {}
    for job, expected in JOB_STAGES.items():
        entry = needs.get(job)
        entry = entry if isinstance(entry, dict) else {}
        jobs[job] = entry.get("result", "missing")
        outputs[job] = entry.get("outputs")
        if not isinstance(outputs[job], dict):
            outputs[job] = {}
        try:
            raw = field(outputs[job], "stages", str)
            observed = json.loads(raw, object_pairs_hook=unique_keys)
            require(isinstance(observed, dict), "invalid stage outputs")
        except (ValueError, TypeError) as error:
            errors.append(f"{job}: {error}")
            observed = {}
        stages[job] = {k: observed.get(k, "not_run") for k in expected}
        if any(value != "success" for value in stages[job].values()):
            errors.append(f"{job}: required stage failed or did not run")

    digests = {}
    for config, job in FORGE_PRODUCERS.items():
        digest = outputs[job].get(config + "_forge")
        if not isinstance(digest, str) or not re.fullmatch("[0-9a-f]{64}", digest):
            errors.append(f"{job}: missing or invalid {config} Forge digest")
            digest = ""
        digests[config] = digest

    # A gate-only rerun can consume the successful differential job's original attempt.
    # Bind its reports to that job output, the current workflow run, and the checked-out revision.
    run_id = outputs["differential"].get("evidence_run_id")
    pattern = r"([1-9][0-9]*)-([1-9][0-9]*)-([0-9a-f]{40})"
    current = re.fullmatch(pattern, current_run)
    producer = re.fullmatch(pattern, run_id) if isinstance(run_id, str) else None
    if not (current and producer and current[1] == producer[1] and int(producer[2]) <= int(current[2])
            and current[3] == producer[3] == revision):
        errors.append("differential: missing or invalid evidence run ID, attempt, or revision")
        run_id = current_run

    report = aggregate(run_id, revision, jobs, forge_digests=digests, prerequisite_errors=errors, **paths)
    report["job_stages"] = stages
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--jobs", help="JSON GitHub needs context for all required CI jobs")
    parser.add_argument("--local-jobs", nargs=3, choices=("success", "failure", "skipped"))
    parser.add_argument("--comparison", choices=("success", "failure"), default="success")
    args = parser.parse_args()
    run_id = os.environ["FORGE_TEST_RUN_ID"]
    revision = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=diff.SUITE, text=True).strip()
    if args.jobs is not None:
        report = hosted_report(args.jobs, run_id, revision)
    else:
        jobs = {"differential": args.comparison}
        if args.local_jobs:
            jobs = dict(zip(("macos", "windows-fixtures", "differential"), args.local_jobs))
        report = aggregate(run_id, revision, jobs)
    report["environment"] = "github-actions" if args.jobs is not None else "local"
    folder = diff.BUILD / "differential/coverage"
    folder.mkdir(parents=True, exist_ok=True)
    diff.write_json(folder / "coverage.json", report)
    summary = markdown(report)
    if os.environ.get("GITHUB_STEP_SUMMARY"):
        with Path(os.environ["GITHUB_STEP_SUMMARY"]).open("a") as stream:
            stream.write(summary)
    print(summary)
    return int(report["gate"] != "passed")


if __name__ == "__main__":
    sys.exit(main())
