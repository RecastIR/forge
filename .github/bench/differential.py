"""Temporary hosted experiment over an exact candidate Forge checkout and its real CI inputs."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
import time

sys.path.insert(0, str(Path("tests/differential").resolve()))
import coverage_report as coverage
import differential as diff

BUILD = Path("build").resolve()
DEST = BUILD / "benchmark"


def check(value, message):
    if not value:
        raise ValueError(message)


def files_to_transfer(case):
    paths = [p for p in case.iterdir() if p.is_file() and p.suffix != ".exe"]
    if (case / "generated").is_dir():
        paths.extend((case / "generated").glob("*.ll"))
    for v in diff.VARIANTS:
        variant = case / v
        if variant.is_dir():
            paths.extend(p for p in variant.iterdir() if p.is_file())
            paths.extend((variant / "native/bin").glob("differential_*"))
            paths.extend((variant / "native/tests").glob("optimized.ll"))
    return paths


def partition(total, shard):
    catalog = diff.load_catalog()
    defs = diff.case_definitions(catalog, diff.SUITE / "cases.json")
    # Distribute positive cases evenly, including configurations which are enabled only once.
    groups = [[] for _ in range(total)]
    load = [0] * total
    def weight(m):
        return sum((m.case["id"], cfg) in defs and "blocked_reason" not in defs[m.case["id"], cfg]
                   for cfg in diff.CONFIGS)
    for m in sorted(catalog, key=lambda m: -weight(m)):
        i = min(range(total), key=lambda i: (load[i], len(groups[i]), i))
        groups[i].append(m)
        load[i] += weight(m)
    selected = groups[shard]
    check(selected, "empty shard")
    if total == 1:
        return diff.SUITE
    subset = DEST / "catalog"
    subset.mkdir(parents=True)
    for m in selected:
        for path in (m.path, m.case["source"]):
            dest = subset / path
            dest.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(diff.SUITE / path, dest)
    ids = {m.case["id"] for m in selected}
    cases = [c for c in diff.read_json(diff.SUITE / "cases.json") if c["fixture_id"] in ids]
    baseline = diff.read_json(diff.SUITE / "coverage-baseline.json")
    baseline["required_cases"] = [c for c in baseline["required_cases"] if c["id"] in ids]
    diff.write_json(subset / "cases.json", cases)
    diff.write_json(subset / "coverage-baseline.json", baseline)
    return subset


def digests():
    return {cfg: diff.sha256((BUILD / preset / "forge").read_bytes())
            for cfg, preset in (("debug","sanitize"), ("release","dev"))}


def run(args):
    start = time.monotonic()
    DEST.mkdir(parents=True)
    suite = partition(args.shards, args.shard)
    output = DEST / "cases"
    check(os.uname().sysname == "Darwin" and os.uname().machine == "arm64", "requires a macOS arm64 runner")
    elapsed = {}
    success = True
    for cfg in diff.CONFIGS:
        if cfg == "debug":
            os.environ["CMAKE_GENERATOR"] = "Xcode"
        else:
            os.environ.pop("CMAKE_GENERATOR", None)
        before = time.monotonic()
        preset = "sanitize" if cfg == "debug" else "dev"
        result = diff.run(cfg, output=output, forge=BUILD / preset / "forge", suite=suite, jobs=args.workers)
        elapsed[cfg] = time.monotonic() - before
        success = success and result == 0
    # Keep the once-per-run negative suite in the split's larger positive shard.
    if args.shard == 0:
        before = time.monotonic()
        result = subprocess.run([sys.executable, "-B", "tests/differential/test_native_differential.py",
                                 "--forge", str(BUILD / "dev/forge")])
        elapsed["negative_tests"] = time.monotonic() - before
        success = success and result.returncode == 0
    else:
        elapsed["negative_tests"] = 0
    run_id = os.environ["FORGE_TEST_RUN_ID"]
    report = coverage.aggregate(run_id, os.environ["CANDIDATE_SHA"], {"differential": "success" if success else "failure"},
                                suite_root=suite, output=output, forge_digests=digests())
    print(coverage.markdown(report), flush=True)
    check(report["gate"] == "passed", "benchmark shard failed coverage validation")
    # Publish evidence of actual observations and diagnostics, excluding disposable CMake trees.
    archive = BUILD / "evidence.tgz"
    with tarfile.open(archive, "w:gz", compresslevel=1) as tar:
        for cfg in diff.CONFIGS:
            folder = output / cfg
            tar.add(folder / "suite.json", arcname=cfg + "/suite.json")
            for log in folder.glob("cmake-workers/*/configuration.log"):
                tar.add(log, arcname=log.relative_to(output))
            for m in diff.load_catalog(suite):
                for path in files_to_transfer(folder / m.case["id"]):
                    tar.add(path, arcname=path.relative_to(output))
        if args.shard == 0:
            root = BUILD / "differential/negative-tests"
            for result in sorted(root.rglob("result.json")):
                for path in files_to_transfer(result.parent):
                    tar.add(path, arcname=Path("negatives") / path.relative_to(root))
    metric = dict(workers=args.workers, shards=args.shards, shard=args.shard, cpu=os.cpu_count(), elapsed=elapsed,
                  total=time.monotonic()-start, counts={c:report["configurations"][c]["counts"] for c in diff.CONFIGS},
                  evidence_bytes=archive.stat().st_size)
    print(json.dumps(metric), flush=True)
    diff.write_json(BUILD / "metric.json", metric)


def evidence_fingerprint(folder):
    result = diff.read_json(folder / "result.json")
    # The rerun identity and absolute temporary paths in negative compiler logs vary with the runner.
    result.pop("run_id", None)
    if result.get("status") == "infrastructure_failure":
        result["diagnostic"] = (result.get("diagnostic") or "").splitlines()[0].split(": ", 1)[0]
    for v in result.get("variants", {}).values():
        v.pop("run_id", None)
        if "diagnostic" in v:
            v["diagnostic"] = v["diagnostic"].splitlines()[0]
    checksum = hashlib.sha256(json.dumps(result, sort_keys=True).encode())
    for pattern in ("generated/*.ll", "*/native/tests/optimized.ll", "*/stdout.bin", "*/stderr.bin"):
        for path in sorted(folder.glob(pattern)):
            checksum.update(str(path.relative_to(folder)).encode())
            checksum.update(hashlib.sha256(path.read_bytes()).digest())
    return checksum.hexdigest()


def combine(args):
    # Independently reconcile the union, including exact catalog membership and every reference.
    root = Path(args.path).resolve()
    dirs = sorted(d for d in root.iterdir() if d.is_dir() and (d / "evidence.tgz").is_file())
    check(len(dirs) == args.shards, f"expected {args.shards} shard archives, got {len(dirs)}")
    merged = DEST / root.name
    merged.mkdir(parents=True)
    rows = {cfg:[] for cfg in diff.CONFIGS}
    totals = {cfg:dict(executed=0, passed=0, uncovered=0, blocked=0) for cfg in diff.CONFIGS}
    run_id = os.environ["FORGE_TEST_RUN_ID"]
    fingerprints = {}
    shard_ids = set()
    for directory in dirs:
        metric = diff.read_json(directory / "metric.json")
        check(metric["shards"] == args.shards and metric["shard"] not in shard_ids, "invalid or duplicate shard")
        shard_ids.add(metric["shard"])
        local = directory / "payload"
        with tarfile.open(directory / "evidence.tgz") as tar:
            tar.extractall(local, filter="data")
        for cfg in diff.CONFIGS:
            suite = diff.read_json(local / cfg / "suite.json")
            check(suite["status"] == "passed" and suite["build_config"] == cfg and suite["run_id"] == run_id,
                  "stale or incomplete shard")
            for key in totals[cfg]:
                totals[cfg][key] += suite[key]
            for item in suite["cases"]:
                name = item["fixture_id"]
                folder = local / cfg / name
                key = f"{cfg}/{name}"
                check(key not in fingerprints, f"duplicate case {key}")
                fingerprints[key] = evidence_fingerprint(folder)
                dest = merged / key
                dest.parent.mkdir(parents=True, exist_ok=True)
                shutil.move(str(folder), dest)
                rows[cfg].append(item)
        for result in sorted((local / "negatives").rglob("result.json")):
            key = result.parent.relative_to(local).as_posix()
            check(key not in fingerprints, f"duplicate negative {key}")
            fingerprints[key] = evidence_fingerprint(result.parent)
    check(shard_ids == set(range(args.shards)), "missing shard")
    for cfg in diff.CONFIGS:
        diff.write_json(merged / cfg / "suite.json", dict(schema_version=1, selection="all", status="passed",
                        run_id=run_id, build_config=cfg, cases=sorted(rows[cfg], key=lambda r:r["fixture_id"]), **totals[cfg]))
    report = coverage.aggregate(run_id, os.environ["CANDIDATE_SHA"], {"differential":"success"}, output=merged,
                                forge_digests=digests())
    print(coverage.markdown(report))
    check(report["gate"] == "passed", "full coverage gate failed")
    check(any(key.startswith("negatives/") for key in fingerprints), "no negative diagnostic evidence")
    if args.expected:
        reference = diff.read_json(Path(args.expected))
        different = [k for k in sorted(reference.keys() | fingerprints.keys()) if reference.get(k) != fingerprints.get(k)]
        check(not different, "behavior, input IR, or failure classification differed for: " + ", ".join(different))
    diff.write_json(BUILD / "fingerprint.json", fingerprints)


def main():
    parser = argparse.ArgumentParser()
    actions = parser.add_subparsers(dest="action", required=True)
    bench = actions.add_parser("run")
    bench.add_argument("--workers", type=int, choices=(1,2,4), required=True)
    bench.add_argument("--shards", type=int, choices=(1,2,4), required=True)
    bench.add_argument("--shard", type=int, required=True)
    verify = actions.add_parser("combine")
    verify.add_argument("--path", required=True)
    verify.add_argument("--shards", type=int, choices=(1,2,4), required=True)
    verify.add_argument("--expected")
    args = parser.parse_args()
    run(args) if args.action == "run" else combine(args)


if __name__ == "__main__":
    main()
