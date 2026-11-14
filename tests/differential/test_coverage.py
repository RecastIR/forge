"""Exercise the CI gate with real publication formats and controlled executions."""
import contextlib
import copy
import io
import json
import os
import shutil
import unittest
from unittest.mock import patch

import coverage_report as coverage
import differential as diff
from test_differential import ArtifactSetup


class CoverageTests(ArtifactSetup):
    def setUp(self):
        super().setUp()
        self.revision = "a" * 40
        self.run_id = "42-1-" + self.revision
        self.prepare_exports("release")
        self.output = self.root / "out"
        self.baseline = self.suite / "coverage-baseline.json"
        self.required = [dict(id=self.case["fixture_id"], config=c, target=diff.TARGET) for c in diff.CONFIGS]
        diff.write_json(self.baseline, dict(schema_version=1, required_cases=self.required))
        for config in diff.CONFIGS:
            self.assertEqual(self.run_config(config), 0)

    def run_config(self, config, *, build=None, execute=None, lift=None, failure=None):
        with contextlib.ExitStack() as stack:
            for ctx in (patch.dict(os.environ, FORGE_TEST_RUN_ID=self.run_id),
                        patch.object(diff, "analyze", return_value=self.selected),
                        patch.object(diff, "lift", lift or self.lift_fixture),
                        patch.object(diff.native, "build", build or self.build_fixture),
                        patch.object(diff.native, "execute", execute or self.execute_fixture),
                        patch.object(diff.platform, "system", return_value="Darwin"),
                        patch.object(diff.platform, "machine", return_value="arm64"),
                        contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO())):
                stack.enter_context(ctx)
            if failure:
                stack.enter_context(failure)
            return diff.run(config, binaries=self.binaries, references=self.references,
                            output=self.output, forge=self.forge, suite=self.suite)

    def report(self, jobs=None, **kwargs):
        return coverage.aggregate(self.run_id, self.revision, jobs or dict.fromkeys(coverage.JOB_STAGES, "success"),
                                  suite_root=self.suite, binaries=self.binaries, references=self.references,
                                  output=self.output, **kwargs)

    def needs(self):
        needs = {job: {"result": "success", "outputs": {"stages": json.dumps(dict.fromkeys(stages, "success"))}}
                 for job, stages in coverage.JOB_STAGES.items()}
        digest = diff.sha256(self.forge.read_bytes())
        needs["macos-sanitize"]["outputs"]["debug_forge"] = digest
        needs["macos-dev"]["outputs"]["release_forge"] = digest
        needs["differential"]["outputs"]["evidence_run_id"] = self.run_id
        return needs

    def hosted(self, needs, current_run=None):
        return coverage.hosted_report(json.dumps(needs), current_run or self.run_id, self.revision,
                                      suite_root=self.suite, binaries=self.binaries,
                                      references=self.references, output=self.output)

    def test_actual_matrix(self):
        report = self.report()
        self.assertEqual(report["gate"], "passed", report)
        for summary in report["configurations"].values():
            self.assertEqual(summary["references_validated"], 2)
            self.assertEqual(summary["counts"], dict(passed=1, failed=0, error=0, blocked=0, reference_only=1))
            self.assertEqual(summary["passing_by_scope"], dict(function=1, application=0))
        for outcome in ("skipped", "failure", "cancelled"):
            self.assertEqual(self.report({"macos": outcome})["gate"], "failed")

    def test_required_jobs_fail_closed(self):
        valid = self.needs()
        self.assertEqual(self.hosted(valid)["gate"], "passed")
        for job in coverage.JOB_STAGES:
            for outcome in ("skipped", "failure", "cancelled", "missing"):
                with self.subTest(job=job, outcome=outcome):
                    needs = copy.deepcopy(valid)
                    if outcome == "missing":
                        del needs[job]
                    else:
                        needs[job]["result"] = outcome
                    report = self.hosted(needs)
                    self.assertEqual(report["gate"], "failed")
                    self.assertIn(f"{job}: {outcome}", report["errors"])

    def test_green_jobs_require_complete_stage_outputs(self):
        valid = self.needs()
        for job, required in coverage.JOB_STAGES.items():
            for stage in required:
                with self.subTest(job=job, stage=stage):
                    needs = copy.deepcopy(valid)
                    stages = json.loads(needs[job]["outputs"]["stages"])
                    del stages[stage]
                    needs[job]["outputs"]["stages"] = json.dumps(stages)
                    report = self.hosted(needs)
                    self.assertEqual(report["gate"], "failed")
                    self.assertEqual(report["job_stages"][job][stage], "not_run")
        for outputs in (None, [], {}, {"stages": "invalid"}, {"stages": "[]"},
                        {"stages": '{"lint":"skipped","lint":"success"}'}):
            with self.subTest(outputs=outputs):
                needs = copy.deepcopy(valid)
                needs["macos-presets"]["outputs"] = outputs
                self.assertEqual(self.hosted(needs)["gate"], "failed")

    def test_both_tested_binaries_are_required(self):
        for config, job in (("debug", "macos-sanitize"), ("release", "macos-dev")):
            for value in (None, "invalid", "0" * 64):
                with self.subTest(config=config, value=value):
                    needs = self.needs()
                    key = config + "_forge"
                    if value is None:
                        del needs[job]["outputs"][key]
                    else:
                        needs[job]["outputs"][key] = value
                    report = self.hosted(needs)
                    self.assertEqual(report["gate"], "failed")
                    self.assertEqual(report["configurations"][config]["counts"]["error"], 1)
                    row = next(r for r in report["cases"] if r["status"] == "error")
                    self.assertIn("Forge executable differs", row["reason"])

        needs = self.needs()
        self.forge.write_bytes(b"sanitized Forge")
        self.assertEqual(self.run_config("debug"), 0)
        needs["macos-sanitize"]["outputs"]["debug_forge"] = diff.sha256(self.forge.read_bytes())
        self.assertEqual(self.hosted(needs)["gate"], "passed")
        dev = needs["macos-dev"]["outputs"]
        sanitize = needs["macos-sanitize"]["outputs"]
        dev["release_forge"], sanitize["debug_forge"] = sanitize["debug_forge"], dev["release_forge"]
        report = self.hosted(needs)
        self.assertEqual(report["gate"], "failed")
        for config in diff.CONFIGS:
            self.assertEqual(report["configurations"][config]["counts"]["error"], 1)

    def test_partial_rerun_requires_the_differential_jobs_actual_evidence(self):
        valid = self.needs()
        current = "42-2-" + self.revision
        self.assertEqual(self.hosted(valid, current)["gate"], "passed")
        for run_id in (None, "previous", "41-1-" + self.revision, "42-0-" + self.revision,
                       "42-3-" + self.revision, "42-1-" + "b" * 40, current):
            with self.subTest(run_id=run_id):
                needs = copy.deepcopy(valid)
                if run_id is None:
                    del needs["differential"]["outputs"]["evidence_run_id"]
                else:
                    needs["differential"]["outputs"]["evidence_run_id"] = run_id
                report = self.hosted(needs, current)
                self.assertEqual(report["gate"], "failed")
                self.assertTrue(any("evidence run ID" in error or "fresh, full differential suite" in error
                                    for error in report["errors"]))
        self.assertEqual(self.hosted(valid, "42-2-" + "b" * 40)["gate"], "failed")

    def test_membership_and_freshness(self):
        suite = self.output / "release/suite.json"
        original = diff.read_json(suite)
        for changes in (dict(selection="unit/enabled"), dict(run_id="previous"), dict(build_config="debug"),
                        dict(cases=original["cases"][:1]), dict(cases=original["cases"] * 2), dict(executed=0)):
            with self.subTest(changes=changes):
                diff.write_json(suite, dict(original, **changes))
                self.assertEqual(self.report()["gate"], "failed")
        diff.write_json(suite, original)
        (self.output / "release/unit/enabled/result.json").unlink()
        self.assertEqual(self.report()["gate"], "failed")

    def test_reclassification_or_skipped_stage(self):
        path = self.output / "release/unit/enabled/result.json"
        record = diff.read_json(path)
        for change in (dict(status="blocked"), dict(native_target="Linux/x86_64"), dict(run_id="previous"),
                       dict(reference={}), dict(stages=dict(record["stages"], lifting="not_run"))):
            with self.subTest(change=change):
                diff.write_json(path, dict(record, **change))
                self.assertEqual(self.report()["gate"], "failed")
        diff.write_json(self.suite / "cases.json", [dict(fixture_id=self.case["fixture_id"], blocked_reason="test")])
        self.assertIn("baseline disagrees", self.report()["errors"][0])
        diff.write_json(self.suite / "cases.json", [dict(self.case, configs=["debug"])])
        self.assertIn("baseline disagrees", self.report()["errors"][0])
        diff.write_json(self.baseline, dict(schema_version=1, required_cases=self.required[:1]))
        self.assertTrue(any("zero successful" in e for e in self.report()["errors"]))

    def test_disjoint_enabled_and_blocked_configurations(self):
        blocked = dict(fixture_id=self.case["fixture_id"], blocked_reason="release opcode", configs=["release"])
        path = self.suite / "cases.json"
        diff.write_json(path, [dict(self.case, configs=["debug"]), blocked])
        definitions = diff.case_definitions(self.catalog, path)
        self.assertEqual(definitions[self.case["fixture_id"], "release"], blocked)
        diff.write_json(self.baseline, dict(schema_version=1, required_cases=self.required[:1]))
        coverage.check_baseline(self.baseline, definitions)
        diff.write_json(path, [self.case, blocked])
        with self.assertRaisesRegex(ValueError, "duplicate"):
            diff.case_definitions(self.catalog, path)

    def test_zero_cases(self):
        diff.write_json(self.suite / "cases.json", [])
        diff.write_json(self.baseline, dict(schema_version=1, required_cases=[]))
        report = self.report()
        self.assertEqual(report["gate"], "failed")
        self.assertEqual(sum("zero successful" in e for e in report["errors"]), 2)

    def test_three_observation_mismatches(self):
        folder = self.output / "release/unit/enabled"
        record = diff.read_json(folder / "result.json")
        for variant in diff.VARIANTS:
            for name in ("stdout", "stderr", "exit_code"):
                with self.subTest(variant=variant, name=name):
                    if name == "exit_code":
                        changed = dict(record["variants"][variant], native_exit_code=7)
                        variants = dict(record["variants"], **{variant: changed})
                        diff.write_json(folder / "result.json", dict(record, variants=variants))
                    else:
                        (folder / variant / (name + ".bin")).write_bytes(b"different")
                    report = self.report()
                    self.assertEqual(report["gate"], "failed")
                    self.assertEqual(report["configurations"]["release"]["counts"]["failed"], 1)
                    self.assertEqual(report["configurations"]["debug"]["counts"]["passed"], 1)
                    row = next(r for r in report["cases"] if r["status"] == "failed")
                    self.assertIn(variant, row["reason"])
                    diff.write_json(folder / "result.json", record)
                    if name != "exit_code":
                        (folder / variant / (name + ".bin")).write_bytes(getattr(self.wanted, name))

    def test_missing_and_stale_variant(self):
        folder = self.output / "release/unit/enabled"
        record = diff.read_json(folder / "result.json")
        record["variants"]["baseline"]["run_id"] = "previous"
        diff.write_json(folder / "result.json", record)
        self.assertEqual(self.report()["gate"], "failed")
        record["variants"]["baseline"]["run_id"] = self.run_id
        diff.write_json(folder / "result.json", record)
        (folder / "o2/stdout.bin").unlink()
        self.assertEqual(self.report()["gate"], "failed")
        del record["variants"]["o2"]
        diff.write_json(folder / "result.json", record)
        self.assertEqual(self.report()["gate"], "failed")

    def test_substituted_debug_variant(self):
        name = self.case["fixture_id"]
        source, dest = (self.output / cfg / name for cfg in diff.CONFIGS)
        record = diff.read_json(dest / "result.json")
        record["variants"]["o2"] = diff.read_json(source / "result.json")["variants"]["o2"]
        diff.write_json(dest / "result.json", record)
        shutil.copytree(source / "o2", dest / "o2", dirs_exist_ok=True)
        report = self.report()
        self.assertEqual(report["gate"], "failed")
        row = next(r for r in report["cases"] if r["config"] == "release" and r["fixture_id"] == name)
        self.assertIn("o2: variant identity", row["reason"])

    def test_missing_or_changed_ir(self):
        work = self.output / "release" / self.case["fixture_id"]
        for path, variants in ((work / diff.CANONICAL_IR, diff.VARIANTS),
                               (work / "o2" / diff.native.OPTIMIZED_IR, ("o2",))):
            original = path.read_bytes()
            for damage in ("missing", "changed"):
                with self.subTest(path=path, damage=damage):
                    if damage == "missing":
                        path.unlink()
                    else:
                        path.write_bytes(original + b" changed")
                    report = self.report()
                    self.assertEqual(report["gate"], "failed")
                    row = next(r for r in report["cases"] if r["status"] == "error")
                    self.assertEqual((row["config"], row["fixture_id"]), ("release", self.case["fixture_id"]))
                    for variant in variants:
                        self.assertIn(variant, row["reason"])
                    path.write_bytes(original)

    def test_partial_execution(self):
        for failed in diff.VARIANTS:
            for stage in ("compilation", "execution"):
                with self.subTest(failed=failed, stage=stage):
                    def build(ir, harness, work, config, variant):
                        if failed == variant and stage == "compilation":
                            raise ValueError("compile failed")
                        return self.build_fixture(ir, harness, work, config, variant)

                    def execute(exe, args, work):
                        if work.name == failed and stage == "execution":
                            raise diff.native.ExecutionFailure("timeout", "deadline")
                        return self.execute_fixture(exe, args, work)

                    self.assertEqual(self.run_config("release", build=build, execute=execute), 1)
                    suite = diff.read_json(self.output / "release/suite.json")
                    self.assertEqual((suite["executed"], suite["passed"]), (1, 0))
                    self.assertNotIn("diagnostic", suite)
                    report = self.report()
                    self.assertEqual(report["gate"], "failed")
                    self.assertEqual(report["configurations"]["release"]["executed"], 1)
                    row = next(r for r in report["cases"] if r["status"] == "error")
                    diagnostic = "compile failed" if stage == "compilation" else "deadline"
                    self.assertIn(f"{failed}: {diagnostic}", row["reason"])

    def test_enabled_stage_errors_reach_gate(self):
        for stage, owner, method, failure in (
                ("analysis", diff, "analyze", ValueError("ambiguous export")),
                ("lifting", diff, "lift", diff.Unsupported("unsupported opcode at 0x10")),
                ("native_compilation", diff.native, "build", ValueError("compile failed")),
                ("native_execution", diff.native, "execute", diff.native.ExecutionFailure("timeout", "deadline")),
                ("native_execution", diff.native, "execute", diff.native.ExecutionFailure("signaled", "signal", -9)),
                ("native_execution", diff.native, "execute", diff.native.ExecutionFailure("output_limit", "overflow"))):
            with self.subTest(stage=stage, failure=failure):
                self.assertEqual(self.run_config("release", failure=patch.object(owner, method, side_effect=failure)), 1)
                report = self.report()
                row = next(r for r in report["cases"] if r["config"] == "release" and r["scope"])
                self.assertEqual((report["gate"], row["status"], row["stages"][stage]), ("failed", "error", "failed"))
                self.assertIn(str(failure), row["reason"])
                if isinstance(failure, diff.native.ExecutionFailure):
                    for variant in diff.VARIANTS:
                        self.assertEqual(row["variants"][variant]["execution_outcome"], failure.outcome)

    def test_lift_diagnostic_classification_reaches_gate(self):
        for code, category in (("LIFT_UNSUPPORTED_INSTRUCTION", "unsupported_lifting_capability"),
                               ("LIFT_FUNCTION_SIZE", "lifting_failure")):
            def reject(args, output, errors):
                context = dict(input=str(args[2]), entry_rva=hex(self.selected.start))
                diagnostic = dict(schema_version=1, stage="lifting", category="unsupported",
                                  code=code, message="test diagnostic", context=context)
                errors.write((json.dumps(diagnostic) + "\n").encode())
                return 1

            with self.subTest(code=code), patch.object(diff.native, "command_status", side_effect=reject):
                self.assertEqual(self.run_config("release", lift=diff.lift), 1)
                result = diff.read_json(self.output / "release/unit/enabled/result.json")
                self.assertEqual(result["failure_categories"], [category])
                self.assertEqual(result["stages"]["lifting"], "failed")
                self.assertEqual(result["stages"]["native_execution"], "not_run")
                self.assertEqual(self.report()["gate"], "failed")

    def test_reference_only_requires_a_trusted_reference(self):
        folder = self.references / "release/unit/uncovered"
        path = folder / "result.json"
        original = diff.read_json(path)
        for change in (dict(status="failed"), dict(binary_sha256="0"*64), dict(build_config="debug")):
            with self.subTest(change=change):
                diff.write_json(path, dict(original, **change))
                self.assertEqual(self.report()["gate"], "failed")
        diff.write_json(path, original)
        (folder / "stdout.bin").write_bytes(b"damage")
        self.assertEqual(self.report()["gate"], "failed")
        path.unlink()
        self.assertEqual(self.report()["configurations"]["release"]["references_validated"], 1)

    def test_producer_and_baseline_integrity(self):
        diff.write_json(self.baseline, dict(schema_version=1, required_cases=self.required * 2))
        self.assertEqual(self.report()["gate"], "failed")
        diff.write_json(self.baseline, dict(schema_version=1, required_cases=self.required))
        path = self.binaries / "debug/build.json"
        diff.write_json(path, dict(diff.read_json(path), reproducible=False))
        self.assertEqual(self.report()["gate"], "failed")


if __name__ == "__main__":
    unittest.main()
