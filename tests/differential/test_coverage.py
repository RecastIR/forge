"""Exercise the CI gate with real publication formats and controlled executions."""
import contextlib
import io
import json
import os
import unittest
from unittest.mock import patch

import coverage_report as coverage
import differential as diff
from test_differential import ArtifactSetup


class CoverageTests(ArtifactSetup):
    def setUp(self):
        super().setUp()
        self.prepare_exports("release")
        self.output = self.root / "out"
        self.baseline = self.suite / "coverage-baseline.json"
        self.required = [dict(id=self.case["fixture_id"], config=c, target=diff.TARGET) for c in diff.CONFIGS]
        diff.write_json(self.baseline, dict(schema_version=1, required_cases=self.required))
        with contextlib.ExitStack() as stack:
            def execute(exe, args, work):
                (work / "stdout.bin").write_bytes(self.wanted.stdout)
                (work / "stderr.bin").write_bytes(self.wanted.stderr)
                return self.wanted
            for context in (patch.dict(os.environ, FORGE_TEST_RUN_ID="current"),
                            patch.object(diff, "analyze", return_value="0x10"), patch.object(diff, "lift"),
                            patch.object(diff.native, "build"), patch.object(diff.native, "execute", execute),
                            patch.object(diff.platform, "system", return_value="Darwin"),
                            patch.object(diff.platform, "machine", return_value="arm64"),
                            contextlib.redirect_stdout(io.StringIO())):
                stack.enter_context(context)
            for config in diff.CONFIGS:
                self.assertEqual(diff.run(config, binaries=self.binaries, references=self.references,
                                          output=self.output, forge=self.forge, suite=self.suite), 0)

    def report(self, jobs=None, **kwargs):
        return coverage.aggregate("current", "revision", jobs or dict.fromkeys(coverage.JOBS, "success"),
                                  suite_root=self.suite, binaries=self.binaries, references=self.references,
                                  output=self.output, **kwargs)

    def test_actual_matrix(self):
        report = self.report()
        self.assertEqual(report["gate"], "passed", report)
        for summary in report["configurations"].values():
            self.assertEqual(summary["references_validated"], 2)
            self.assertEqual(summary["counts"], dict(passed=1, failed=0, error=0, blocked=0, reference_only=1))
            self.assertEqual(summary["passing_by_scope"], dict(function=1, application=0))
        for outcome in ("skipped", "failure", "cancelled"):
            self.assertEqual(self.report({"macos": outcome})["gate"], "failed")

    def test_green_job_cannot_hide_a_skipped_step_or_substituted_forge(self):
        report = self.report()
        needs = {job: {"outputs": {"stages": json.dumps(dict.fromkeys(stages, "success"))}}
                 for job, stages in coverage.JOB_STAGES.items()}
        coverage.verify_job_stages(report, needs)
        self.assertEqual(report["gate"], "passed")
        needs["macos"]["outputs"]["stages"] = '{"formatting":"success"}'
        coverage.verify_job_stages(report, needs)
        self.assertEqual(report["gate"], "failed")
        self.assertEqual(report["job_stages"]["macos"]["sanitize"], "not_run")
        report = self.report(forge_digests=dict.fromkeys(diff.CONFIGS, "0" * 64))
        self.assertEqual(report["gate"], "failed")
        self.assertEqual(report["configurations"]["debug"]["counts"]["error"], 1)

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

    def test_zero_cases(self):
        diff.write_json(self.suite / "cases.json", [])
        diff.write_json(self.baseline, dict(schema_version=1, required_cases=[]))
        report = self.report()
        self.assertEqual(report["gate"], "failed")
        self.assertEqual(sum("zero successful" in e for e in report["errors"]), 2)

    def test_three_observation_mismatches(self):
        folder = self.output / "release/unit/enabled"
        record = diff.read_json(folder / "result.json")
        for name in ("stdout", "stderr", "exit_code"):
            with self.subTest(name=name):
                if name == "exit_code":
                    diff.write_json(folder / "result.json", dict(record, native_exit_code=7))
                else:
                    (folder / (name + ".bin")).write_bytes(b"different")
                report = self.report()
                self.assertEqual(report["gate"], "failed")
                self.assertEqual(report["configurations"]["release"]["counts"]["failed"], 1)
                self.assertEqual(report["configurations"]["debug"]["counts"]["passed"], 1)
                if name != "exit_code":
                    (folder / (name + ".bin")).write_bytes(getattr(self.wanted, name))

    def test_enabled_stage_errors_reach_gate(self):
        for stage, owner, method, failure in (
                ("analysis", diff, "analyze", ValueError("ambiguous export")),
                ("lifting", diff, "lift", diff.Unsupported("unsupported opcode at 0x10")),
                ("native_compilation", diff.native, "build", ValueError("compile failed")),
                ("native_execution", diff.native, "execute", diff.native.ExecutionFailure("timeout", "deadline")),
                ("native_execution", diff.native, "execute", diff.native.ExecutionFailure("signaled", "signal", -9)),
                ("native_execution", diff.native, "execute", diff.native.ExecutionFailure("output_limit", "overflow"))):
            with self.subTest(stage=stage, failure=failure), contextlib.ExitStack() as stack:
                for context in (patch.dict(os.environ, FORGE_TEST_RUN_ID="current"),
                                patch.object(diff, "analyze", return_value="0x10"), patch.object(diff, "lift"),
                                patch.object(diff.native, "build"), patch.object(owner, method, side_effect=failure),
                                contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO())):
                    stack.enter_context(context)
                self.assertEqual(diff.run("release", binaries=self.binaries, references=self.references,
                                          output=self.output, forge=self.forge, suite=self.suite), 1)
                report = self.report()
                row = next(r for r in report["cases"] if r["config"] == "release" and r["scope"])
                self.assertEqual((report["gate"], row["status"], row["stages"][stage]), ("failed", "error", "failed"))
                self.assertEqual(row["reason"], str(failure))
                if isinstance(failure, diff.native.ExecutionFailure):
                    self.assertEqual(row["execution_outcome"], failure.outcome)

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
