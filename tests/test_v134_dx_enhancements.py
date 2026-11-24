"""Tests for SIDIK v1.3.4 global PyPI DX hardening, expanded SAST/SCA, CLI, SARIF, and GUI."""

import io
import json
import os
import tempfile
import unittest
from contextlib import redirect_stdout
from unittest.mock import patch

from sidik.cli import launch_gui_cli, run_cli_with_args
from sidik.core import SecurityScanner
from sidik.dependency_analyzer.database import VulnerabilityDatabase, get_user_cache_dir, get_user_db_path
from sidik.dependency_analyzer.parsers import parse_pipfile_lock, parse_pyproject_toml, parse_uv_lock
from sidik.models import ConfidenceScore, Finding, ScanReport, ScanSummary, SeverityLevel
from sidik.reporting.formatter import ReportFormatter
from sidik.secret_detector.detector import SecretDetector


class TestV134DxEnhancements(unittest.TestCase):
    """Covers user cache OSV DB, expanded SAST/SCA coverage, CLI flags, SARIF root, and GUI safety."""

    def test_user_cache_osv_db_priority_and_age(self):
        with tempfile.TemporaryDirectory() as tmp:
            old_env = os.environ.get("SIDIK_CACHE_DIR")
            os.environ["SIDIK_CACHE_DIR"] = tmp
            try:
                self.assertEqual(get_user_cache_dir(), os.path.abspath(tmp))
                cache_db = get_user_db_path()
                payload = {
                    "metadata": {
                        "source": "unit-cache",
                        "generated_utc": "2025-01-01T00:00:00Z",
                    },
                    "advisories": [
                        {
                            "id": "PYSEC-CACHE-1",
                            "cve": "CVE-2099-9999",
                            "package": "cache-demo-pkg",
                            "vulnerable_specifier": "<2.0.0",
                            "fixed_version": "2.0.0",
                            "severity": "HIGH",
                            "summary": "Cached advisory",
                            "details": "Loaded from user cache",
                        }
                    ],
                }
                with open(cache_db, "w", encoding="utf-8") as f:
                    json.dump(payload, f)

                db = VulnerabilityDatabase()
                advs = db.get_advisories("cache_demo_pkg")
                self.assertEqual(len(advs), 1)
                self.assertEqual(advs[0]["cve"], "CVE-2099-9999")
                self.assertTrue(db.active_db_source.startswith("user_cache"))
                age = db.snapshot_age_days()
                self.assertIsNotNone(age)
                assert age is not None
                self.assertGreater(age, 60)
            finally:
                if old_env is None:
                    os.environ.pop("SIDIK_CACHE_DIR", None)
                else:
                    os.environ["SIDIK_CACHE_DIR"] = old_env

    def test_expanded_secret_files_and_binary_size_guards(self):
        with tempfile.TemporaryDirectory() as tmp:
            with open(os.path.join(tmp, ".env.production"), "w", encoding="utf-8") as f:
                f.write("AWS_ACCESS_KEY_ID=AKIAJ2M4K8P9Q3R7W5T1\n")
            with open(os.path.join(tmp, "config.yaml"), "w", encoding="utf-8") as f:
                f.write("api_key: AKIAJ2M4K8P9Q3R7W5T2\n")
            # Lockfiles must never trigger secret scanner even though .lock or .toml/.json might look complex
            with open(os.path.join(tmp, "uv.lock"), "w", encoding="utf-8") as f:
                f.write('[[package]]\nname = "requests"\nversion = "2.19.0"\n')
            # Binary NUL-byte file disguised as .py should be skipped safely
            with open(os.path.join(tmp, "binary_blob.py"), "wb") as f:
                f.write(b"\x00\x01AWS_KEY='AKIAJ2M4K8P9Q3R7W5T3'\n")

            scanner = SecurityScanner(enable_secret_scan=True, enable_dependency_scan=True)
            report = scanner.scan_path(tmp)
            sec_files = {os.path.basename(f.file_path) for f in report.findings if f.finding_type == "secret"}
            self.assertIn(".env.production", sec_files)
            self.assertIn("config.yaml", sec_files)
            self.assertNotIn("binary_blob.py", sec_files)
            dep_pkgs = {f.metadata.get("package") for f in report.findings if f.finding_type == "dependency"}
            self.assertIn("requests", dep_pkgs)

        # Oversized file guard
        with tempfile.TemporaryDirectory() as tmp2:
            big = os.path.join(tmp2, "huge.py")
            with open(big, "w", encoding="utf-8") as f:
                f.write("AWS_KEY = 'AKIAJ2M4K8P9Q3R7W5T1'\n" + ("#" * 2048))
            det_small = SecretDetector(max_file_size_bytes=256)
            self.assertEqual(det_small.scan_file(big), [])

    def test_expanded_sca_parsers_and_manifest_discovery(self):
        pyproject_src = """
[project]
name = "demo"
dependencies = ["requests==2.19.0"]

[project.optional-dependencies]
dev = ["urllib3==1.26.5"]

[dependency-groups]
lint = [{include-group = "base"}, "jinja2==3.0.0"]
"""
        specs_toml = parse_pyproject_toml(pyproject_src)
        names_toml = {s.package_name for s in specs_toml}
        self.assertEqual(names_toml, {"requests", "urllib3", "jinja2"})

        pip_lock_src = json.dumps({
            "default": {"requests": {"version": "==2.19.0"}},
            "develop": {"pyyaml": {"version": "==5.3"}},
        })
        specs_pip = parse_pipfile_lock(pip_lock_src)
        self.assertEqual({(s.package_name, s.specifier) for s in specs_pip}, {("requests", "==2.19.0"), ("pyyaml", "==5.3")})

        uv_lock_src = '[[package]]\nname = "urllib3"\nversion = "1.26.5"\n'
        specs_uv = parse_uv_lock(uv_lock_src)
        self.assertEqual(len(specs_uv), 1)
        self.assertEqual((specs_uv[0].package_name, specs_uv[0].specifier), ("urllib3", "==1.26.5"))

        with tempfile.TemporaryDirectory() as tmp:
            req_dir = os.path.join(tmp, "requirements")
            os.makedirs(req_dir)
            with open(os.path.join(tmp, "requirements-dev.txt"), "w", encoding="utf-8") as f:
                f.write("requests==2.19.0\n")
            with open(os.path.join(req_dir, "base.txt"), "w", encoding="utf-8") as f:
                f.write("urllib3==1.26.5\n")
            scanner = SecurityScanner(enable_secret_scan=False, enable_dependency_scan=True)
            rep = scanner.scan_path(tmp)
            found_pkgs = {f.metadata.get("package") for f in rep.findings}
            self.assertIn("requests", found_pkgs)
            self.assertIn("urllib3", found_pkgs)

    def test_single_pass_scan_and_extract_equivalence(self):
        det = SecretDetector()
        sample = (
            "prod_aws = 'AKIAJ2M4K8P9Q3R7W5T1'\n"
            "sample_aws = 'AKIAIOSFODNN7EXAMPLE'\n"
            "suppressed = 'AKIAJ2M4K8P9Q3R7W5T9'  # sidik:ignore\n"
        )
        f_single, c_single = det.scan_and_extract_content(sample, file_path="app.py", include_filtered=True)
        f_legacy = det.scan_content(sample, file_path="app.py")
        c_legacy = det.extract_candidates(sample, file_path="app.py", include_filtered=True)
        self.assertEqual([x.id for x in f_single], [x.id for x in f_legacy])
        self.assertEqual([x.candidate_id for x in c_single], [x.candidate_id for x in c_legacy])

    def test_cli_dx_flags_baseline_sarif_multipath_and_gui_help(self):
        with tempfile.TemporaryDirectory() as tmp:
            with open(os.path.join(tmp, "pyproject.toml"), "w", encoding="utf-8") as f:
                f.write('[tool.sidik]\nexclude = ["ignored_dir/"]\n')
            ign_dir = os.path.join(tmp, "ignored_dir")
            os.makedirs(ign_dir)
            with open(os.path.join(ign_dir, "secret.py"), "w", encoding="utf-8") as f:
                f.write("aws_key = 'AKIAJ2M4K8P9Q3R7W5T2'\n")

            a_py = os.path.join(tmp, "a.py")
            b_py = os.path.join(tmp, "b.py")
            with open(a_py, "w", encoding="utf-8") as f:
                f.write("aws_key = 'AKIAJ2M4K8P9Q3R7W5T1'\n")
            with open(b_py, "w", encoding="utf-8") as f:
                f.write("x = 1\n")

            baseline_file = os.path.join(tmp, "baseline.json")
            sarif_file = os.path.join(tmp, "out.sarif")
            summary_file = os.path.join(tmp, "step_summary.md")

            # Write baseline + secondary SARIF in single pass, with --no-step-summary
            with patch.dict(os.environ, {"GITHUB_STEP_SUMMARY": summary_file}):
                with redirect_stdout(io.StringIO()):
                    rc1 = run_cli_with_args([
                        tmp,
                        "--format", "github",
                        "--sarif-output", sarif_file,
                        "--write-baseline", baseline_file,
                        "--no-step-summary",
                        "--quiet",
                    ], exit_on_finish=False)
                self.assertEqual(rc1, 1)
                self.assertTrue(os.path.isfile(sarif_file))
                self.assertTrue(os.path.isfile(baseline_file))
                self.assertFalse(os.path.exists(summary_file))

            # Re-run with --baseline -> should suppress existing finding and pass cleanly (rc=0)
            with redirect_stdout(io.StringIO()):
                rc2 = run_cli_with_args([a_py, b_py, "--baseline", baseline_file, "--quiet"], exit_on_finish=False)
            self.assertEqual(rc2, 0)

        # sidik-gui --help should exit cleanly with 0 without importing tkinter
        with redirect_stdout(io.StringIO()):
            with self.assertRaises(SystemExit) as ctx:
                launch_gui_cli(["--help"])
        self.assertEqual(ctx.exception.code, 0)

    def test_sarif_repo_root_relative_uri(self):
        with tempfile.TemporaryDirectory() as tmp:
            sub = os.path.join(tmp, "src", "api")
            os.makedirs(sub)
            fp = os.path.join(sub, "service.py")
            with open(fp, "w", encoding="utf-8") as f:
                f.write("x = 1\n")
            report = ScanReport(
                summary=ScanSummary(target_path=sub, total_files_scanned=1),
                findings=[
                    Finding(
                        id="SEC-1",
                        finding_type="secret",
                        category="API_KEY",
                        title="AWS Key",
                        description="Exposed key",
                        file_path=fp,
                        line_number=1,
                        severity=SeverityLevel.CRITICAL,
                        confidence=ConfidenceScore.HIGH,
                        metadata={"rule_id": "SEC001"},
                    )
                ],
            )
            sarif = json.loads(ReportFormatter.to_sarif(report, repo_root=tmp))
            uri = sarif["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
            self.assertEqual(uri, "src/api/service.py")

    def test_gui_chart_bundle_honest_non_benchmark_metrics(self):
        from sidik.gui import _get_scans_output_root, generate_scan_chart_bundle
        try:
            import matplotlib  # noqa: F401
        except ImportError:
            self.skipTest("matplotlib not installed")

        with tempfile.TemporaryDirectory() as tmp:
            report = ScanReport(
                summary=ScanSummary(
                    target_path=os.path.join(tmp, "user_project"),
                    total_files_scanned=3,
                    total_secrets_found=1,
                    total_vulnerabilities_found=0,
                    scan_duration_seconds=0.05,
                    peak_memory_mb=0.42,
                ),
                findings=[
                    Finding(
                        id="SEC-1",
                        finding_type="secret",
                        category="API_KEY",
                        title="AWS Key",
                        description="Exposed key",
                        file_path=os.path.join(tmp, "user_project", "app.py"),
                        line_number=1,
                        severity=SeverityLevel.CRITICAL,
                        confidence=ConfidenceScore.HIGH,
                    )
                ],
            )
            info = generate_scan_chart_bundle(report, scans_root=tmp, crit_n=1, high_n=0, med_n=0, low_n=0)
            self.assertFalse(info["has_ground_truth"])
            self.assertIsNone(info["metrics"])
            self.assertTrue(os.path.isdir(os.path.join(tmp, info["scan_id"])))
            self.assertTrue(os.path.isfile(os.path.join(tmp, info["scan_id"], "fig_master_bundle.png")))
            self.assertTrue(_get_scans_output_root())


if __name__ == "__main__":
    unittest.main()
