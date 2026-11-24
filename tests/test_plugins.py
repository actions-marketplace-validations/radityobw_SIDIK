"""Unit tests for the decoupled SIDIK post-scan plugin architecture (v1.2.0)."""

import json
import os
import tempfile
import unittest
from typing import Any, Dict, Optional

from sidik import SecurityScanner
from sidik.cli import run_cli_with_args
from sidik.models import ScanReport
from sidik.plugins import PostScanPlugin, apply_post_scan_plugins
from sidik.reporting.formatter import ReportFormatter


class _DummyMLPlugin:
    name = "dummy-ml"
    version = "0.1.0"
    description = "Deterministic test double implementing PostScanPlugin"

    def triage_report(
        self,
        scanner: Any,
        target_path: str,
        report: ScanReport,
        options: Optional[Dict[str, Any]] = None,
    ) -> ScanReport:
        opts = options or {}
        for finding in report.findings:
            if finding.finding_type == "secret":
                finding.metadata["ml_triage"] = {
                    "action": "KEEP_ALERT",
                    "predicted_is_secret": True,
                    "secret_probability": 0.91,
                    "model_name": str(opts.get("model_path") or "dummy_non_neural"),
                    "model_version": self.version,
                    "suppressed_by_ml": False,
                    "top_feature_contributions": {"shannon_entropy": 4.2, "is_test_path": 0.0},
                }
        return report


class TestSidikPluginArchitecture(unittest.TestCase):
    """Validates plugin protocol, scanner pass-through, formatter rendering, and strict decoupling."""

    def test_decoupling_no_sidik_ml_imports_in_sidik(self):
        pkg_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "sidik")
        for root, _, files in os.walk(pkg_dir):
            for fn in files:
                if fn.endswith(".py"):
                    full_path = os.path.join(root, fn)
                    with open(full_path, "r", encoding="utf-8") as fh:
                        content = fh.read()
                    self.assertNotIn("sidik_ml", content, f"Forbidden coupling to sidik_ml in {full_path}")

    def test_post_scan_plugin_protocol_and_unified_scan(self):
        plugin = _DummyMLPlugin()
        self.assertIsInstance(plugin, PostScanPlugin)

        with tempfile.TemporaryDirectory() as tmp:
            py_file = os.path.join(tmp, "app.py")
            req_file = os.path.join(tmp, "requirements.txt")
            with open(py_file, "w", encoding="utf-8") as f:
                f.write("aws_key = 'AKIAJ2M4K8P9Q3R7W5T1'\n")
            with open(req_file, "w", encoding="utf-8") as f:
                f.write("requests==2.19.0\n")

            scanner = SecurityScanner(
                enable_secret_scan=True,
                enable_dependency_scan=True,
                post_scan_plugins=[plugin],
                plugin_options={"model_path": "unit_test.skops"},
            )
            report = scanner.scan_path(tmp)

            sec_findings = [f for f in report.findings if f.finding_type == "secret"]
            dep_findings = [f for f in report.findings if f.finding_type == "dependency"]
            self.assertEqual(len(sec_findings), 1)
            self.assertGreaterEqual(len(dep_findings), 1)
            self.assertIn("ml_triage", sec_findings[0].metadata)
            self.assertEqual(sec_findings[0].metadata["ml_triage"]["model_name"], "unit_test.skops")
            self.assertNotIn("ml_triage", dep_findings[0].metadata)

            console = ReportFormatter.to_console_summary(report, lang="id", use_color=False)
            md = ReportFormatter.to_markdown(report, lang="id")
            html_out = ReportFormatter.to_html(report, lang="en")
            sarif_doc = json.loads(ReportFormatter.to_sarif(report))
            json_doc = json.loads(ReportFormatter.to_json(report))
            csv_out = ReportFormatter.to_csv(report)

            self.assertIn("ML Triage:", console)
            self.assertIn("[SIDIK-ML Hybrid Triage]", console)
            self.assertIn("**ML Triage:**", md)
            self.assertIn("SIDIK-ML Hybrid Triage", md)
            self.assertIn("ML Probability:", html_out)
            self.assertIn("SIDIK-ML Hybrid Security Dashboard", html_out)
            self.assertIn("#ea580c", html_out)
            self.assertIn("#f59e0b", html_out)
            self.assertNotIn("Research Edition", html_out)
            self.assertEqual(sarif_doc["runs"][0]["tool"]["driver"]["version"], "1.3.4")
            sarif_secret_results = [
                r for r in sarif_doc["runs"][0]["results"]
                if not r["ruleId"].startswith("SIDIK-SCA-")
            ]
            self.assertEqual(len(sarif_secret_results), 1)
            self.assertIn("properties", sarif_secret_results[0])
            self.assertIn("ml_triage", sarif_secret_results[0]["properties"])
            json_secret_findings = [
                f for f in json_doc["findings"]
                if f["finding_type"] == "secret"
            ]
            self.assertEqual(len(json_secret_findings), 1)
            self.assertIn("ml_triage", json_secret_findings[0]["metadata"])
            self.assertIn("ml_triage", csv_out)

    def test_apply_post_scan_plugins_noop_without_plugins(self):
        with tempfile.TemporaryDirectory() as tmp:
            py_file = os.path.join(tmp, "app.py")
            with open(py_file, "w", encoding="utf-8") as f:
                f.write("aws_key = 'AKIAJ2M4K8P9Q3R7W5T1'\n")
            scanner = SecurityScanner(enable_dependency_scan=False)
            report = scanner.scan_path(tmp)
            unchanged = apply_post_scan_plugins(scanner, tmp, report, plugins=None)
            self.assertIs(unchanged, report)
            self.assertNotIn("ml_triage", unchanged.findings[0].metadata)

    def test_cli_list_plugins_and_unknown_plugin_error(self):
        code_list = run_cli_with_args(["--list-plugins"], exit_on_finish=False)
        self.assertEqual(code_list, 0)

        with tempfile.TemporaryDirectory() as tmp:
            code_bad = run_cli_with_args(["--target", tmp, "--plugin", "nonexistent-plugin-xyz"], exit_on_finish=False)
            self.assertEqual(code_bad, 2)

    def test_cli_symmetric_interactive_and_gui_shorthands(self):
        from unittest.mock import patch

        with patch("sidik.cli.run_interactive_cli", return_value=0) as mock_tui:
            for argv in (["-i"], ["interactive"], ["cli"], ["tui"]):
                mock_tui.reset_mock()
                code = run_cli_with_args(argv, exit_on_finish=False)
                self.assertEqual(code, 0)
                mock_tui.assert_called_once()

        with patch("sidik.gui.main") as mock_gui:
            for argv, expected_ml in ((["--gui"], False), (["gui"], False), (["--gui", "--enable-ml"], True)):
                mock_gui.reset_mock()
                code = run_cli_with_args(argv, exit_on_finish=False)
                self.assertEqual(code, 0)
                mock_gui.assert_called_once()
                _, kwargs = mock_gui.call_args
                self.assertEqual(kwargs["enable_ml"], expected_ml)


if __name__ == "__main__":
    unittest.main()
