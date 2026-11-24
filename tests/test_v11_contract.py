"""Regression and API contract tests introduced for SIDIK v1.1.0 stabilization."""

import json
import os
import subprocess
import sys
import tempfile
import tracemalloc
import unittest

from sidik import (
    CANDIDATE_SCHEMA_VERSION,
    SecretCandidate,
    SecurityScanner,
    __version__,
)
from sidik.dependency_analyzer.matcher import is_version_vulnerable
from sidik.dependency_analyzer.parsers import (
    parse_pipfile,
    parse_pyproject_toml,
    parse_requirements_txt,
    parse_setup_py,
)
from sidik.models import compute_stable_id
from sidik.secret_detector.detector import SecretDetector


class TestSidikV11Stabilization(unittest.TestCase):
    """Verifies packaging, determinism, non-intrusive tracemalloc, parser fixes, and ML contract."""

    def test_version_and_exports(self):
        self.assertEqual(__version__, "1.3.6")
        self.assertEqual(CANDIDATE_SCHEMA_VERSION, "1.0.0")
        self.assertEqual(compute_stable_id("SEC-SEC001", "a.py", "1"), compute_stable_id("SEC-SEC001", "a.py", "1"))

    def test_deterministic_ids_across_hash_seeds(self):
        """Finding IDs must stay identical regardless of PYTHONHASHSEED."""
        sidik_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        snippet = (
            "from sidik.secret_detector.detector import SecretDetector\n"
            "d = SecretDetector()\n"
            "res = d.scan_content(\"aws_key = 'AKIAJ2M4K8P9Q3R7W5T1'\", file_path='app.py')\n"
            "print(res[0].id)\n"
        )
        ids = []
        for seed in ("111", "999"):
            env = os.environ.copy()
            env["PYTHONHASHSEED"] = seed
            proc = subprocess.run(
                [sys.executable, "-c", snippet],
                cwd=sidik_root,
                env=env,
                capture_output=True,
                text=True,
                check=True,
            )
            ids.append(proc.stdout.strip())
        self.assertEqual(ids[0], ids[1])
        self.assertTrue(ids[0].startswith("SEC-SEC001-"))

    def test_sec012_precheck_sync(self):
        """SEC012 generic rule keywords (token, auth, credential) must pass fast line precheck."""
        detector = SecretDetector(enable_context=True, enable_entropy=True)
        code = (
            "my_token = 'aB9cD8eF7gH6iJ5kL4mN3oP2qR1sT0uV'\n"
            "service_auth = 'Zp7Yq9Xr5Wt3Vu1Ts0Rq8Po6Nm4Lk2Ji'\n"
            "user_credential = 'M9n8B7v6C5x4Z3a2S1d0F9g8H7j6K5l4'\n"
        )
        findings = detector.scan_content(code, file_path="config.py")
        self.assertEqual(len(findings), 3)

    def test_tracemalloc_non_interference(self):
        """Default SecurityScanner must not mutate caller tracemalloc state."""
        was_tracing = tracemalloc.is_tracing()
        if was_tracing:
            tracemalloc.stop()

        with tempfile.TemporaryDirectory() as tmp:
            fp = os.path.join(tmp, "sample.py")
            with open(fp, "w", encoding="utf-8") as f:
                f.write("x = 1\n")

            # 1. Default measure_memory=False does not start tracemalloc
            scanner_default = SecurityScanner(measure_memory=False)
            scanner_default.scan_path(tmp)
            self.assertFalse(tracemalloc.is_tracing())

            # 2. If caller already runs tracemalloc, even measure_memory=True must not stop it
            tracemalloc.start()
            try:
                scanner_mem = SecurityScanner(measure_memory=True)
                scanner_mem.scan_path(tmp)
                self.assertTrue(tracemalloc.is_tracing())
            finally:
                if tracemalloc.is_tracing():
                    tracemalloc.stop()

    def test_results_directory_is_not_silently_skipped(self):
        """Target directories named 'results' or 'figures' must be scanned unless listed in .sidikignore."""
        with tempfile.TemporaryDirectory() as tmp:
            res_dir = os.path.join(tmp, "results")
            os.makedirs(res_dir)
            fp = os.path.join(res_dir, "leak.py")
            with open(fp, "w", encoding="utf-8") as f:
                f.write("aws_key = 'AKIAJ2M4K8P9Q3R7W5T1'\n")

            scanner = SecurityScanner(enable_dependency_scan=False)
            report = scanner.scan_path(tmp)
            self.assertEqual(report.summary.total_secrets_found, 1)

    def test_secret_candidate_contract_and_no_raw_secret_leak(self):
        """extract_candidates captures both passed and filtered candidates safely without raw secret values."""
        detector = SecretDetector(enable_context=True, enable_entropy=True)
        raw_real = "AKIAJ2M4K8P9Q3R7W5T1"
        raw_mock = "AKIAIOSFODNN7EXAMPLE"
        code = (
            f"prod_aws_key = '{raw_real}'\n"
            f"test_aws_key = '{raw_mock}'\n"
        )
        candidates = detector.extract_candidates(code, file_path="tests/sample_cfg.py", include_filtered=True)
        self.assertEqual(len(candidates), 2)
        self.assertIsInstance(candidates[0], SecretCandidate)

        passed = [c for c in candidates if c.deterministic_decision.get("passed_deterministic_filter")]
        rejected = [c for c in candidates if not c.deterministic_decision.get("passed_deterministic_filter")]
        self.assertEqual(len(passed), 1)
        self.assertEqual(len(rejected), 1)

        serialized = json.dumps([c.to_dict() for c in candidates])
        self.assertNotIn(raw_real, serialized)
        self.assertNotIn(raw_mock, serialized)
        self.assertEqual(passed[0].schema_version, CANDIDATE_SCHEMA_VERSION)
        self.assertTrue(passed[0].file_context["is_test_path"])
        self.assertIn("upper_ratio", passed[0].string_stats)
        self.assertIn("is_placeholder_or_mock", rejected[0].lexical_context)
        self.assertTrue(rejected[0].lexical_context["is_placeholder_or_mock"])

    def test_parser_and_matcher_edge_cases(self):
        """Verifies PEP 508 extras/markers, Pipfile dicts, AST setup.py, and matcher ranges."""
        req_specs = parse_requirements_txt("requests[security,socks]==2.25.0 ; python_version >= '3.8'\n")
        self.assertEqual(len(req_specs), 1)
        self.assertEqual(req_specs[0].package_name, "requests")
        self.assertEqual(req_specs[0].specifier, "==2.25.0")

        toml_specs = parse_pyproject_toml('[project]\ndependencies = ["urllib3[brotli]<1.26.18,>=1.20"]\n')
        self.assertEqual(len(toml_specs), 1)
        self.assertEqual(toml_specs[0].package_name, "urllib3")

        pipfile_specs = parse_pipfile('[packages]\nrequests = {version = "==2.25.1", extras = ["socks"]}\n')
        self.assertEqual(len(pipfile_specs), 1)
        self.assertEqual(pipfile_specs[0].specifier, "==2.25.1")

        setup_code = (
            "from setuptools import setup\n"
            "DEPS = ['requests[security]==2.25.0']\n"
            "setup(name='x', install_requires=DEPS)\n"
        )
        setup_specs = parse_setup_py(setup_code)
        self.assertEqual(len(setup_specs), 1)
        self.assertEqual(setup_specs[0].package_name, "requests")
        self.assertEqual(setup_specs[0].specifier, "==2.25.0")

        # Matcher: upper-bound-only & Poetry 0.x caret
        vuln_upper, _ = is_version_vulnerable("<2.30.0", "<2.31.0")
        self.assertTrue(vuln_upper)
        vuln_caret, _ = is_version_vulnerable("^0.4.2", "<0.4.4")
        self.assertTrue(vuln_caret)
        safe_caret, _ = is_version_vulnerable("^0.4.4", "<0.4.4")
        self.assertFalse(safe_caret)


if __name__ == "__main__":
    unittest.main()
