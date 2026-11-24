"""Unit tests for dependency analyzer, manifest parsers, and vulnerability matching."""

import unittest
from sidik.dependency_analyzer.parsers import (
    parse_requirements_txt,
    parse_pyproject_toml,
    parse_pipfile,
    parse_poetry_lock
)
from sidik.dependency_analyzer.matcher import is_version_vulnerable
from sidik.dependency_analyzer.analyzer import DependencyAnalyzer


class TestDependencyAnalyzer(unittest.TestCase):

    def setUp(self):
        self.analyzer = DependencyAnalyzer()

    def test_parse_requirements(self):
        content = """
        # Core requirements
        requests==2.25.1
        urllib3>=1.26.0,<1.26.18
        django==3.2.5
        flask # unpinned
        """
        specs = parse_requirements_txt(content)
        self.assertEqual(len(specs), 4)
        self.assertEqual(specs[0].package_name, "requests")
        self.assertEqual(specs[0].specifier, "==2.25.1")
        self.assertEqual(specs[3].specifier, "*")

    def test_parse_pyproject_pep621(self):
        content = """
        [project]
        dependencies = [
            "requests==2.25.1",
            "jinja2<3.1.4"
        ]
        """
        specs = parse_pyproject_toml(content)
        self.assertEqual(len(specs), 2)
        self.assertEqual(specs[0].package_name, "requests")

    def test_vulnerability_matching(self):
        # requests 2.25.1 is vulnerable to CVE-2023-32681 (<2.31.0)
        is_vuln, reason = is_version_vulnerable("==2.25.1", "<2.31.0")
        self.assertTrue(is_vuln)

        # requests 2.31.0 is safe
        is_vuln_safe, _ = is_version_vulnerable("==2.31.0", "<2.31.0")
        self.assertFalse(is_vuln_safe)

    def test_vulnerability_matching_with_ranges(self):
        # urllib3 1.26.17 is safe for CVE-2023-43804 (<1.26.17)
        is_vuln, _ = is_version_vulnerable("==1.26.17", "<1.26.17,>=1.20")
        self.assertFalse(is_vuln)

        # urllib3 1.26.10 is vulnerable
        is_vuln_bad, _ = is_version_vulnerable("==1.26.10", "<1.26.17,>=1.20")
        self.assertTrue(is_vuln_bad)

    def test_parse_setup_py(self):
        content = """
        from setuptools import setup
        setup(
            name="demo-pkg",
            install_requires=[
                "requests==2.25.1",
                "django>=3.2.0,<3.2.14"
            ]
        )
        """
        from sidik.dependency_analyzer.parsers import parse_setup_py
        specs = parse_setup_py(content)
        self.assertEqual(len(specs), 2)
        self.assertEqual(specs[0].package_name, "requests")
        self.assertEqual(specs[1].package_name, "django")

    def test_parse_git_repo_and_direct_url_dependencies(self):
        import os
        import tempfile

        req_content = """
        requests @ git+https://github.com/psf/requests.git@v2.19.0
        git+ssh://git@github.com/psf/requests.git@v2.32.3#egg=requests
        -e git+https://github.com/urllib3/urllib3.git@1.26.5#egg=urllib3
        urllib3 @ https://github.com/urllib3/urllib3/archive/refs/tags/v1.26.5.tar.gz
        django @ https://files.pythonhosted.org/packages/django-3.2.5-py3-none-any.whl
        flask @ git+https://github.com/pallets/flask.git@main
        flask @ git+https://github.com/pallets/flask.git@0123456789abcdef
        -e .
        -r base.txt
        """
        specs = parse_requirements_txt(req_content)
        self.assertEqual([(s.package_name, s.specifier) for s in specs], [
            ("requests", "==2.19.0"),
            ("requests", "==2.32.3"),
            ("urllib3", "==1.26.5"),
            ("urllib3", "==1.26.5"),
            ("django", "==3.2.5"),
            ("flask", "*"),
            ("flask", "*"),
        ])

        poetry_toml = """
        [tool.poetry.dependencies]
        python = "^3.9"
        requests = { git = "https://github.com/psf/requests.git", tag = "v2.19.0" }
        urllib3 = { url = "https://github.com/urllib3/urllib3/archive/refs/tags/v1.26.5.tar.gz" }
        """
        p_specs = parse_pyproject_toml(poetry_toml)
        self.assertEqual([(s.package_name, s.specifier) for s in p_specs], [
            ("requests", "==2.19.0"),
            ("urllib3", "==1.26.5"),
        ])

        pipfile_toml = """
        [packages]
        requests = { git = "https://github.com/psf/requests.git", ref = "v2.19.0" }

        [dev-packages]
        django = { git = "https://github.com/django/django.git", ref = "3.2.5" }
        """
        pf_specs = parse_pipfile(pipfile_toml)
        self.assertEqual([(s.package_name, s.specifier) for s in pf_specs], [
            ("requests", "==2.19.0"),
            ("django", "==3.2.5"),
        ])

        # End-to-end SCA scan: vulnerable Git tag detects CVE-2023-32681; safe Git tag v2.32.3 avoids it
        with tempfile.TemporaryDirectory() as tmp:
            vuln_req = os.path.join(tmp, "requirements.txt")
            with open(vuln_req, "w", encoding="utf-8") as fh:
                fh.write("requests @ git+https://github.com/psf/requests.git@v2.19.0\n")
            findings_vuln = DependencyAnalyzer().scan_directory(tmp)
            self.assertTrue(any("CVE-2023-32681" in (f.metadata.get("cve") or f.title) for f in findings_vuln))

            with open(vuln_req, "w", encoding="utf-8") as fh:
                fh.write("requests @ git+https://github.com/psf/requests.git@v2.32.3\n")
            findings_safe = DependencyAnalyzer().scan_directory(tmp)
            self.assertFalse(any("CVE-2023-32681" in (f.metadata.get("cve") or f.title) for f in findings_safe))


if __name__ == "__main__":
    unittest.main()

