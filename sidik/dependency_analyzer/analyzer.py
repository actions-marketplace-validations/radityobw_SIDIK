"""Dependency security analyzer orchestrator."""

import os
import re
from typing import Callable, List, Optional
from sidik.models import Finding, SeverityLevel, ConfidenceScore, compute_stable_id
from sidik.dependency_analyzer.parsers import (
    parse_requirements_txt,
    parse_pyproject_toml,
    parse_pipfile,
    parse_pipfile_lock,
    parse_poetry_lock,
    parse_uv_lock,
    parse_setup_py,
    DependencySpec
)
from sidik.dependency_analyzer.database import VulnerabilityDatabase
from sidik.dependency_analyzer.matcher import is_version_vulnerable
from sidik.i18n import get_dependency_remediation


MANIFEST_FILENAMES = {
    "requirements.txt": parse_requirements_txt,
    "pyproject.toml": parse_pyproject_toml,
    "Pipfile": parse_pipfile,
    "Pipfile.lock": parse_pipfile_lock,
    "poetry.lock": parse_poetry_lock,
    "uv.lock": parse_uv_lock,
    "setup.py": parse_setup_py
}

_REQ_TXT_RE = re.compile(r"^.*requirements(?:[-_.][a-z0-9_.-]+)?\.txt$")


def get_manifest_parser(file_path: str) -> Optional[Callable[[str], List[DependencySpec]]]:
    """Resolves the dependency manifest parser function for a file path, or None."""
    filename = os.path.basename(file_path)
    f_lower = filename.lower()
    for supported_name, p_func in MANIFEST_FILENAMES.items():
        if f_lower == supported_name.lower():
            return p_func
    if _REQ_TXT_RE.match(f_lower):
        return parse_requirements_txt
    parent_name = os.path.basename(os.path.dirname(os.path.abspath(file_path))).lower()
    if parent_name == "requirements" and f_lower.endswith(".txt"):
        return parse_requirements_txt
    return None


def is_manifest_file(file_path: str) -> bool:
    """Returns True if file_path matches any supported Python dependency manifest."""
    return get_manifest_parser(file_path) is not None


class DependencyAnalyzer:
    """Scans dependency manifests for vulnerable packages against advisory database."""

    def __init__(self, db: Optional[VulnerabilityDatabase] = None):
        self.db = db or VulnerabilityDatabase()

    def scan_manifest_file(self, file_path: str) -> List[Finding]:
        """Scans a single dependency manifest file for known vulnerabilities."""
        if not os.path.isfile(file_path):
            return []

        parser = get_manifest_parser(file_path)

        if not parser:
            return []

        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
        except Exception:
            return []

        specs: List[DependencySpec] = parser(content)
        findings: List[Finding] = []

        for spec in specs:
            advisories = self.db.get_advisories(spec.package_name)
            reported: set[str] = set()
            for adv in advisories:
                cve_id = adv.get("cve") or adv["id"]
                if cve_id in reported:
                    continue
                vuln, reason = is_version_vulnerable(spec.specifier, adv["vulnerable_specifier"])
                if vuln:
                    reported.add(cve_id)
                    finding_id = compute_stable_id(
                        f"DEP-{cve_id}",
                        file_path.replace("\\", "/"),
                        spec.package_name,
                        spec.specifier,
                    )
                    manifest_name = os.path.basename(file_path)
                    fixed_ver = adv.get("fixed_version")
                    remediation = get_dependency_remediation(
                        package_name=spec.package_name,
                        cve_id=cve_id,
                        fixed_version=fixed_ver,
                        manifest_file=manifest_name
                    )

                    findings.append(Finding(
                        id=finding_id,
                        finding_type="dependency",
                        category="VULNERABLE_DEPENDENCY",
                        title=f"Vulnerable Dependency: {spec.package_name} ({cve_id})",
                        description=adv["summary"],
                        file_path=file_path,
                        line_number=spec.line_number if spec.line_number > 0 else None,
                        snippet=spec.raw_line.strip(),
                        severity=SeverityLevel(adv.get("severity", "HIGH")),
                        confidence=ConfidenceScore.HIGH,
                        remediation=remediation,
                        metadata={
                            "package": spec.package_name,
                            "declared_version": spec.specifier,
                            "cve": cve_id,
                            "advisory_id": adv["id"],
                            "vulnerable_specifier": adv["vulnerable_specifier"],
                            "fixed_version": adv.get("fixed_version"),
                            "details": adv.get("details", ""),
                            "matching_reason": reason
                        }
                    ))

        return findings

    def scan_directory(self, dir_path: str) -> List[Finding]:
        """Finds and scans all dependency manifests within a directory tree."""
        findings: List[Finding] = []
        for root, _, files in os.walk(dir_path):
            for file in files:
                full_path = os.path.join(root, file)
                if is_manifest_file(full_path):
                    findings.extend(self.scan_manifest_file(full_path))
        return findings
