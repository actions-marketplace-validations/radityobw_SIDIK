"""Semantic version evaluation and CVE advisory matching using packaging specifiers."""

import re
from typing import Optional, Sequence, Tuple
from packaging.version import Version, InvalidVersion
from packaging.specifiers import SpecifierSet, InvalidSpecifier


def normalize_version_specifier(raw_spec: str) -> str:
    """Normalizes poetry / pipenv symbols (e.g. ^, ~) into PEP 440 specifiers."""
    spec = raw_spec.strip()
    if not spec or spec == "*":
        return ""

    # Poetry caret: ^1.2.3 -> >=1.2.3,<2.0.0 ; ^0.2.3 -> >=0.2.3,<0.3.0 ; ^0.0.3 -> >=0.0.3,<0.0.4
    if spec.startswith("^"):
        v_str = spec[1:].strip()
        try:
            v = Version(v_str)
            if v.major > 0:
                return f">={v_str},<{v.major + 1}.0.0"
            if v.minor > 0:
                return f">={v_str},<0.{v.minor + 1}.0"
            return f">={v_str},<0.0.{v.micro + 1}"
        except InvalidVersion:
            return f">={v_str}"

    # Poetry tilde: ~1.2.3 -> >=1.2.3, <1.3.0
    if spec.startswith("~") and not spec.startswith("~="):
        v_str = spec[1:].strip()
        try:
            v = Version(v_str)
            next_minor = v.minor + 1
            return f">={v_str},<{v.major}.{next_minor}.0"
        except InvalidVersion:
            return f">={v_str}"

    # Plain version without operator: "2.25.1" -> "==2.25.1"
    if re.match(r"^[0-9]+(?:\.[0-9a-zA-Z]+)*$", spec):
        return f"=={spec}"

    return spec


def extract_concrete_version(specifier_str: str) -> Optional[str]:
    """Attempts to extract a single concrete version from pinned specifiers."""
    match = re.search(r"==\s*([0-9a-zA-Z\.\-]+)", specifier_str)
    if match:
        return match.group(1)
    # Check for direct number
    match_direct = re.match(r"^([0-9]+(?:\.[0-9a-zA-Z]+)+)$", specifier_str.strip())
    if match_direct:
        return match_direct.group(1)
    return None


def is_version_vulnerable(
    declared_spec: str,
    vulnerable_spec: str,
    vulnerable_versions: Optional[Sequence[str]] = None,
) -> Tuple[bool, str]:
    """Evaluates whether the declared dependency version satisfies the vulnerable constraint.

    Returns:
        (is_vulnerable: bool, matched_reason: str)
    """
    norm_declared = normalize_version_specifier(declared_spec)
    if vulnerable_versions:
        if not norm_declared:
            return True, f"Unpinned dependency '*' matches {len(vulnerable_versions)} known vulnerable version(s)"
        parsed_vuln_versions = []
        for rv in vulnerable_versions:
            try:
                parsed_vuln_versions.append(Version(str(rv)))
            except InvalidVersion:
                continue
        if not parsed_vuln_versions:
            return False, "No valid explicit vulnerable versions"

        concrete = extract_concrete_version(norm_declared)
        if concrete:
            try:
                v = Version(concrete)
                if v in set(parsed_vuln_versions):
                    return True, f"Concrete version {concrete} matches explicit vulnerable version list"
                return False, f"Version {concrete} is outside explicit vulnerable version list"
            except InvalidVersion:
                pass
        try:
            declared_spec_set = SpecifierSet(norm_declared)
            for v_vuln in parsed_vuln_versions:
                if v_vuln in declared_spec_set:
                    return True, f"Declared range '{norm_declared}' includes explicit vulnerable version {v_vuln}"
            return False, f"Declared range '{norm_declared}' avoids explicit vulnerable versions"
        except InvalidSpecifier:
            return False, f"Invalid declared specifier: {declared_spec}"

    if not norm_declared:
        # Wildcard or unpinned dependency: considered risky
        return True, f"Unpinned dependency '*' matches vulnerable envelope {vulnerable_spec}"

    try:
        vuln_spec_set = SpecifierSet(vulnerable_spec)
    except InvalidSpecifier:
        return False, f"Invalid vulnerability specifier: {vulnerable_spec}"

    # Case 1: Exact version pinned (e.g. requests==2.25.0)
    concrete = extract_concrete_version(norm_declared)
    if concrete:
        try:
            v = Version(concrete)
            if v in vuln_spec_set:
                return True, f"Concrete version {concrete} is within vulnerable range ({vulnerable_spec})"
            else:
                return False, f"Version {concrete} is outside vulnerable range ({vulnerable_spec})"
        except InvalidVersion:
            pass

    # Case 2: Range specification (e.g. >=2.20.0, <2.28.0 or <2.30.0)
    try:
        declared_spec_set = SpecifierSet(norm_declared)
        # Check if lower bound or sample points are in the vulnerable set
        probe_versions = []
        for spec in declared_spec_set:
            try:
                v_bound = Version(spec.version)
            except InvalidVersion:
                continue
            if spec.operator in (">=", "==", "~="):
                probe_versions.append(v_bound)
            elif spec.operator == ">":
                probe_versions.append(Version(f"{v_bound.major}.{v_bound.minor}.{v_bound.micro + 1}"))
                probe_versions.append(Version(f"{v_bound.major}.{v_bound.minor + 1}.0"))
            elif spec.operator in ("<", "<="):
                if spec.operator == "<=":
                    probe_versions.append(v_bound)
                probe_versions.append(Version("0.0.0"))
                if v_bound.micro > 0:
                    probe_versions.append(Version(f"{v_bound.major}.{v_bound.minor}.{v_bound.micro - 1}"))
                if v_bound.minor > 0:
                    probe_versions.append(Version(f"{v_bound.major}.{v_bound.minor - 1}.0"))
                if v_bound.major > 0:
                    probe_versions.append(Version(f"{v_bound.major - 1}.0.0"))

        for spec in vuln_spec_set:
            try:
                v_vuln = Version(spec.version)
            except InvalidVersion:
                continue
            if spec.operator in (">=", "==", "~="):
                probe_versions.append(v_vuln)
            elif spec.operator == ">":
                probe_versions.append(Version(f"{v_vuln.major}.{v_vuln.minor}.{v_vuln.micro + 1}"))

        for sample_v in probe_versions:
            if sample_v in declared_spec_set and sample_v in vuln_spec_set:
                return True, f"Declared range '{norm_declared}' intersects with {vulnerable_spec} (e.g. {sample_v})"
    except InvalidSpecifier:
        pass

    return False, "Not vulnerable"
