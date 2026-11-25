"""Semantic version evaluation and CVE advisory matching using packaging specifiers."""

import re
from typing import List, Optional, Sequence, Tuple
from packaging.version import Version, InvalidVersion
from packaging.specifiers import SpecifierSet, InvalidSpecifier

_HYPHEN_RANGE_RE = re.compile(r"^\s*v?([0-9][A-Za-z0-9._+-]*)\s+-\s+v?([0-9][A-Za-z0-9._+-]*)\s*$")
_PLAIN_VER_RE = re.compile(r"^[vV]?([0-9]+(?:\.[0-9]+)*(?:[-+.][0-9A-Za-z.]+)*)$")
_SINGLE_EQ_RE = re.compile(r"^=\s*v?([0-9].*)$")
_OP_PREFIX_RE = re.compile(r"^(>=|<=|!=|==|~=|~|\^|>|<|=)\s*v?(.+)$")


def _clean_semver_token(raw: str) -> str:
    """Converts common SemVer tokens (v1.2.3+incompatible, 1.2.3-alpha.1) into PEP 440 compatible strings."""
    tok = raw.strip().lstrip("vV").split("+", 1)[0]
    tok = re.sub(r"-alpha\.?", "a", tok, flags=re.IGNORECASE)
    tok = re.sub(r"-beta\.?", "b", tok, flags=re.IGNORECASE)
    tok = re.sub(r"-rc\.?", "rc", tok, flags=re.IGNORECASE)
    return tok


def _expand_caret_or_tilde(op: str, ver_body: str) -> str:
    v_str = _clean_semver_token(ver_body)
    if op == "^":
        try:
            v = Version(v_str)
            if v.major > 0:
                return f">={v_str},<{v.major + 1}.0.0"
            if v.minor > 0:
                return f">={v_str},<0.{v.minor + 1}.0"
            return f">={v_str},<0.0.{v.micro + 1}"
        except InvalidVersion:
            return f">={v_str}"
    try:
        v = Version(v_str)
        next_minor = v.minor + 1
        return f">={v_str},<{v.major}.{next_minor}.0"
    except InvalidVersion:
        return f">={v_str}"


def _expand_x_range(raw: str) -> Optional[str]:
    tok = raw.strip().lstrip("vV=")
    m_xy = re.match(r"^(\d+)\.(\d+)\.(?:x|X|\*)$", tok)
    if m_xy:
        maj, min_v = int(m_xy.group(1)), int(m_xy.group(2))
        return f">={maj}.{min_v}.0,<{maj}.{min_v + 1}.0"
    m_x = re.match(r"^(\d+)\.(?:x|X|\*)$", tok)
    if m_x:
        maj = int(m_x.group(1))
        return f">={maj}.0.0,<{maj + 1}.0.0"
    return None


def _normalize_single_clause(clause: str) -> str:
    c = clause.strip()
    if not c or c in ("*", "x", "X"):
        return ""
    x_exp = _expand_x_range(c)
    if x_exp is not None:
        return x_exp
    if c.startswith("^"):
        return _expand_caret_or_tilde("^", c[1:])
    if c.startswith("~") and not c.startswith("~="):
        return _expand_caret_or_tilde("~", c[1:])
    m_eq = _SINGLE_EQ_RE.match(c)
    if m_eq:
        return f"=={_clean_semver_token(m_eq.group(1))}"
    m_op = _OP_PREFIX_RE.match(c)
    if m_op:
        op = "==" if m_op.group(1) == "=" else m_op.group(1)
        return f"{op}{_clean_semver_token(m_op.group(2))}"
    m_plain = _PLAIN_VER_RE.match(c)
    if m_plain:
        return f"=={_clean_semver_token(m_plain.group(1))}"
    return c


def normalize_version_specifier(raw_spec: str) -> str:
    """Normalizes PyPI PEP 440, npm/Rust/Go/PHP SemVer ranges (^, ~, x-range, hyphen, space-AND) into specifiers."""
    spec = raw_spec.strip()
    if not spec or spec in ("*", "x", "X"):
        return ""

    # Hyphen range: 1.2.0 - 2.3.4 -> >=1.2.0,<=2.3.4
    m_hyph = _HYPHEN_RANGE_RE.match(spec)
    if m_hyph:
        lo = _clean_semver_token(m_hyph.group(1))
        hi = _clean_semver_token(m_hyph.group(2))
        return f">={lo},<={hi}"

    # Split comma or whitespace-separated comparator clauses (normalize 'op ver' spaces first)
    compacted = re.sub(r"(>=|<=|!=|==|~=|~|\^|>|<|=)\s+", r"\1", spec)
    parts: List[str] = []
    for comma_part in compacted.split(","):
        for sub in comma_part.strip().split():
            norm_part = _normalize_single_clause(sub)
            if norm_part:
                parts.append(norm_part)

    if not parts:
        return ""
    return ",".join(parts)


def extract_concrete_version(specifier_str: str) -> Optional[str]:
    """Attempts to extract a single concrete version from pinned specifiers."""
    match = re.search(r"==\s*([0-9a-zA-Z.\-]+)", specifier_str)
    if match:
        return _clean_semver_token(match.group(1))
    # Check for direct number
    match_direct = re.match(r"^[vV]?([0-9]+(?:\.[0-9a-zA-Z.-]+)+)$", specifier_str.strip())
    if match_direct:
        return _clean_semver_token(match_direct.group(1))
    return None


def _is_single_branch_vulnerable(
    declared_spec: str,
    vulnerable_spec: str,
    vulnerable_versions: Optional[Sequence[str]] = None,
) -> Tuple[bool, str]:
    """Evaluates one non-OR declared specifier branch against a vulnerable constraint."""
    norm_declared = normalize_version_specifier(declared_spec)
    if vulnerable_versions:
        if not norm_declared:
            return True, f"Unpinned dependency '*' matches {len(vulnerable_versions)} known vulnerable version(s)"
        parsed_vuln_versions = []
        for rv in vulnerable_versions:
            try:
                parsed_vuln_versions.append(Version(_clean_semver_token(str(rv))))
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
        return True, f"Unpinned dependency '*' matches vulnerable envelope {vulnerable_spec}"

    try:
        vuln_spec_set = SpecifierSet(normalize_version_specifier(vulnerable_spec) or vulnerable_spec)
    except InvalidSpecifier:
        return False, f"Invalid vulnerability specifier: {vulnerable_spec}"

    # Case 1: Exact version pinned (e.g. requests==2.25.0)
    concrete = extract_concrete_version(norm_declared)
    if concrete and "," not in norm_declared:
        try:
            v = Version(concrete)
            if v in vuln_spec_set:
                return True, f"Concrete version {concrete} is within vulnerable range ({vulnerable_spec})"
            return False, f"Version {concrete} is outside vulnerable range ({vulnerable_spec})"
        except InvalidVersion:
            pass

    # Case 2: Range specification (e.g. >=2.20.0, <2.28.0 or ^4.17.19)
    try:
        declared_spec_set = SpecifierSet(norm_declared)
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


def is_version_vulnerable(
    declared_spec: str,
    vulnerable_spec: str,
    vulnerable_versions: Optional[Sequence[str]] = None,
    ecosystem: str = "PyPI",
) -> Tuple[bool, str]:
    """Evaluates whether the declared dependency version satisfies the vulnerable constraint across OR branches."""
    _ = ecosystem  # Reserved for future ecosystem-specific edge-case overrides
    branches = [b.strip() for b in declared_spec.split("||") if b.strip()]
    if len(branches) <= 1:
        return _is_single_branch_vulnerable(declared_spec, vulnerable_spec, vulnerable_versions)

    last_reason = "Not vulnerable"
    for branch in branches:
        is_vuln, reason = _is_single_branch_vulnerable(branch, vulnerable_spec, vulnerable_versions)
        if is_vuln:
            return True, f"OR-branch '{branch}': {reason}"
        last_reason = reason
    return False, last_reason
