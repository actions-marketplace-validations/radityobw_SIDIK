"""Secret detector engine coordinating regex matching, entropy validation, and context filtering."""

import hashlib
import os
import re
from typing import List, Optional, Dict, Any, Tuple
from sidik.models import (
    Finding,
    SeverityLevel,
    ConfidenceScore,
    SecretCandidate,
    CANDIDATE_SCHEMA_VERSION,
    compute_stable_id,
)
from sidik.secret_detector.patterns import SECRET_PATTERNS
from sidik.secret_detector.entropy import calculate_shannon_entropy, analyze_charset_distribution
from sidik.secret_detector.context import (
    evaluate_line_context,
    is_comment_line,
    is_env_reference_line,
    is_placeholder_or_mock,
    UUID_PATTERN,
    GIT_SHA_PATTERN,
)
from sidik.i18n import get_secret_remediation

_FAST_LINE_PRECHECK = re.compile(
    r"(?i)(?:AKIA|AIza|sk-|sk_live_|ghp_|github_pat_|xox[baprs]-|eyJ|"
    r"password|passwd|pwd|db_pass|user_pass|://|PRIVATE KEY-----|"
    r"secret|api_?key|token|auth|credential|client_?secret|access_?token)"
)

_PROVIDER_PREFIXES = (
    "AKIA", "AIza", "sk-proj-", "sk_live_", "sk-",
    "ghp_", "github_pat_", "xox", "eyJ", "-----BEGIN"
)
_HEX_RE = re.compile(r"^[0-9a-fA-F]+$")
_BASE64_RE = re.compile(r"^[A-Za-z0-9+/=_\-]+$")
_ASSIGN_IDENT_RE = re.compile(r"^\s*(?:['\"]?)([A-Za-z_][A-Za-z0-9_\-.]*)(?:['\"]?)\s*(?:=|:=|:)")
_TEST_PATH_MARKERS = ("test", "tests", "mock", "fixture", "spec")
_EXAMPLE_PATH_MARKERS = ("example", "examples", "sample", "doc", "docs", "readme")
DEFAULT_MAX_FILE_SIZE_BYTES = 5 * 1024 * 1024  # 5 MB safety guard


def _read_text_file_safely(file_path: str, max_bytes: int = DEFAULT_MAX_FILE_SIZE_BYTES) -> Optional[str]:
    """Reads a UTF-8 text file safely, skipping missing, oversized, or binary (NUL-byte) files."""
    if not os.path.isfile(file_path):
        return None
    try:
        if max_bytes > 0 and os.path.getsize(file_path) > max_bytes:
            return None
        with open(file_path, "rb") as fb:
            head = fb.read(4096)
            if b"\x00" in head:
                return None
            rest = fb.read()
        return (head + rest).decode("utf-8", errors="ignore")
    except Exception:
        return None


def mask_secret(secret: str) -> str:
    """Masks secret value for safe reporting."""
    if len(secret) <= 6:
        return "*" * len(secret)
    prefix_len = min(4, len(secret) // 4)
    suffix_len = min(4, len(secret) // 4)
    masked_len = len(secret) - prefix_len - suffix_len
    return secret[:prefix_len] + ("*" * masked_len) + secret[-suffix_len:]


def _extract_provider_prefix(candidate: str) -> Optional[str]:
    for pfx in _PROVIDER_PREFIXES:
        if candidate.startswith(pfx):
            return pfx
    return None


def _build_secret_candidate(
    rule: Dict[str, Any],
    candidate: str,
    line: str,
    prev_line: str,
    file_path: str,
    line_num: int,
    col_start: int,
    col_end: int,
    entropy: float,
    is_valid: bool,
    confidence: ConfidenceScore,
    context_meta: Dict[str, Any],
    has_inline_suppression: bool,
) -> SecretCandidate:
    """Builds a leak-safe structured SecretCandidate record without persisting raw secret literals."""
    norm_path = file_path.replace("\\", "/")
    path_lower = norm_path.lower()
    masked_val = mask_secret(candidate)
    masked_line = line.replace(candidate, masked_val).strip()
    charset = analyze_charset_distribution(candidate)
    is_mock, mock_reason = is_placeholder_or_mock(candidate, line)
    ident_match = _ASSIGN_IDENT_RE.match(line)
    clues = list(context_meta.get("context_clues", []))

    rejection_reason: Optional[str] = None
    if not is_valid:
        if has_inline_suppression:
            rejection_reason = "inline_suppression"
        elif clues:
            rejection_reason = str(clues[-1])
        else:
            rejection_reason = "filtered_by_rule"

    provider_pfx = _extract_provider_prefix(candidate)
    file_name = os.path.basename(norm_path)
    _, ext = os.path.splitext(file_name.lower())

    return SecretCandidate(
        candidate_id=compute_stable_id(
            f"SEC-{rule['id']}", norm_path, str(line_num), str(col_start), candidate
        ),
        schema_version=CANDIDATE_SCHEMA_VERSION,
        rule_id=rule["id"],
        rule_name=rule["name"],
        category=rule["category"],
        severity=SeverityLevel(rule["severity"]),
        masked_value=masked_val,
        value_sha256=hashlib.sha256(candidate.encode("utf-8")).hexdigest(),
        file_path=file_path,
        line_number=line_num,
        column_start=col_start,
        column_end=col_end,
        entropy=entropy,
        string_stats={
            "length": len(candidate),
            "unique_chars": len(set(candidate)),
            "unique_ratio": round(len(set(candidate)) / max(1, len(candidate)), 4),
            "digit_ratio": charset["digit"],
            "lower_ratio": charset["lower"],
            "upper_ratio": charset["upper"],
            "symbol_ratio": charset["symbol"],
            "is_hex_like": bool(_HEX_RE.match(candidate)),
            "is_base64_like": bool(_BASE64_RE.match(candidate)),
            "is_uuid_like": bool(UUID_PATTERN.match(candidate)),
            "is_git_sha_like": bool(GIT_SHA_PATTERN.match(candidate)),
            "matched_provider_prefix": provider_pfx,
        },
        lexical_context={
            "is_comment": is_comment_line(line),
            "is_placeholder_or_mock": is_mock,
            "placeholder_reason": mock_reason,
            "has_positive_keyword": "positive_keyword_context" in clues,
            "has_inline_suppression": has_inline_suppression,
            "identifier_name": ident_match.group(1) if ident_match else None,
            "context_clues": clues,
        },
        pattern_evidence={
            "rule_id": rule["id"],
            "rule_name": rule["name"],
            "category": rule["category"],
            "min_entropy": float(rule.get("min_entropy", 0.0)),
            "meets_entropy_threshold": entropy >= float(rule.get("min_entropy", 0.0)),
            "is_generic_rule": rule["id"] == "SEC012",
        },
        code_context={
            "line_length": len(line),
            "is_assignment": ("=" in line or ":=" in line),
            "is_dict_entry": (":" in line and ("{" in line or line.strip().startswith(("'", '"')))),
            "is_function_call": ("(" in line and ")" in line),
            "is_env_reference": is_env_reference_line(line),
            "masked_line": masked_line,
            "prev_line_is_comment": is_comment_line(prev_line),
        },
        file_context={
            "file_extension": ext,
            "file_name": file_name,
            "is_test_path": any(m in path_lower for m in _TEST_PATH_MARKERS),
            "is_example_or_doc_path": any(m in path_lower for m in _EXAMPLE_PATH_MARKERS),
            "path_depth": len([seg for seg in norm_path.split("/") if seg]),
        },
        deterministic_decision={
            "passed_deterministic_filter": is_valid,
            "confidence": confidence.value,
            "rejection_reason": rejection_reason,
        },
    )


class SecretDetector:
    """Core secret detection scanner with configurable ablation options."""

    def __init__(
        self,
        enable_context: bool = True,
        enable_entropy: bool = True,
        max_file_size_bytes: int = DEFAULT_MAX_FILE_SIZE_BYTES,
    ):
        self.enable_context = enable_context
        self.enable_entropy = enable_entropy
        self.max_file_size_bytes = max_file_size_bytes
        self.patterns = SECRET_PATTERNS

    def _evaluate_match(self, candidate: str, line: str, rule: Dict[str, Any], entropy: float):
        is_valid = True
        confidence = ConfidenceScore.MEDIUM
        meta: Dict[str, Any] = {
            "rule_id": rule["id"],
            "rule_name": rule["name"],
            "raw_entropy": entropy
        }

        if self.enable_entropy and not self.enable_context:
            min_ent = rule.get("min_entropy", 2.0)
            if entropy < min_ent:
                is_valid = False
        elif self.enable_context:
            is_valid, confidence, context_meta = evaluate_line_context(
                candidate=candidate,
                line=line,
                rule=rule if self.enable_entropy else {"min_entropy": 0.0},
                entropy=entropy
            )
            meta.update(context_meta)

        return is_valid, confidence, meta

    def scan_and_extract_content(
        self,
        content: str,
        file_path: str = "memory",
        include_filtered: bool = True,
    ) -> Tuple[List[Finding], List[SecretCandidate]]:
        """Scans content and extracts structured SecretCandidate objects in a single pass."""
        findings: List[Finding] = []
        candidates: List[SecretCandidate] = []
        lines = content.splitlines()
        use_fast_precheck = (self.patterns is SECRET_PATTERNS)
        specific_patterns = [r for r in self.patterns if r["id"] != "SEC012"]
        generic_rule = next((r for r in self.patterns if r["id"] == "SEC012"), None)
        norm_path = file_path.replace("\\", "/")

        def _append_hit(
            rule: Dict[str, Any],
            candidate_str: str,
            line: str,
            prev_line: str,
            line_num: int,
            col_start: int,
            col_end: int,
            entropy: float,
            is_valid: bool,
            confidence: ConfidenceScore,
            meta: Dict[str, Any],
            has_inline_suppression: bool,
        ) -> None:
            finding_id = compute_stable_id(
                f"SEC-{rule['id']}", norm_path, str(line_num), str(col_start), candidate_str
            )
            if is_valid and not has_inline_suppression:
                findings.append(Finding(
                    id=finding_id,
                    finding_type="secret",
                    category=rule["category"],
                    title=f"{rule['name']} Found",
                    description=rule["description"],
                    file_path=file_path,
                    line_number=line_num,
                    snippet=f"Line {line_num}: {line.replace(candidate_str, mask_secret(candidate_str)).strip()}",
                    severity=SeverityLevel(rule["severity"]),
                    confidence=confidence,
                    remediation=get_secret_remediation(rule["id"]) or rule.get("remediation"),
                    metadata=meta,
                ))
            if include_filtered or (is_valid and not has_inline_suppression):
                candidates.append(_build_secret_candidate(
                    rule=rule,
                    candidate=candidate_str,
                    line=line,
                    prev_line=prev_line,
                    file_path=file_path,
                    line_num=line_num,
                    col_start=col_start,
                    col_end=col_end,
                    entropy=entropy,
                    is_valid=(is_valid and not has_inline_suppression),
                    confidence=confidence,
                    context_meta=meta,
                    has_inline_suppression=has_inline_suppression,
                ))

        for line_num, line in enumerate(lines, start=1):
            if use_fast_precheck and not _FAST_LINE_PRECHECK.search(line):
                continue

            prev_line = lines[line_num - 2] if line_num >= 2 else ""
            line_lower = line.lower()
            has_inline_suppression = (
                "sidik:ignore" in line_lower
                or "# nosec" in line_lower
                or "// nosec" in line_lower
                or "# noqa: sidik" in line_lower
                or "// noqa: sidik" in line_lower
            )
            if has_inline_suppression and not include_filtered:
                continue

            matched_specific = False

            for rule in specific_patterns:
                for match in rule["pattern"].finditer(line):
                    grp_idx = 1 if match.groups() else 0
                    candidate_str = match.group(grp_idx)
                    if not candidate_str:
                        continue
                    entropy = calculate_shannon_entropy(candidate_str)
                    is_valid, confidence, meta = self._evaluate_match(candidate_str, line, rule, entropy)
                    if is_valid and not has_inline_suppression:
                        matched_specific = True
                    _append_hit(
                        rule, candidate_str, line, prev_line, line_num,
                        match.start(grp_idx), match.end(grp_idx),
                        entropy, is_valid, confidence, meta, has_inline_suppression,
                    )

            if not matched_specific and generic_rule:
                for match in generic_rule["pattern"].finditer(line):
                    grp_idx = 1 if match.groups() else 0
                    candidate_str = match.group(grp_idx)
                    if not candidate_str:
                        continue
                    entropy = calculate_shannon_entropy(candidate_str)
                    is_valid, confidence, meta = self._evaluate_match(candidate_str, line, generic_rule, entropy)
                    _append_hit(
                        generic_rule, candidate_str, line, prev_line, line_num,
                        match.start(grp_idx), match.end(grp_idx),
                        entropy, is_valid, confidence, meta, has_inline_suppression,
                    )

        return findings, candidates

    def scan_and_extract_file(
        self,
        file_path: str,
        include_filtered: bool = True,
    ) -> Tuple[List[Finding], List[SecretCandidate]]:
        """Reads file safely and returns both Findings and SecretCandidates in one pass."""
        content = _read_text_file_safely(file_path, max_bytes=self.max_file_size_bytes)
        if content is None:
            return [], []
        return self.scan_and_extract_content(content, file_path=file_path, include_filtered=include_filtered)

    def extract_candidates(
        self,
        content: str,
        file_path: str = "memory",
        include_filtered: bool = True
    ) -> List[SecretCandidate]:
        """Extracts structured pre-triage SecretCandidate records for inspection or ML inference."""
        _, candidates = self.scan_and_extract_content(content, file_path=file_path, include_filtered=include_filtered)
        return candidates

    def extract_candidates_from_file(self, file_path: str, include_filtered: bool = True) -> List[SecretCandidate]:
        """Extracts structured SecretCandidate records from a local file."""
        content = _read_text_file_safely(file_path, max_bytes=self.max_file_size_bytes)
        if content is None:
            return []
        return self.extract_candidates(content, file_path=file_path, include_filtered=include_filtered)

    def scan_content(self, content: str, file_path: str = "memory") -> List[Finding]:
        """Scans source code content string and returns all identified secret findings."""
        findings, _ = self.scan_and_extract_content(content, file_path=file_path, include_filtered=False)
        return findings

    def scan_file(self, file_path: str) -> List[Finding]:
        """Scans a single local file for hardcoded secrets."""
        content = _read_text_file_safely(file_path, max_bytes=self.max_file_size_bytes)
        if content is None:
            return []
        return self.scan_content(content, file_path=file_path)
