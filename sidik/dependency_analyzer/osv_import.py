"""Conversion of Google OSV (PyPI ecosystem) advisories into the SIDIK offline database format.

The OSV schema expresses affected versions as ordered ``introduced`` / ``fixed`` /
``last_affected`` events. SIDIK stores one PEP 440 specifier per record (for example
``>=1.0,<1.4.2``), so every event interval becomes its own advisory record.
"""

import argparse
import hashlib
import io
import json
import math
import os
import sqlite3
import sys
import time
import urllib.request
import zipfile
from typing import Any, Dict, Iterable, List, Optional, Tuple

from packaging.specifiers import InvalidSpecifier, SpecifierSet
from packaging.version import InvalidVersion, Version

from sidik.dependency_analyzer.database import (
    SUPPORTED_ECOSYSTEMS,
    canonicalize_ecosystem,
    get_user_db_path,
    get_user_sqlite_db_path,
)
from sidik.dependency_analyzer.matcher import _clean_semver_token
from sidik.dependency_analyzer.parsers import normalize_ecosystem_package_name

OSV_PYPI_URL = "https://osv-vulnerabilities.storage.googleapis.com/PyPI/all.zip"
OSV_ECOSYSTEM_URLS: Dict[str, str] = {
    eco: f"https://osv-vulnerabilities.storage.googleapis.com/{eco}/all.zip"
    for eco in SUPPORTED_ECOSYSTEMS
}
DEFAULT_OUTPUT_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data", "pypi_advisories.json"
)
MAX_DETAILS_CHARS = 400
MAX_ZIP_UNCOMPRESSED_BYTES = 512 * 1024 * 1024  # 512 MB decompression guard

SEVERITY_ALIASES = {
    "CRITICAL": "CRITICAL",
    "HIGH": "HIGH",
    "MODERATE": "MEDIUM",
    "MEDIUM": "MEDIUM",
    "LOW": "LOW",
}
DEFAULT_SEVERITY = "MEDIUM"

_CVSS_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
_CVSS_AC = {"L": 0.77, "H": 0.44}
_CVSS_UI = {"N": 0.85, "R": 0.62}
_CVSS_CIA = {"H": 0.56, "L": 0.22, "N": 0.0}


def _roundup(value: float) -> float:
    """CVSS v3.1 Roundup function (Appendix A of the specification)."""
    as_int = round(value * 100000)
    if as_int % 10000 == 0:
        return as_int / 100000.0
    return (math.floor(as_int / 10000) + 1) / 10.0


def cvss3_base_score(vector: str) -> Optional[float]:
    """Computes the CVSS v3.x base score from a vector string, or None when unparseable."""
    parts = vector.strip().split("/")
    if not parts or parts[0] not in ("CVSS:3.0", "CVSS:3.1"):
        return None
    metrics: Dict[str, str] = {}
    for part in parts[1:]:
        if ":" in part:
            key, val = part.split(":", 1)
            metrics[key] = val
    try:
        scope_changed = metrics["S"] == "C"
        privileges = {"N": 0.85, "L": 0.68 if scope_changed else 0.62, "H": 0.5 if scope_changed else 0.27}
        iss = 1 - (
            (1 - _CVSS_CIA[metrics["C"]])
            * (1 - _CVSS_CIA[metrics["I"]])
            * (1 - _CVSS_CIA[metrics["A"]])
        )
        exploitability = (
            8.22 * _CVSS_AV[metrics["AV"]] * _CVSS_AC[metrics["AC"]]
            * privileges[metrics["PR"]] * _CVSS_UI[metrics["UI"]]
        )
    except KeyError:
        return None
    if scope_changed:
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
    else:
        impact = 6.42 * iss
    if impact <= 0:
        return 0.0
    if scope_changed:
        return _roundup(min(1.08 * (impact + exploitability), 10.0))
    return _roundup(min(impact + exploitability, 10.0))


def score_to_severity(score: float) -> str:
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    if score > 0.0:
        return "LOW"
    return "INFO"


_CVSS2_AV = {"L": 0.395, "A": 0.646, "N": 1.0}
_CVSS2_AC = {"H": 0.35, "M": 0.61, "L": 0.71}
_CVSS2_AU = {"M": 0.45, "S": 0.56, "N": 0.704}
_CVSS2_CIA = {"N": 0.0, "P": 0.275, "C": 0.660}


def cvss2_base_score(vector: str) -> Optional[float]:
    """Computes a CVSS v2.0 base score from an OSV vector string, or None when unparseable."""
    raw = vector.strip()
    if raw.startswith("CVSS:2.0/"):
        raw = raw[len("CVSS:2.0/"):]
    metrics: Dict[str, str] = {}
    for part in raw.split("/"):
        if ":" in part:
            k, v = part.split(":", 1)
            metrics[k] = v
    try:
        av = _CVSS2_AV[metrics["AV"]]
        ac = _CVSS2_AC[metrics["AC"]]
        au = _CVSS2_AU[metrics["Au"]]
        c = _CVSS2_CIA[metrics["C"]]
        i = _CVSS2_CIA[metrics["I"]]
        a = _CVSS2_CIA[metrics["A"]]
    except KeyError:
        return None
    impact = 10.41 * (1.0 - (1.0 - c) * (1.0 - i) * (1.0 - a))
    exploitability = 20.0 * av * ac * au
    f_impact = 0.0 if impact == 0.0 else 1.176
    score = ((0.6 * impact) + (0.4 * exploitability) - 1.5) * f_impact
    return max(0.0, min(10.0, round(score, 1)))


def cvss4_severity(vector: str) -> Optional[str]:
    """Maps a CVSS v4.0 base vector string to CRITICAL/HIGH/MEDIUM/LOW, or None if invalid."""
    parts = vector.strip().split("/")
    if not parts or parts[0] != "CVSS:4.0":
        return None
    metrics: Dict[str, str] = {}
    for part in parts[1:]:
        if ":" in part:
            k, v = part.split(":", 1)
            metrics[k] = v
    if not any(k in metrics for k in ("VC", "VI", "VA", "SC", "SI", "SA")):
        return None
    vc = metrics.get("VC", "N")
    vi = metrics.get("VI", "N")
    va = metrics.get("VA", "N")
    sc = metrics.get("SC", "N")
    si = metrics.get("SI", "N")
    sa = metrics.get("SA", "N")
    impacts = (vc, vi, va, sc, si, sa)
    if (vc == "H" and vi == "H" and va == "H") or (
        metrics.get("AV") == "N"
        and metrics.get("PR") == "N"
        and metrics.get("UI") == "N"
        and ("H" in (vc, vi) or (sc == "H" and si == "H"))
    ):
        return "CRITICAL"
    if "H" in impacts:
        return "HIGH"
    if "L" in impacts:
        return "MEDIUM"
    return "LOW"


def extract_severity(record: Dict[str, Any]) -> Tuple[str, str]:
    """Returns (severity, source) across database_specific, CVSS v3/v4/v2, MAL-*, or default."""
    db_specific = record.get("database_specific")
    if isinstance(db_specific, dict):
        label = str(db_specific.get("severity", "")).upper()
        if label in SEVERITY_ALIASES:
            return SEVERITY_ALIASES[label], "database_specific"

    for affected in record.get("affected", []) or []:
        if not isinstance(affected, dict):
            continue
        for sub_key in ("database_specific", "ecosystem_specific"):
            sub = affected.get(sub_key)
            if isinstance(sub, dict):
                label = str(sub.get("severity", "")).upper()
                if label in SEVERITY_ALIASES:
                    return SEVERITY_ALIASES[label], "database_specific"

    for entry in record.get("severity", []) or []:
        if not isinstance(entry, dict):
            continue
        sev_type = str(entry.get("type", "")).upper()
        vec = str(entry.get("score", ""))
        if sev_type.startswith("CVSS_V3"):
            score = cvss3_base_score(vec)
            if score is not None:
                return score_to_severity(score), "cvss_v3"
        elif sev_type.startswith("CVSS_V4"):
            sev = cvss4_severity(vec)
            if sev is not None:
                return sev, "cvss_v4"
        elif sev_type.startswith("CVSS_V2"):
            score = cvss2_base_score(vec)
            if score is not None:
                return ("HIGH" if score >= 7.0 else score_to_severity(score)), "cvss_v2"

    if str(record.get("id", "")).startswith("MAL-"):
        return "CRITICAL", "malicious_package"

    return DEFAULT_SEVERITY, "default"


def events_to_specifiers(events: List[Dict[str, Any]]) -> List[Tuple[str, Optional[str]]]:
    """Turns OSV range events into (PEP 440 specifier, fixed_version) pairs."""
    intervals: List[Tuple[str, Optional[str], Optional[str]]] = []  # (introduced, upper clause, fixed)
    current: Optional[str] = None
    for event in events:
        if "introduced" in event:
            if current is not None:
                intervals.append((current, None, None))
            current = str(event["introduced"])
        elif "fixed" in event:
            intervals.append((current if current is not None else "0", "<" + str(event["fixed"]), str(event["fixed"])))
            current = None
        elif "last_affected" in event:
            intervals.append((current if current is not None else "0", "<=" + str(event["last_affected"]), None))
            current = None
    if current is not None:
        intervals.append((current, None, None))

    results: List[Tuple[str, Optional[str]]] = []
    for introduced, upper, fixed in intervals:
        clauses: List[str] = []
        clean_intro = _clean_semver_token(introduced) if introduced != "0" else "0"
        if clean_intro and clean_intro != "0":
            clauses.append(">=" + clean_intro)
        if upper:
            op = "<=" if upper.startswith("<=") else "<"
            ver_u = upper[len(op):]
            clean_u = _clean_semver_token(ver_u)
            clauses.append(op + clean_u)
        specifier = ",".join(clauses) if clauses else ">=0"
        try:
            SpecifierSet(specifier)
        except InvalidSpecifier:
            continue
        clean_fixed = _clean_semver_token(fixed) if fixed else None
        results.append((specifier, clean_fixed))
    return results


def _pick_cve(record: Dict[str, Any]) -> str:
    record_id = str(record.get("id", ""))
    if record_id.startswith("CVE-"):
        return record_id
    for alias in record.get("aliases", []) or []:
        if str(alias).startswith("CVE-"):
            return str(alias)
    return record_id


def _summary_and_details(record: Dict[str, Any]) -> Tuple[str, str]:
    details = str(record.get("details", "") or "").strip()
    summary = str(record.get("summary", "") or "").strip()
    if not summary and details:
        summary = details.splitlines()[0][:160]
    if len(details) > MAX_DETAILS_CHARS:
        details = details[:MAX_DETAILS_CHARS].rstrip() + "..."
    return summary, details


def convert_osv_record(record: Dict[str, Any], ecosystem: str = "PyPI") -> Tuple[List[Dict[str, Any]], str]:
    """Converts one OSV record into SIDIK advisories for target ecosystem. Returns (advisories, severity_source)."""
    if record.get("withdrawn"):
        return [], "default"
    record_id = str(record.get("id", ""))
    if not record_id:
        return [], "default"

    target_eco = canonicalize_ecosystem(ecosystem) or ecosystem
    target_eco_low = target_eco.lower()
    is_pypi = target_eco_low == "pypi"

    severity, severity_source = extract_severity(record)
    cve = _pick_cve(record)
    summary, details = _summary_and_details(record)

    advisories: List[Dict[str, Any]] = []
    seen: set[Tuple[str, str]] = set()
    for affected in record.get("affected", []) or []:
        package = affected.get("package") or {}
        if str(package.get("ecosystem", "")).lower() != target_eco_low:
            continue
        name = normalize_ecosystem_package_name(str(package.get("name", "")), target_eco)
        if not name:
            continue
        range_hits = 0
        for rng in affected.get("ranges", []) or []:
            if str(rng.get("type", "")).upper() not in ("ECOSYSTEM", "SEMVER"):
                continue
            for specifier, fixed in events_to_specifiers(rng.get("events", []) or []):
                range_hits += 1
                key = (name, specifier)
                if key in seen:
                    continue
                seen.add(key)
                adv_entry: Dict[str, Any] = {
                    "id": record_id,
                    "cve": cve,
                    "package": name,
                    "vulnerable_specifier": specifier,
                    "fixed_version": fixed,
                    "severity": severity,
                    "summary": summary,
                    "details": details,
                }
                if not is_pypi:
                    adv_entry["ecosystem"] = target_eco
                advisories.append(adv_entry)

        if range_hits == 0:
            raw_versions = affected.get("versions") or []
            parsed_vers: List[Tuple[Version, str]] = []
            seen_ver_strs: set[str] = set()
            for rv in raw_versions:
                v_str = _clean_semver_token(str(rv).strip())
                if not v_str or v_str in seen_ver_strs:
                    continue
                try:
                    v_obj = Version(v_str)
                except InvalidVersion:
                    continue
                seen_ver_strs.add(v_str)
                parsed_vers.append((v_obj, v_str))

            if parsed_vers:
                parsed_vers.sort(key=lambda item: item[0])
                valid_versions = [v_str for _, v_str in parsed_vers]
                if len(valid_versions) == 1:
                    spec_str = f"=={valid_versions[0]}"
                    key = (name, spec_str)
                    if key not in seen:
                        seen.add(key)
                        adv_single: Dict[str, Any] = {
                            "id": record_id,
                            "cve": cve,
                            "package": name,
                            "vulnerable_specifier": spec_str,
                            "fixed_version": None,
                            "severity": severity,
                            "summary": summary,
                            "details": details,
                        }
                        if not is_pypi:
                            adv_single["ecosystem"] = target_eco
                        advisories.append(adv_single)
                else:
                    spec_str = f"explicit({len(valid_versions)} versions)"
                    key = (name, spec_str)
                    if key not in seen:
                        seen.add(key)
                        adv_multi: Dict[str, Any] = {
                            "id": record_id,
                            "cve": cve,
                            "package": name,
                            "vulnerable_specifier": spec_str,
                            "vulnerable_versions": valid_versions,
                            "fixed_version": None,
                            "severity": severity,
                            "summary": summary,
                            "details": details,
                        }
                        if not is_pypi:
                            adv_multi["ecosystem"] = target_eco
                        advisories.append(adv_multi)
    return advisories, severity_source


def build_database(
    records: Iterable[Dict[str, Any]],
    source: str,
    source_sha256: str,
    ecosystem: str = "PyPI",
) -> Dict[str, Any]:
    """Builds the on-disk payload (metadata plus sorted advisory list) from OSV records."""
    target_eco = canonicalize_ecosystem(ecosystem) or ecosystem
    advisories: List[Dict[str, Any]] = []
    record_count = 0
    skipped = 0
    severity_sources: Dict[str, int] = {
        "database_specific": 0,
        "cvss_v3": 0,
        "cvss_v4": 0,
        "cvss_v2": 0,
        "malicious_package": 0,
        "default": 0,
    }
    for record in records:
        record_count += 1
        converted, sev_source = convert_osv_record(record, ecosystem=target_eco)
        if not converted:
            skipped += 1
            continue
        severity_sources[sev_source] = severity_sources.get(sev_source, 0) + len(converted)
        advisories.extend(converted)

    advisories.sort(key=lambda a: (a["package"], a["id"], a["vulnerable_specifier"]))
    return {
        "metadata": {
            "ecosystem": target_eco,
            "source": source,
            "source_sha256": source_sha256,
            "generated_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "osv_record_count": record_count,
            "skipped_record_count": skipped,
            "advisory_count": len(advisories),
            "package_count": len({a["package"] for a in advisories}),
            "severity_sources": severity_sources,
        },
        "advisories": advisories,
    }


def read_zip_records(zip_bytes: bytes, max_uncompressed_bytes: int = MAX_ZIP_UNCOMPRESSED_BYTES) -> Iterable[Dict[str, Any]]:
    with zipfile.ZipFile(io.BytesIO(zip_bytes)) as zf:
        total_uncompressed = 0
        for info in zf.infolist():
            name = info.filename
            if not name.lower().endswith(".json"):
                continue
            total_uncompressed += max(0, info.file_size)
            if total_uncompressed > max_uncompressed_bytes:
                raise ValueError(
                    f"OSV archive uncompressed size exceeds limit ({max_uncompressed_bytes} bytes)"
                )
            try:
                data = json.loads(zf.read(name).decode("utf-8"))
            except (ValueError, UnicodeDecodeError):
                continue
            if isinstance(data, dict):
                yield data


def download_osv_zip(url: str = OSV_PYPI_URL, timeout: int = 180) -> bytes:
    if not url.startswith("https://"):
        raise ValueError(f"Refusing non-HTTPS OSV download URL: {url}")
    with urllib.request.urlopen(url, timeout=timeout) as response:  # noqa: S310 (validated https URL)
        return response.read()


def write_database(payload: Dict[str, Any], output_path: str) -> None:
    os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(payload, f, ensure_ascii=False, separators=(",", ":"))


def write_sqlite_ecosystem(
    advisories: List[Dict[str, Any]],
    metadata: Dict[str, Any],
    ecosystem: str,
    sqlite_path: Optional[str] = None,
) -> str:
    """Stores one ecosystem's OSV advisories inside the indexed SQLite user cache."""
    resolved = sqlite_path or get_user_sqlite_db_path()
    os.makedirs(os.path.dirname(os.path.abspath(resolved)), exist_ok=True)
    conn = sqlite3.connect(resolved)
    try:
        conn.execute(
            "CREATE TABLE IF NOT EXISTS advisories ("
            "ecosystem TEXT NOT NULL, "
            "package TEXT NOT NULL, "
            "id TEXT NOT NULL, "
            "cve TEXT, "
            "vulnerable_specifier TEXT NOT NULL, "
            "vulnerable_versions TEXT, "
            "fixed_version TEXT, "
            "severity TEXT, "
            "summary TEXT, "
            "details TEXT)"
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_adv_eco_pkg ON advisories(lower(ecosystem), package)"
        )
        conn.execute(
            "CREATE TABLE IF NOT EXISTS ecosystem_meta ("
            "ecosystem TEXT PRIMARY KEY, "
            "advisory_count INTEGER, "
            "package_count INTEGER, "
            "generated_utc TEXT, "
            "source TEXT)"
        )
        with conn:
            conn.execute("DELETE FROM advisories WHERE lower(ecosystem) = lower(?)", (ecosystem,))
            conn.executemany(
                "INSERT INTO advisories VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                [
                    (
                        ecosystem,
                        a["package"],
                        a["id"],
                        a.get("cve"),
                        a["vulnerable_specifier"],
                        json.dumps(a["vulnerable_versions"]) if "vulnerable_versions" in a else None,
                        a.get("fixed_version"),
                        a.get("severity"),
                        a.get("summary"),
                        a.get("details"),
                    )
                    for a in advisories
                ],
            )
            conn.execute(
                "INSERT OR REPLACE INTO ecosystem_meta (ecosystem, advisory_count, package_count, generated_utc, source) "
                "VALUES (?, ?, ?, ?, ?)",
                (
                    ecosystem,
                    int(metadata.get("advisory_count", len(advisories))),
                    int(metadata.get("package_count", 0)),
                    str(metadata.get("generated_utc", "")),
                    str(metadata.get("source", "")),
                ),
            )
    finally:
        conn.close()
    return resolved


def import_osv(input_zip: Optional[str] = None, output_path: Optional[str] = None,
               url: str = OSV_PYPI_URL, ecosystem: str = "PyPI") -> Dict[str, Any]:
    """Downloads (or reads) an OSV ecosystem archive and writes JSON (PyPI) or SQLite cache. Returns metadata."""
    target_eco = canonicalize_ecosystem(ecosystem) or ecosystem
    resolved_url = url if (target_eco == "PyPI" or url != OSV_PYPI_URL) else OSV_ECOSYSTEM_URLS.get(target_eco, url)
    if input_zip:
        with open(input_zip, "rb") as f:
            raw = f.read()
        source = os.path.basename(input_zip)
    else:
        raw = download_osv_zip(resolved_url)
        source = resolved_url
    payload = build_database(read_zip_records(raw), source, hashlib.sha256(raw).hexdigest(), ecosystem=target_eco)
    if target_eco.lower() == "pypi":
        resolved_output = output_path or get_user_db_path()
        write_database(payload, resolved_output)
        payload["metadata"]["output_path"] = resolved_output
    else:
        sqlite_out = write_sqlite_ecosystem(
            payload["advisories"], payload["metadata"], target_eco, sqlite_path=output_path
        )
        payload["metadata"]["output_path"] = sqlite_out
    return payload["metadata"]


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Import Google OSV dumps into SIDIK offline databases")
    parser.add_argument("--input", default=None, help="Local all.zip path (skips download)")
    parser.add_argument("--output", default=None, help="Output JSON/SQLite path (defaults to user cache directory)")
    parser.add_argument("--url", default=OSV_PYPI_URL, help="OSV archive URL")
    parser.add_argument(
        "--ecosystem",
        default="PyPI",
        help="Target OSV ecosystem(s), comma-separated or 'all' (PyPI, npm, Go, crates.io, Maven, Packagist, RubyGems, NuGet)",
    )
    args = parser.parse_args(argv)

    raw_eco = (args.ecosystem or "PyPI").strip()
    if raw_eco.lower() == "all":
        ecos = list(SUPPORTED_ECOSYSTEMS)
    else:
        ecos = []
        for part in raw_eco.split(","):
            tok = part.strip()
            if not tok:
                continue
            canon = canonicalize_ecosystem(tok)
            if not canon:
                print(
                    f"Error: Unsupported ecosystem '{tok}'. Supported: {', '.join(SUPPORTED_ECOSYSTEMS)}",
                    file=sys.stderr,
                )
                return 1
            if canon not in ecos:
                ecos.append(canon)
        if not ecos:
            ecos = ["PyPI"]

    try:
        results = []
        for eco in ecos:
            eco_url = OSV_ECOSYSTEM_URLS.get(eco, args.url) if args.url == OSV_PYPI_URL else args.url
            meta = import_osv(args.input, args.output, eco_url, ecosystem=eco)
            results.append(meta)
    except (OSError, zipfile.BadZipFile, ValueError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    print(json.dumps(results[0] if len(results) == 1 else results, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
