"""Formatters for scan reports: JSON, Markdown, CSV, and Modern Rich Terminal Table."""

import base64
import csv
import html
from importlib import resources
import io
import json
import os
import sys
from typing import Dict, Any, Optional
from sidik.models import ScanReport


# Windows ANSI terminal enablement via built-in ctypes
if sys.platform == "win32":
    try:
        import ctypes
        kernel32 = ctypes.windll.kernel32
        handle = kernel32.GetStdHandle(-11)  # STD_OUTPUT_HANDLE
        mode = ctypes.c_ulong()
        if kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
            kernel32.SetConsoleMode(handle, mode.value | 0x0004)  # ENABLE_VIRTUAL_TERMINAL_PROCESSING
    except Exception:
        pass


def _detect_ml_edition(report: ScanReport) -> bool:
    """Returns True when any finding carries SIDIK-ML triage metadata."""
    return any(
        isinstance((getattr(f, "metadata", None) or {}).get("ml_triage"), dict)
        for f in getattr(report, "findings", [])
    )


def _format_ml_triage_summary(ml_meta: Dict[str, Any]) -> str:
    """Formats optional SIDIK-ML triage metadata cleanly for console and Markdown output."""
    action = str(ml_meta.get("action", "KEEP_ALERT"))
    prob = float(ml_meta.get("secret_probability", 0.0))
    model_name = str(ml_meta.get("model_name", "N/A"))
    summary = f"{action} (p={prob:.2f}, model={model_name})"
    top_feats = ml_meta.get("top_feature_contributions")
    if isinstance(top_feats, dict) and top_feats:
        items = ", ".join(f"{k}={float(v):.3f}" if isinstance(v, (int, float)) else f"{k}={v}" for k, v in list(top_feats.items())[:3])
        summary += f" | Top features: {items}"
    return summary


class ReportFormatter:
    """Renders ScanReport into various output formats: JSON, Markdown, CSV, and Modern Console."""

    @staticmethod
    def to_json(report: ScanReport, indent: int = 2) -> str:
        """Formats report as standardized JSON string."""
        return json.dumps(report.to_dict(), indent=indent)

    @staticmethod
    def to_csv(report: ScanReport) -> str:
        """Exports all findings into a structured CSV format."""
        output = io.StringIO()
        writer = csv.writer(output, lineterminator="\n")

        # CSV Header
        writer.writerow([
            "Finding_ID",
            "Type",
            "Category",
            "Severity",
            "Confidence",
            "File_Path",
            "Line_Number",
            "Title",
            "Description",
            "Code_Snippet",
            "Remediation",
            "Metadata"
        ])

        for f in report.findings:
            meta_str = json.dumps(f.metadata) if f.metadata else ""
            writer.writerow([
                f.id,
                f.finding_type,
                f.category,
                f.severity.value if hasattr(f.severity, "value") else str(f.severity),
                f.confidence.value if hasattr(f.confidence, "value") else str(f.confidence),
                f.file_path,
                f.line_number or "",
                f.title,
                f.description,
                f.snippet or "",
                f.remediation or "",
                meta_str
            ])

        return output.getvalue()

    @staticmethod
    def to_markdown(report: ScanReport, lang: str = "en") -> str:
        """Formats report as detailed Markdown document in English or Indonesian."""
        from sidik import __version__ as SIDIK_VERSION
        from sidik.i18n import get_secret_remediation, get_dependency_remediation
        s = report.summary
        is_id = (lang.lower() == "id")
        is_ml = _detect_ml_edition(report)

        if is_ml:
            md_title = f"# 🛡️ SIDIK-ML Hybrid Triage (Core SIDIK v{SIDIK_VERSION}): Secret Identification and Dependency Inspection Kit"
            title_sub = (
                "### Laporan Analisis Keamanan & Klasifikasi Triage Non-ANN ML"
                if is_id
                else "### Automated Security Assessment & Explainable Non-ANN ML Triage Report"
            )
        else:
            md_title = f"# 🛡️ SIDIK: Secret Identification and Dependency Inspection Kit (v{SIDIK_VERSION})"
            title_sub = "### Laporan Otomatis Analisis Keamanan & Audit Kerentanan" if is_id else "### Automated Security Assessment & Vulnerability Audit Report"
        sum_heading = "## Ringkasan Eksekutif" if is_id else "## Summary"
        findings_heading = "## Temuan Keamanan" if is_id else "## Findings"
        detailed_heading = "### Rincian Temuan & Rekomendasi" if is_id else "### Detailed Findings"
        clean_msg = "*Tidak ditemukan kerentanan atau kebocoran kredensial pada target.*" if is_id else "*No security issues detected.*"

        lbl_target = "Path Target" if is_id else "Target Path"
        lbl_time = "Waktu Pemindaian" if is_id else "Scan Timestamp"
        lbl_files = "Berkas Dipindai" if is_id else "Files Scanned"
        lbl_secrets = "Secrets Ditemukan" if is_id else "Secrets Found"
        lbl_deps = "Kerentanan Dependensi" if is_id else "Vulnerabilities Found"
        lbl_duration = "Durasi Pemindaian" if is_id else "Scan Duration"
        lbl_memory = "Konsumsi Memori" if is_id else "Peak Memory"

        table_header = "| # | Tipe | Kategori | Tingkat Bahaya | Confidence | Lokasi | Detail |" if is_id else "| # | Type | Category | Severity | Confidence | Location | Detail |"
        lbl_category = "Kategori" if is_id else "Category"
        lbl_conf = "Confidence" if is_id else "Confidence"
        lbl_file = "Berkas" if is_id else "File"
        lbl_line = "Baris" if is_id else "Line"
        lbl_code = "Kode" if is_id else "Code"
        lbl_desc = "Deskripsi" if is_id else "Description"
        lbl_remed = "Rekomendasi Perbaikan" if is_id else "Remediation"

        md = [
            md_title,
            title_sub,
            "",
            sum_heading,
            f"- **{lbl_target}:** `{s.target_path}`",
            f"- **{lbl_time}:** `{s.timestamp}`",
            f"- **{lbl_files}:** {s.total_files_scanned}",
            f"- **{lbl_secrets}:** {s.total_secrets_found}",
            f"- **{lbl_deps}:** {s.total_vulnerabilities_found}",
            f"- **{lbl_duration}:** {s.scan_duration_seconds}s",
            f"- **{lbl_memory}:** {s.peak_memory_mb} MB",
            "",
            "---",
            "",
            findings_heading,
            ""
        ]

        if not report.findings:
            md.append(clean_msg)
            return "\n".join(md)

        md.append(table_header)
        md.append("|---|---|---|---|---|---|---|")

        for idx, f in enumerate(report.findings, start=1):
            loc = f"`{f.file_path}`"
            if f.line_number:
                loc += f":{f.line_number}"
            sev_str = f.severity.value if hasattr(f.severity, "value") else str(f.severity)
            conf_str = f.confidence.value if hasattr(f.confidence, "value") else str(f.confidence)
            md.append(f"| {idx} | {f.finding_type} | {f.category} | **{sev_str}** | {conf_str} | {loc} | {f.title} |")

        md.append("")
        md.append(detailed_heading)
        for idx, f in enumerate(report.findings, start=1):
            sev_str = f.severity.value if hasattr(f.severity, "value") else str(f.severity)
            conf_str = f.confidence.value if hasattr(f.confidence, "value") else str(f.confidence)
            md.append(f"#### {idx}. [{sev_str}] {f.title}")
            md.append(f"- **{lbl_category}:** {f.category}")
            md.append(f"- **{lbl_conf}:** {conf_str}")
            md.append(f"- **{lbl_file}:** `{f.file_path}` ({lbl_line}: {f.line_number or 'N/A'})")
            if f.snippet:
                md.append(f"- **{lbl_code}:** `{f.snippet}`")
            md.append(f"- **{lbl_desc}:** {f.description}")
            ml_meta = (f.metadata or {}).get("ml_triage") if f.metadata else None
            if isinstance(ml_meta, dict):
                md.append(f"- **ML Triage:** {_format_ml_triage_summary(ml_meta)}")

            # Localize remediation if possible
            remediation_text = f.remediation
            if f.finding_type == "secret" and "rule_id" in f.metadata:
                remediation_text = get_secret_remediation(f.metadata["rule_id"], lang=lang) or f.remediation
            elif f.finding_type == "dependency" and "cve" in f.metadata:
                remediation_text = get_dependency_remediation(
                    package_name=f.metadata.get("package", ""),
                    cve_id=f.metadata.get("cve", ""),
                    fixed_version=f.metadata.get("fixed_version"),
                    manifest_file=None,
                    lang=lang
                ) or f.remediation

            if remediation_text:
                md.append(f"- **{lbl_remed}:** {remediation_text}")
            md.append("")

        return "\n".join(md)

    @staticmethod
    def to_sarif(report: ScanReport) -> str:
        """Formats report as OASIS SARIF v2.1.0 JSON for GitHub Code Scanning / Security tab integration."""
        from sidik import __version__ as SIDIK_VERSION

        rules_map: Dict[str, Dict[str, Any]] = {}
        results_list = []

        base_dir = report.summary.target_path
        if os.path.isfile(base_dir):
            base_dir = os.path.dirname(base_dir)

        sev_to_sarif = {
            "CRITICAL": ("error", "9.5"),
            "HIGH": ("error", "8.0"),
            "MEDIUM": ("warning", "5.5"),
            "LOW": ("note", "3.0"),
            "INFO": ("note", "1.0"),
        }

        for f in report.findings:
            sev_val = (f.severity.value if hasattr(f.severity, "value") else str(f.severity)).upper()
            sarif_level, sec_score = sev_to_sarif.get(sev_val, ("warning", "5.0"))

            if f.finding_type == "secret":
                rule_id = f"SIDIK-{f.metadata.get('rule_id', f.category)}"
            else:
                cve = f.metadata.get("cve") or f.metadata.get("advisory_id") or f.category
                rule_id = f"SIDIK-SCA-{cve}"

            if rule_id not in rules_map:
                rules_map[rule_id] = {
                    "id": rule_id,
                    "name": f.category,
                    "shortDescription": {"text": f.title},
                    "fullDescription": {"text": f.description or f.title},
                    "help": {
                        "text": f.remediation or f.description or f.title,
                        "markdown": f"**Remediation:** {f.remediation or 'Review and remediate finding.'}"
                    },
                    "defaultConfiguration": {"level": sarif_level},
                    "properties": {
                        "tags": ["security", f.finding_type, f.category.lower()],
                        "security-severity": sec_score,
                        "precision": "high"
                    }
                }

            try:
                rel_uri = os.path.relpath(f.file_path, base_dir).replace("\\", "/")
                if rel_uri.startswith(".."):
                    rel_uri = os.path.basename(f.file_path)
            except Exception:
                rel_uri = f.file_path.replace("\\", "/")

            line_no = max(1, int(f.line_number or 1))
            msg_text = f"{f.title}: {f.description}"
            if f.remediation:
                msg_text += f" | Fix: {f.remediation}"

            sarif_result: Dict[str, Any] = {
                "ruleId": rule_id,
                "level": sarif_level,
                "message": {"text": msg_text},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": rel_uri,
                                "uriBaseId": "%SRCROOT%"
                            },
                            "region": {
                                "startLine": line_no,
                                "snippet": {"text": f.snippet or ""}
                            }
                        }
                    }
                ]
            }
            ml_meta = (f.metadata or {}).get("ml_triage") if f.metadata else None
            if isinstance(ml_meta, dict):
                sarif_result["properties"] = {"ml_triage": ml_meta}
            results_list.append(sarif_result)

        sarif_doc = {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "SIDIK",
                            "fullName": "SIDIK: Secret Identification and Dependency Inspection Kit",
                            "version": SIDIK_VERSION,
                            "informationUri": "https://github.com/radityobw/SIDIK",
                            "rules": list(rules_map.values())
                        }
                    },
                    "results": results_list
                }
            ]
        }
        return json.dumps(sarif_doc, indent=2)

    @staticmethod
    def to_github_annotations(report: ScanReport, lang: str = "id") -> str:
        """Formats findings as GitHub Actions workflow commands (::error / ::warning) for inline PR annotations."""
        from sidik import __version__ as SIDIK_VERSION
        from sidik.i18n import get_secret_remediation, get_dependency_remediation
        base_dir = report.summary.target_path
        if os.path.isfile(base_dir):
            base_dir = os.path.dirname(base_dir)

        out_lines = []
        for f in report.findings:
            sev_val = (f.severity.value if hasattr(f.severity, "value") else str(f.severity)).upper()
            cmd = "error" if sev_val in ("CRITICAL", "HIGH") else ("warning" if sev_val == "MEDIUM" else "notice")
            try:
                rel_file = os.path.relpath(f.file_path, base_dir).replace("\\", "/")
                if rel_file.startswith(".."):
                    rel_file = f.file_path.replace("\\", "/")
            except Exception:
                rel_file = f.file_path.replace("\\", "/")

            line_no = max(1, int(f.line_number or 1))
            rem = f.remediation or ""
            if f.finding_type == "secret" and "rule_id" in f.metadata:
                rem = get_secret_remediation(f.metadata["rule_id"], lang=lang) or rem
            elif f.finding_type == "dependency" and "cve" in f.metadata:
                rem = get_dependency_remediation(
                    package_name=f.metadata.get("package", ""),
                    cve_id=f.metadata.get("cve", ""),
                    fixed_version=f.metadata.get("fixed_version"),
                    manifest_file=os.path.basename(f.file_path) if f.file_path else None,
                    lang=lang
                ) or rem

            title = f"SIDIK [{sev_val}] {f.title}".replace(",", ";").replace(":", " -")
            msg = f"{f.description}"
            if rem:
                msg += f" | Fix: {rem}"
            msg = msg.replace("\r", " ").replace("\n", " ")
            out_lines.append(f"::{cmd} file={rel_file},line={line_no},title={title}::{msg}")

        if not out_lines:
            out_lines.append("::notice title=SIDIK Security Scan::Clean! Zero hardcoded secrets or vulnerable dependencies detected.")
        return "\n".join(out_lines)

    @staticmethod
    def to_console_summary(report: ScanReport, lang: str = "en", use_color: Optional[bool] = None) -> str:
        """Renders modern, information-dense CLI output with ANSI styling and actionable remediation blocks."""
        from sidik import __version__ as SIDIK_VERSION
        from sidik.i18n import get_secret_remediation, get_dependency_remediation
        s = report.summary
        is_id = (lang.lower() == "id")
        is_ml = _detect_ml_edition(report)

        # Auto-detect color support
        if use_color is None:
            no_color = bool(os.environ.get("NO_COLOR") or os.environ.get("TERM") == "dumb")
            use_color = sys.stdout.isatty() and not no_color

        # ANSI Color Palette
        if use_color:
            C_RESET = "\033[0m"
            C_BOLD = "\033[1m"
            C_DIM = "\033[2m"
            C_RED = "\033[91m"
            C_YELLOW = "\033[93m"
            C_BLUE = "\033[94m"
            C_GREEN = "\033[92m"
            C_CYAN = "\033[96m"
            C_PURPLE = "\033[95m"
            C_WHITE = "\033[97m"
        else:
            C_RESET = C_BOLD = C_DIM = C_RED = C_YELLOW = C_BLUE = C_GREEN = C_CYAN = C_PURPLE = C_WHITE = ""

        C_BORDER = C_YELLOW if is_ml else C_CYAN

        # Localized strings
        t_target = "Target:         " if not is_id else "Target:         "
        t_files = "Files Scanned:  " if not is_id else "Berkas Dipindai:"
        t_secrets = "Secrets:        " if not is_id else "Secrets:        "
        t_vulns = "Vulnerabilities:" if not is_id else "Kerentanan:     "
        t_dur = "Duration:       " if not is_id else "Durasi:         "
        t_mem = "Peak Memory:    " if not is_id else "Puncak Memori:  "
        t_sec_unit = "seconds" if not is_id else "detik"
        t_overview = "Findings Overview:" if not is_id else "Ikhtisar Temuan:"
        t_clean = "[OK] Clean! No security issues detected." if not is_id else "[OK] Bersih! Tidak ditemukan masalah keamanan."
        t_fix_lbl = "Fix / Remediation:" if not is_id else "Solusi / Remediasi:"

        # Severity breakdown tally
        crit_n = sum(1 for f in report.findings if (f.severity.value if hasattr(f.severity, "value") else str(f.severity)) == "CRITICAL")
        high_n = sum(1 for f in report.findings if (f.severity.value if hasattr(f.severity, "value") else str(f.severity)) == "HIGH")
        med_n = sum(1 for f in report.findings if (f.severity.value if hasattr(f.severity, "value") else str(f.severity)) == "MEDIUM")
        low_n = sum(1 for f in report.findings if (f.severity.value if hasattr(f.severity, "value") else str(f.severity)) == "LOW")

        base_dir = s.target_path
        if os.path.isfile(base_dir):
            base_dir = os.path.dirname(base_dir)

        border_w = 82
        header_title_line = (
            f"{C_BOLD}{C_YELLOW} [SIDIK-ML Hybrid Triage]{C_RESET} {C_BOLD}{C_WHITE}SIDIK: Secret Identification and Dependency Inspection Kit (Core v{SIDIK_VERSION}){C_RESET}"
            if is_ml
            else f"{C_BOLD}{C_WHITE} SIDIK: Secret Identification and Dependency Inspection Kit (v{SIDIK_VERSION}){C_RESET}"
        )
        lines = [
            f"{C_BORDER}{'=' * border_w}{C_RESET}",
            header_title_line,
            f"{C_BORDER}{'=' * border_w}{C_RESET}",
            f" {C_DIM}{t_target}{C_RESET} {C_WHITE}{s.target_path}{C_RESET}",
            f" {C_DIM}{t_files}{C_RESET} {s.total_files_scanned:<8} {C_DIM}{t_dur}{C_RESET} {s.scan_duration_seconds} {t_sec_unit}",
            f" {C_DIM}{t_secrets}{C_RESET} {s.total_secrets_found:<8} {C_DIM}{t_mem}{C_RESET} {s.peak_memory_mb} MB",
            f" {C_DIM}{t_vulns}{C_RESET} {s.total_vulnerabilities_found}",
            f"{C_DIM}{'-' * border_w}{C_RESET}",
            f" {C_BOLD}Status Severity:{C_RESET} "
            f"{C_RED}[CRITICAL: {crit_n}]{C_RESET} "
            f"{C_YELLOW}[HIGH: {high_n}]{C_RESET} "
            f"{C_BLUE}[MEDIUM: {med_n}]{C_RESET} "
            f"{C_GREEN}[LOW: {low_n}]{C_RESET}",
            f"{C_DIM}{'-' * border_w}{C_RESET}"
        ]

        if report.findings:
            lines.append(f" {C_BOLD}{t_overview}{C_RESET}")
            for idx, f in enumerate(report.findings, start=1):
                sev_val = f.severity.value if hasattr(f.severity, "value") else str(f.severity)
                if sev_val == "CRITICAL":
                    c_sev = f"{C_BOLD}{C_RED}[CRITICAL]{C_RESET}"
                elif sev_val == "HIGH":
                    c_sev = f"{C_BOLD}{C_YELLOW}[HIGH    ]{C_RESET}"
                elif sev_val == "MEDIUM":
                    c_sev = f"{C_BOLD}{C_BLUE}[MEDIUM  ]{C_RESET}"
                else:
                    c_sev = f"{C_BOLD}{C_GREEN}[LOW     ]{C_RESET}"

                try:
                    rel_path = os.path.relpath(f.file_path, base_dir)
                    if rel_path.startswith(".."):
                        rel_path = os.path.basename(f.file_path)
                except Exception:
                    rel_path = f.file_path
                loc = f"{rel_path}:{f.line_number}" if f.line_number else rel_path
                lines.append(f" [{idx:02d}] {c_sev} [{f.category:16s}] {f.title} -> {C_WHITE}{loc}{C_RESET}")

                if f.snippet:
                    clean_snip = f.snippet.strip().replace("\n", " ")
                    if len(clean_snip) > 95:
                        clean_snip = clean_snip[:92] + "..."
                    lines.append(f"      {C_DIM}Code:{C_RESET} `{clean_snip}`")

                ml_meta = (f.metadata or {}).get("ml_triage") if f.metadata else None
                if isinstance(ml_meta, dict):
                    lines.append(f"      {C_DIM}ML Triage:{C_RESET} {_format_ml_triage_summary(ml_meta)}")

                rem_text = f.remediation
                if f.finding_type == "secret" and "rule_id" in f.metadata:
                    rem_text = get_secret_remediation(f.metadata["rule_id"], lang=lang) or rem_text
                elif f.finding_type == "dependency" and "cve" in f.metadata:
                    rem_text = get_dependency_remediation(
                        package_name=f.metadata.get("package", ""),
                        cve_id=f.metadata.get("cve", ""),
                        fixed_version=f.metadata.get("fixed_version"),
                        manifest_file=os.path.basename(f.file_path) if f.file_path else None,
                        lang=lang
                    ) or rem_text

                if rem_text:
                    lines.append(f"      {C_CYAN}{t_fix_lbl}{C_RESET} {rem_text}")
        else:
            lines.append(f" {C_GREEN}{t_clean}{C_RESET}")

        lines.append(f"{C_BORDER}{'=' * border_w}{C_RESET}")
        return "\n".join(lines)

    @staticmethod
    def to_html(report: ScanReport, lang: str = "en") -> str:
        """Formats scan report into a self-contained, interactive HTML security assessment dashboard."""
        from sidik import __version__ as SIDIK_VERSION
        from sidik.i18n import get_secret_remediation, get_dependency_remediation
        s = report.summary
        is_id = (lang.lower() == "id")
        is_ml = _detect_ml_edition(report)

        if is_ml:
            theme_primary = "#ea580c"
            theme_glow = "#f59e0b"
            theme_accent = "#fbbf24"
            theme_header_bg = "linear-gradient(180deg, #271a0c 0%, var(--card-bg) 100%)"
            theme_logo_shadow = "rgba(245, 158, 11, 0.55)"
            theme_badge_grad = "linear-gradient(135deg, #ea580c 0%, #fbbf24 100%)"
            edition_pill = "<span class=\"edition-badge\">NON-ANN ML TRIAGE</span>"
            edition_label = f"SIDIK-ML Hybrid (Core v{html.escape(SIDIK_VERSION)})"
        else:
            theme_primary = "#0284c7"
            theme_glow = "#38bdf8"
            theme_accent = "#38bdf8"
            theme_header_bg = "linear-gradient(180deg, #131c31 0%, var(--card-bg) 100%)"
            theme_logo_shadow = "rgba(56, 189, 248, 0.5)"
            theme_badge_grad = "linear-gradient(135deg, #0284c7 0%, #38bdf8 100%)"
            edition_pill = "<span class=\"edition-badge edition-core\">DETERMINISTIC CORE</span>"
            edition_label = f"Core v{html.escape(SIDIK_VERSION)}"

        # Resolve official SIDIK logo as base64 data URI (prefer bundled sidik.assets over repo-local logo/)
        logo_bytes: Optional[bytes] = None
        try:
            res = resources.files("sidik.assets").joinpath("SIDIK-nobg-purelogo-dark.png")
            if res.is_file():
                logo_bytes = res.read_bytes()
        except Exception:
            logo_bytes = None
        if logo_bytes is None:
            base_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
            logo_path = os.path.join(base_dir, "logo", "SIDIK-nobg-purelogo-dark.png")
            if os.path.exists(logo_path):
                try:
                    with open(logo_path, "rb") as lf:
                        logo_bytes = lf.read()
                except Exception:
                    logo_bytes = None

        logo_data_uri = f"data:image/png;base64,{base64.b64encode(logo_bytes).decode('ascii')}" if logo_bytes else ""

        if logo_data_uri:
            logo_html = f'<img src="{logo_data_uri}" alt="SIDIK Logo" class="header-logo-img">'
            favicon_html = f'<link rel="icon" type="image/png" href="{logo_data_uri}">'
        else:
            logo_html = '<div class="logo-badge">🛡️</div>'
            favicon_html = ''

        # Counts
        total_findings = len(report.findings)
        crit_n = sum(1 for f in report.findings if (f.severity.value if hasattr(f.severity, "value") else str(f.severity)) == "CRITICAL")
        high_n = sum(1 for f in report.findings if (f.severity.value if hasattr(f.severity, "value") else str(f.severity)) == "HIGH")
        med_n = sum(1 for f in report.findings if (f.severity.value if hasattr(f.severity, "value") else str(f.severity)) == "MEDIUM")
        low_n = sum(1 for f in report.findings if (f.severity.value if hasattr(f.severity, "value") else str(f.severity)) == "LOW")

        # Translations
        if is_ml:
            t_page_title = "Dasbor Hybrid Keamanan SIDIK-ML" if is_id else "SIDIK-ML Hybrid Security Dashboard"
        else:
            t_page_title = "Dasbor Laporan Analisis Keamanan SIDIK" if is_id else "SIDIK Security Assessment Dashboard"
        t_subtitle = "Secret Identification and Dependency Inspection Kit"
        t_target_path = "Path Target" if is_id else "Target Path"
        t_timestamp = "Waktu Pemindaian" if is_id else "Scan Timestamp"
        t_duration = "Durasi" if is_id else "Duration"
        t_memory = "Puncak Memori" if is_id else "Peak Memory"
        t_files_scanned = "Berkas Dipindai" if is_id else "Files Scanned"
        t_total_findings = "Total Temuan" if is_id else "Total Findings"
        t_secrets_count = "Secrets" if is_id else "Secrets"
        t_deps_count = "Kerentanan Dependensi" if is_id else "Vulnerabilities"

        t_search_ph = "Cari temuan (rule, file, CVE, kata kunci)..." if is_id else "Search findings (rule, file, CVE, keyword)..."
        t_all_sev = "Semua Tingkat" if is_id else "All Severities"
        t_all_types = "Semua Tipe" if is_id else "All Types"
        t_type_sec = "Kredensial / Secret" if is_id else "Secret"
        t_type_dep = "Dependensi Rentan" if is_id else "Dependency"
        t_print_btn = "🖨️ Cetak / Ekspor PDF" if is_id else "🖨️ Print / Save as PDF"
        t_copy_code = "Salin Kode" if is_id else "Copy Code"
        t_copy_rem = "Salin Solusi" if is_id else "Copy Fix"

        t_col_num = "#"
        t_col_id = "ID Temuan" if is_id else "Finding ID"
        t_col_type = "Tipe" if is_id else "Type"
        t_col_category = "Kategori" if is_id else "Category"
        t_col_severity = "Tingkat Bahaya" if is_id else "Severity"
        t_col_conf = "Confidence" if is_id else "Confidence"
        t_col_location = "Lokasi Berkas" if is_id else "Location"
        t_col_detail = "Judul & Deskripsi" if is_id else "Title & Description"
        t_col_action = "Aksi" if is_id else "Action"

        t_remediation_hdr = "Rekomendasi Perbaikan & Remediasi" if is_id else "Remediation & Action Plan"
        t_code_hdr = "Potongan Kode / Versi Terdeteksi" if is_id else "Code Snippet / Detected Version"
        t_meta_hdr = "Metadata Teknis" if is_id else "Technical Metadata"
        t_clean_msg = (
            "Bersih! Tidak ditemukan kebocoran kredensial atau dependensi rentan."
            if is_id
            else "Clean! No hardcoded secrets or vulnerable dependencies detected."
        )

        # Findings rows generator
        rows_html = []
        for idx, f in enumerate(report.findings, start=1):
            sev_str = f.severity.value if hasattr(f.severity, "value") else str(f.severity)
            conf_str = f.confidence.value if hasattr(f.confidence, "value") else str(f.confidence)

            # Localize remediation
            remediation_text = f.remediation
            if f.finding_type == "secret" and "rule_id" in f.metadata:
                remediation_text = get_secret_remediation(f.metadata["rule_id"], lang=lang) or f.remediation
            elif f.finding_type == "dependency" and "cve" in f.metadata:
                remediation_text = get_dependency_remediation(
                    package_name=f.metadata.get("package", ""),
                    cve_id=f.metadata.get("cve", ""),
                    fixed_version=f.metadata.get("fixed_version"),
                    manifest_file=None,
                    lang=lang
                ) or f.remediation

            loc_str = f.file_path
            loc_display = os.path.basename(f.file_path)
            if f.line_number:
                loc_str += f":{f.line_number}"
                loc_display += f":{f.line_number}"

            # Metadata items
            meta_chips = []
            for mk, mv in (f.metadata or {}).items():
                if mk in ["snippet", "full_match"] or not mv:
                    continue
                if mk == "ml_triage" and isinstance(mv, dict):
                    prob_val = f"{float(mv.get('secret_probability', 0.0)):.2f}"
                    meta_chips.append(f"<span class='meta-tag'><strong>ML Action:</strong> {html.escape(str(mv.get('action', 'KEEP_ALERT')))}</span>")
                    meta_chips.append(f"<span class='meta-tag'><strong>ML Probability:</strong> {html.escape(prob_val)}</span>")
                    meta_chips.append(f"<span class='meta-tag'><strong>ML Model:</strong> {html.escape(str(mv.get('model_name', 'N/A')))}</span>")
                    top_f = mv.get("top_feature_contributions")
                    if isinstance(top_f, dict) and top_f:
                        top_txt = ", ".join(
                            f"{k}={float(v):.3f}" if isinstance(v, (int, float)) else f"{k}={v}"
                            for k, v in list(top_f.items())[:3]
                        )
                        meta_chips.append(f"<span class='meta-tag'><strong>ML Top Features:</strong> {html.escape(top_txt)}</span>")
                else:
                    meta_chips.append(f"<span class='meta-tag'><strong>{html.escape(str(mk))}:</strong> {html.escape(str(mv))}</span>")
            meta_html = "".join(meta_chips) if meta_chips else "<span class='text-muted'>-</span>"

            if f.snippet:
                raw_snip_js = html.escape(json.dumps(f.snippet))
                snippet_html = (
                    f"<div class='detail-actions'>"
                    f"<button type='button' class='btn-copy' onclick='event.stopPropagation(); copyToClipboard(this, {raw_snip_js})'>{t_copy_code}</button>"
                    f"</div>"
                    f"<pre class='code-block'><code>{html.escape(f.snippet)}</code></pre>"
                )
            else:
                snippet_html = "<span class='text-muted'>Tidak ada potongan kode.</span>"

            rem_body = remediation_text or "Ikuti panduan rotasi rahasia atau perbarui paket."
            raw_rem_js = html.escape(json.dumps(rem_body))
            remed_html = (
                f"<div class='remediation-box'>"
                f"<div class='rem-hdr'><strong>🛡️ {t_remediation_hdr}:</strong>"
                f"<button type='button' class='btn-copy' onclick='event.stopPropagation(); copyToClipboard(this, {raw_rem_js})'>{t_copy_rem}</button>"
                f"</div>"
                f"<p>{html.escape(rem_body)}</p>"
                f"</div>"
            )

            row = f"""
            <tr class="finding-row" data-id="{html.escape(f.id)}" data-type="{html.escape(f.finding_type)}" data-severity="{html.escape(sev_str)}" onclick="toggleDetail('detail-{idx}')">
                <td class="text-center font-mono">{idx}</td>
                <td class="font-mono text-cyan"><strong>{html.escape(f.id)}</strong></td>
                <td class="text-center"><span class="badge badge-{html.escape(f.finding_type)}">{html.escape(f.finding_type.upper())}</span></td>
                <td><span class="category-chip">{html.escape(f.category)}</span></td>
                <td class="text-center"><span class="badge badge-{html.escape(sev_str.lower())}">{html.escape(sev_str)}</span></td>
                <td class="text-center"><span class="conf-badge">{html.escape(conf_str)}</span></td>
                <td title="{html.escape(loc_str)}"><span class="font-mono text-muted">{html.escape(loc_display)}</span></td>
                <td>
                    <div class="finding-title">{html.escape(f.title)}</div>
                    <div class="finding-desc text-muted">{html.escape(f.description)}</div>
                </td>
                <td class="text-center">
                    <button type="button" class="btn-toggle" onclick="event.stopPropagation(); toggleDetail('detail-{idx}')">▼</button>
                </td>
            </tr>
            <tr id="detail-{idx}" class="detail-row" style="display:none;">
                <td colspan="9">
                    <div class="detail-card">
                        <div class="detail-section">
                            <h4>{t_code_hdr}</h4>
                            {snippet_html}
                        </div>
                        <div class="detail-section">
                            {remed_html}
                        </div>
                        <div class="detail-section">
                            <h4>{t_meta_hdr}</h4>
                            <div class="meta-container">{meta_html}</div>
                        </div>
                        <div class="detail-footer">
                            <span class="text-muted font-mono">Full Path: {html.escape(loc_str)}</span>
                        </div>
                    </div>
                </td>
            </tr>
            """
            rows_html.append(row)

        tbody_content = "\n".join(rows_html) if rows_html else f"<tr><td colspan='9' class='text-center p-8 text-green font-bold'>{t_clean_msg}</td></tr>"

        html_template = f"""<!DOCTYPE html>
<html lang="{html.escape(lang)}">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{html.escape(t_page_title)}</title>
    {favicon_html}
    <style>
        :root {{
            --bg: #090d16;
            --card-bg: #111827;
            --card-border: #1f293d;
            --card-hover: #1e293b;
            --fg: #f3f4f6;
            --fg-muted: #94a3b8;
            --primary: {theme_primary};
            --primary-glow: {theme_glow};
            --cyan: {theme_accent};
            --danger: #ef4444;
            --danger-bg: rgba(239, 68, 68, 0.15);
            --warning: #f97316;
            --warning-bg: rgba(249, 115, 22, 0.15);
            --medium: #eab308;
            --medium-bg: rgba(234, 179, 8, 0.15);
            --success: #10b981;
            --success-bg: rgba(16, 185, 129, 0.15);
            --code-bg: #030712;
        }}
        * {{ box-sizing: border-box; margin: 0; padding: 0; }}
        body {{
            background-color: var(--bg);
            color: var(--fg);
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            font-size: 14px;
            line-height: 1.5;
            padding: 24px;
        }}
        .container {{ max-width: 1400px; margin: 0 auto; }}
        .header {{
            background: {theme_header_bg};
            border: 1px solid var(--card-border);
            border-radius: 12px;
            padding: 24px 28px;
            margin-bottom: 20px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            box-shadow: 0 4px 20px rgba(0, 0, 0, 0.35);
        }}
        .header-title {{ display: flex; align-items: center; gap: 16px; }}
        .header-title .header-logo-img {{
            width: 50px;
            height: 50px;
            object-fit: contain;
            filter: drop-shadow(0 0 12px {theme_logo_shadow});
            border-radius: 8px;
            display: block;
        }}
        .header-title .logo-badge {{
            background: {theme_badge_grad};
            color: #ffffff;
            font-size: 24px;
            width: 48px;
            height: 48px;
            display: flex;
            align-items: center;
            justify-content: center;
            border-radius: 10px;
            box-shadow: 0 0 15px {theme_logo_shadow};
        }}
        .edition-badge {{
            display: inline-block;
            margin-left: 10px;
            padding: 2px 9px;
            border-radius: 999px;
            font-size: 11px;
            font-weight: 700;
            letter-spacing: 0.4px;
            vertical-align: middle;
            background: #f59e0b;
            color: #0a0d12;
        }}
        .edition-badge.edition-core {{
            background: #0369a1;
            color: #e0f2fe;
        }}
        .header-title h1 {{ font-size: 22px; font-weight: 700; color: #ffffff; letter-spacing: -0.5px; }}
        .header-title p {{ font-size: 13px; color: var(--fg-muted); margin-top: 2px; }}
        .header-actions {{ display: flex; align-items: center; gap: 12px; }}
        .btn {{
            background: var(--card-hover);
            color: var(--fg);
            border: 1px solid var(--card-border);
            padding: 8px 16px;
            border-radius: 8px;
            cursor: pointer;
            font-size: 13px;
            font-weight: 600;
            transition: all 0.2s;
            display: inline-flex;
            align-items: center;
            gap: 6px;
        }}
        .btn:hover {{ background: #334155; border-color: var(--primary-glow); color: #fff; }}
        .metrics-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
            gap: 16px;
            margin-bottom: 24px;
        }}
        .metric-card {{
            background: var(--card-bg);
            border: 1px solid var(--card-border);
            border-radius: 10px;
            padding: 16px 20px;
            position: relative;
            overflow: hidden;
            box-shadow: 0 2px 8px rgba(0, 0, 0, 0.2);
        }}
        .metric-card::before {{
            content: '';
            position: absolute;
            top: 0; left: 0; right: 0; height: 3px;
            background: var(--primary-glow);
        }}
        .metric-card.card-crit::before {{ background: var(--danger); }}
        .metric-card.card-high::before {{ background: var(--warning); }}
        .metric-card.card-med::before {{ background: var(--medium); }}
        .metric-card.card-low::before {{ background: var(--success); }}
        .metric-lbl {{ font-size: 12px; font-weight: 600; color: var(--fg-muted); text-transform: uppercase; letter-spacing: 0.5px; }}
        .metric-val {{ font-size: 28px; font-weight: 800; color: #ffffff; margin-top: 6px; font-family: monospace; }}
        .metric-sub {{ font-size: 11px; color: var(--fg-muted); margin-top: 4px; }}

        .meta-strip {{
            background: var(--card-bg);
            border: 1px solid var(--card-border);
            border-radius: 8px;
            padding: 12px 20px;
            margin-bottom: 20px;
            display: flex;
            flex-wrap: wrap;
            gap: 24px;
            font-size: 13px;
        }}
        .meta-strip-item {{ display: flex; align-items: center; gap: 8px; }}
        .meta-strip-item strong {{ color: var(--fg-muted); }}

        .filter-toolbar {{
            background: var(--card-bg);
            border: 1px solid var(--card-border);
            border-radius: 10px;
            padding: 14px 18px;
            margin-bottom: 20px;
            display: flex;
            flex-wrap: wrap;
            align-items: center;
            justify-content: space-between;
            gap: 12px;
        }}
        .search-box {{
            flex: 1;
            min-width: 280px;
            position: relative;
        }}
        .search-input {{
            width: 100%;
            background: #030712;
            border: 1px solid var(--card-border);
            color: #ffffff;
            padding: 8px 14px;
            border-radius: 6px;
            font-size: 13px;
            outline: none;
            transition: border-color 0.2s;
        }}
        .search-input:focus {{ border-color: var(--primary-glow); }}
        .filter-group {{ display: flex; align-items: center; gap: 6px; flex-wrap: wrap; }}
        .pill-filter {{
            background: #1e293b;
            color: var(--fg-muted);
            border: 1px solid transparent;
            padding: 5px 12px;
            border-radius: 20px;
            font-size: 12px;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.2s;
        }}
        .pill-filter:hover {{ color: #ffffff; background: #334155; }}
        .pill-filter.active {{ background: var(--primary); color: #ffffff; }}

        .table-card {{
            background: var(--card-bg);
            border: 1px solid var(--card-border);
            border-radius: 10px;
            overflow: hidden;
            box-shadow: 0 4px 12px rgba(0, 0, 0, 0.25);
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            text-align: left;
        }}
        th {{
            background: #151e30;
            color: var(--cyan);
            font-size: 12px;
            font-weight: 700;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            padding: 12px 14px;
            border-bottom: 1px solid var(--card-border);
        }}
        td {{
            padding: 12px 14px;
            border-bottom: 1px solid #1a2336;
            vertical-align: middle;
        }}
        .finding-row {{ cursor: pointer; transition: background-color 0.15s; }}
        .finding-row:hover {{ background-color: rgba(56, 189, 248, 0.05); }}
        .finding-title {{ font-weight: 600; color: #ffffff; font-size: 13px; }}
        .finding-desc {{ font-size: 12px; margin-top: 2px; }}

        .badge {{
            display: inline-block;
            padding: 3px 8px;
            border-radius: 4px;
            font-size: 11px;
            font-weight: 700;
            text-align: center;
        }}
        .badge-critical {{ background: var(--danger-bg); color: #f87171; border: 1px solid rgba(239, 68, 68, 0.3); }}
        .badge-high {{ background: var(--warning-bg); color: #fb923c; border: 1px solid rgba(249, 115, 22, 0.3); }}
        .badge-medium {{ background: var(--medium-bg); color: #facc15; border: 1px solid rgba(234, 179, 8, 0.3); }}
        .badge-low {{ background: var(--success-bg); color: #4ade80; border: 1px solid rgba(16, 185, 129, 0.3); }}
        .badge-secret {{ background: rgba(56, 189, 248, 0.15); color: #38bdf8; border: 1px solid rgba(56, 189, 248, 0.3); }}
        .badge-dependency {{ background: rgba(168, 85, 247, 0.15); color: #c084fc; border: 1px solid rgba(168, 85, 247, 0.3); }}
        .category-chip {{ background: #1e293b; color: #cbd5e1; padding: 2px 7px; border-radius: 4px; font-size: 11px; font-family: monospace; }}
        .conf-badge {{ font-size: 11px; color: var(--fg-muted); font-weight: 600; }}

        .btn-toggle {{
            background: transparent;
            border: 1px solid #334155;
            color: var(--fg-muted);
            border-radius: 4px;
            padding: 2px 6px;
            cursor: pointer;
            font-size: 10px;
        }}
        .btn-toggle:hover {{ background: #334155; color: #ffffff; }}

        .detail-row {{ background: #0c1220; }}
        .detail-card {{
            padding: 16px 20px;
            border-left: 3px solid var(--primary-glow);
            margin: 6px 0;
            display: flex;
            flex-direction: column;
            gap: 14px;
        }}
        .detail-section h4 {{ font-size: 12px; font-weight: 700; color: var(--cyan); margin-bottom: 6px; text-transform: uppercase; letter-spacing: 0.5px; }}
        .code-block {{
            background: var(--code-bg);
            border: 1px solid #1e293b;
            border-radius: 6px;
            padding: 10px 14px;
            overflow-x: auto;
            color: #38bdf8;
            font-family: Consolas, Monaco, "Courier New", monospace;
            font-size: 12px;
        }}
        .remediation-box {{
            background: rgba(16, 185, 129, 0.08);
            border: 1px solid rgba(16, 185, 129, 0.25);
            border-radius: 6px;
            padding: 12px 16px;
            color: #d1fae5;
        }}
        .remediation-box strong {{ color: #34d399; font-size: 13px; display: block; margin-bottom: 4px; }}
        .rem-hdr {{ display: flex; justify-content: space-between; align-items: center; margin-bottom: 6px; }}
        .detail-actions {{ display: flex; justify-content: flex-end; margin-bottom: 6px; }}
        .btn-copy {{
            background: #1e293b;
            border: 1px solid #334155;
            color: #cbd5e1;
            border-radius: 5px;
            padding: 3px 8px;
            font-size: 11px;
            cursor: pointer;
        }}
        .btn-copy:hover {{ background: #334155; color: #ffffff; }}
        .meta-container {{ display: flex; flex-wrap: wrap; gap: 8px; }}
        .meta-tag {{ background: #1e293b; border: 1px solid #334155; padding: 3px 8px; border-radius: 4px; font-size: 11px; }}
        .meta-tag strong {{ color: var(--cyan); }}
        .detail-footer {{ border-top: 1px solid #1e293b; padding-top: 8px; font-size: 11px; }}

        .font-mono {{ font-family: Consolas, Monaco, "Courier New", monospace; }}
        .text-center {{ text-align: center; }}
        .text-cyan {{ color: var(--cyan); }}
        .text-green {{ color: var(--success); }}
        .text-muted {{ color: var(--fg-muted); }}
        .p-8 {{ padding: 32px; }}
        .font-bold {{ font-weight: 700; }}

        @media print {{
            body {{ background: #fff; color: #000; padding: 10px; }}
            .header, .metrics-grid, .meta-strip, .table-card {{ border: 1px solid #ccc; background: #fff; color: #000; box-shadow: none; }}
            .header-actions, .filter-toolbar, .btn-toggle {{ display: none; }}
            .code-block {{ background: #f4f4f4; color: #111; border: 1px solid #ddd; }}
            .remediation-box {{ background: #f0fdf4; color: #065f46; border: 1px solid #bbf7d0; }}
            th {{ background: #eee; color: #111; }}
            td {{ border-bottom: 1px solid #ddd; }}
            .detail-row {{ display: table-row !important; }}
        }}
    </style>
</head>
<body>
<div class="container">
    <!-- Header -->
    <header class="header">
        <div class="header-title">
            {logo_html}
            <div>
                <h1>{html.escape(t_page_title)} {edition_pill}</h1>
                <p>{html.escape(t_subtitle)} &bull; {edition_label}</p>
            </div>
        </div>
        <div class="header-actions">
            <button class="btn" onclick="window.print()">{t_print_btn}</button>
        </div>
    </header>

    <!-- Scan Metadata -->
    <div class="meta-strip">
        <div class="meta-strip-item"><strong>{t_target_path}:</strong> <code>{html.escape(s.target_path)}</code></div>
        <div class="meta-strip-item"><strong>{t_timestamp}:</strong> <span>{html.escape(s.timestamp)}</span></div>
        <div class="meta-strip-item"><strong>{t_duration}:</strong> <span>{s.scan_duration_seconds}s</span></div>
        <div class="meta-strip-item"><strong>{t_memory}:</strong> <span>{s.peak_memory_mb} MB</span></div>
    </div>

    <!-- Summary Metric Cards -->
    <div class="metrics-grid">
        <div class="metric-card">
            <div class="metric-lbl">{t_files_scanned}</div>
            <div class="metric-val">{s.total_files_scanned}</div>
            <div class="metric-sub">{s.scan_duration_seconds}s execution</div>
        </div>
        <div class="metric-card">
            <div class="metric-lbl">{t_total_findings}</div>
            <div class="metric-val">{total_findings}</div>
            <div class="metric-sub">{s.total_secrets_found} {t_secrets_count} &bull; {s.total_vulnerabilities_found} {t_deps_count}</div>
        </div>
        <div class="metric-card card-crit">
            <div class="metric-lbl">CRITICAL</div>
            <div class="metric-val" style="color:#ef4444;">{crit_n}</div>
            <div class="metric-sub">Urgent remediation required</div>
        </div>
        <div class="metric-card card-high">
            <div class="metric-lbl">HIGH</div>
            <div class="metric-val" style="color:#f97316;">{high_n}</div>
            <div class="metric-sub">High severity security exposure</div>
        </div>
        <div class="metric-card card-med">
            <div class="metric-lbl">MEDIUM</div>
            <div class="metric-val" style="color:#eab308;">{med_n}</div>
            <div class="metric-sub">Standard defense-in-depth</div>
        </div>
        <div class="metric-card card-low">
            <div class="metric-lbl">LOW</div>
            <div class="metric-val" style="color:#10b981;">{low_n}</div>
            <div class="metric-sub">Low priority / informational</div>
        </div>
    </div>

    <!-- Interactive Filtering Toolbar -->
    <div class="filter-toolbar">
        <div class="search-box">
            <input type="text" id="searchInput" class="search-input" placeholder="{t_search_ph}" oninput="filterTable()">
        </div>
        <div class="filter-group">
            <button class="pill-filter active" data-filter="all" onclick="setSeverityFilter('all', this)">{t_all_sev}</button>
            <button class="pill-filter" data-filter="CRITICAL" onclick="setSeverityFilter('CRITICAL', this)">CRITICAL ({crit_n})</button>
            <button class="pill-filter" data-filter="HIGH" onclick="setSeverityFilter('HIGH', this)">HIGH ({high_n})</button>
            <button class="pill-filter" data-filter="MEDIUM" onclick="setSeverityFilter('MEDIUM', this)">MEDIUM ({med_n})</button>
            <button class="pill-filter" data-filter="LOW" onclick="setSeverityFilter('LOW', this)">LOW ({low_n})</button>
        </div>
        <div class="filter-group">
            <button class="pill-filter active" data-type="all" onclick="setTypeFilter('all', this)">{t_all_types}</button>
            <button class="pill-filter" data-type="secret" onclick="setTypeFilter('secret', this)">{t_type_sec} ({s.total_secrets_found})</button>
            <button class="pill-filter" data-type="dependency" onclick="setTypeFilter('dependency', this)">{t_type_dep} ({s.total_vulnerabilities_found})</button>
        </div>
    </div>

    <!-- Findings Table -->
    <div class="table-card">
        <table id="findingsTable">
            <thead>
                <tr>
                    <th style="width: 45px;" class="text-center">{t_col_num}</th>
                    <th style="width: 130px;">{t_col_id}</th>
                    <th style="width: 90px;" class="text-center">{t_col_type}</th>
                    <th style="width: 140px;">{t_col_category}</th>
                    <th style="width: 100px;" class="text-center">{t_col_severity}</th>
                    <th style="width: 90px;" class="text-center">{t_col_conf}</th>
                    <th style="width: 220px;">{t_col_location}</th>
                    <th>{t_col_detail}</th>
                    <th style="width: 50px;" class="text-center">{t_col_action}</th>
                </tr>
            </thead>
            <tbody>
                {tbody_content}
            </tbody>
        </table>
    </div>
</div>

<script>
    let activeSev = 'all';
    let activeType = 'all';

    function toggleDetail(id) {{
        const row = document.getElementById(id);
        if (row) {{
            row.style.display = (row.style.display === 'none' || row.style.display === '') ? 'table-row' : 'none';
        }}
    }}

    function setSeverityFilter(sev, btn) {{
        activeSev = sev;
        document.querySelectorAll('.filter-group button[data-filter]').forEach(b => b.classList.remove('active'));
        btn.classList.add('active');
        filterTable();
    }}

    function setTypeFilter(type, btn) {{
        activeType = type;
        document.querySelectorAll('.filter-group button[data-type]').forEach(b => b.classList.remove('active'));
        btn.classList.add('active');
        filterTable();
    }}

    function filterTable() {{
        const query = document.getElementById('searchInput').value.toLowerCase().trim();
        const rows = document.querySelectorAll('.finding-row');

        rows.forEach(row => {{
            const id = row.getAttribute('data-id').toLowerCase();
            const sev = row.getAttribute('data-severity');
            const type = row.getAttribute('data-type');
            const text = row.innerText.toLowerCase();
            const detailId = row.nextElementSibling ? row.nextElementSibling.id : '';
            const detailRow = detailId ? document.getElementById(detailId) : null;

            const matchesQuery = !query || text.includes(query) || id.includes(query);
            const matchesSev = (activeSev === 'all' || sev === activeSev);
            const matchesType = (activeType === 'all' || type === activeType);

            if (matchesQuery && matchesSev && matchesType) {{
                row.style.display = 'table-row';
            }} else {{
                row.style.display = 'none';
                if (detailRow && detailRow.classList.contains('detail-row')) {{
                    detailRow.style.display = 'none';
                }}
            }}
        }});
    }}
    function filterFindings() {{
        filterTable();
    }}

    function copyToClipboard(btn, text) {{
        if (!navigator.clipboard) {{
            const ta = document.createElement('textarea');
            ta.value = text;
            document.body.appendChild(ta);
            ta.select();
            document.execCommand('copy');
            document.body.removeChild(ta);
            showCopied(btn);
            return;
        }}
        navigator.clipboard.writeText(text).then(() => {{
            showCopied(btn);
        }}).catch(() => {{}});
    }}

    function showCopied(btn) {{
        const orig = btn.innerText;
        btn.innerText = '✓ Copied';
        setTimeout(() => {{ btn.innerText = orig; }}, 1500);
    }}
</script>
</body>
</html>
"""
        return html_template
