"""Core unified security scanner orchestrating secret detection and dependency analysis."""

import os
import time
import fnmatch
import tracemalloc
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple
from sidik.models import ScanReport, SecretCandidate
from sidik.plugins import apply_post_scan_plugins
from sidik.secret_detector.detector import SecretDetector
from sidik.dependency_analyzer.analyzer import DependencyAnalyzer, MANIFEST_FILENAMES
from sidik.dependency_analyzer.database import VulnerabilityDatabase
from sidik.reporting.aggregator import FindingAggregator


def load_sidikignore_patterns(base_dir: str) -> List[str]:
    """Loads ignore glob patterns from a .sidikignore file in base_dir, if present."""
    ignore_file = os.path.join(base_dir, ".sidikignore")
    patterns: List[str] = []
    if os.path.isfile(ignore_file):
        try:
            with open(ignore_file, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        patterns.append(line)
        except Exception:
            pass
    return patterns


def is_path_ignored(rel_path: str, patterns: List[str]) -> bool:
    """Checks whether a relative path matches any ignore pattern (gitignore-style)."""
    if not patterns:
        return False
    norm_rel = rel_path.replace("\\", "/").strip("/")
    parts = norm_rel.split("/")
    filename = parts[-1]

    for pat in patterns:
        pat = pat.replace("\\", "/").strip()
        if not pat:
            continue

        # Trailing slash indicates directory match (e.g., 'vendor/', 'tests/fixtures/')
        if pat.endswith("/"):
            dir_pat = pat.rstrip("/")
            if norm_rel == dir_pat or norm_rel.startswith(dir_pat + "/"):
                return True
            for i in range(len(parts)):
                sub = "/".join(parts[:i + 1])
                if fnmatch.fnmatch(sub, dir_pat) or fnmatch.fnmatch(parts[i], dir_pat):
                    return True
        else:
            if fnmatch.fnmatch(norm_rel, pat) or fnmatch.fnmatch(filename, pat):
                return True
            # Prefix or subdirectory match
            if norm_rel.startswith(pat + "/") or fnmatch.fnmatch(norm_rel, f"*/{pat}"):
                return True
            # Globstar match (e.g., tests/** or dataset/**)
            if "**" in pat:
                prefix = pat.split("**")[0].rstrip("/")
                if not prefix or norm_rel == prefix or norm_rel.startswith(prefix + "/"):
                    suffix = pat.split("**")[-1].lstrip("/")
                    if not suffix or fnmatch.fnmatch(norm_rel, f"*{suffix}") or fnmatch.fnmatch(filename, suffix):
                        return True
    return False


class SecurityScanner:
    """SIDIK (Secret Identification and Dependency Inspection Kit) core security analyzer."""

    DEFAULT_PRUNE_DIRS = {
        ".git", ".venv", "venv", "__pycache__", "node_modules",
        ".idea", ".vscode", ".pytest_cache", "dist", "build"
    }

    def __init__(
        self,
        enable_secret_scan: bool = True,
        enable_dependency_scan: bool = True,
        enable_context: bool = True,
        enable_entropy: bool = True,
        custom_vulnerability_db: Optional[str] = None,
        ignore_patterns: Optional[List[str]] = None,
        measure_memory: bool = False,
        secret_extensions: Optional[Tuple[str, ...]] = None,
        post_scan_plugins: Optional[Sequence[Any]] = None,
        plugin_options: Optional[Dict[str, Any]] = None,
    ):
        self.enable_secret_scan = enable_secret_scan
        self.enable_dependency_scan = enable_dependency_scan
        self.secret_detector = SecretDetector(enable_context=enable_context, enable_entropy=enable_entropy)
        db = VulnerabilityDatabase(custom_vulnerability_db) if custom_vulnerability_db else None
        self.dependency_analyzer = DependencyAnalyzer(db=db)
        self.custom_ignore_patterns = list(ignore_patterns) if ignore_patterns else []
        self.measure_memory = measure_memory
        self.secret_extensions = secret_extensions or (".py", ".env")
        self.post_scan_plugins = list(post_scan_plugins) if post_scan_plugins else []
        self.plugin_options = dict(plugin_options) if plugin_options else {}

    def _discover_candidate_files(self, target_path: str) -> List[Tuple[str, str, bool, bool]]:
        """Discovers target files for secret and/or dependency scanning honoring .sidikignore."""
        base_dir = target_path if os.path.isdir(target_path) else os.path.dirname(target_path)
        file_ignore_patterns = load_sidikignore_patterns(base_dir)
        all_ignore_patterns = list(self.custom_ignore_patterns) + file_ignore_patterns

        candidate_files: List[Tuple[str, str, bool, bool]] = []

        if os.path.isfile(target_path):
            filename = os.path.basename(target_path).lower()
            if not is_path_ignored(os.path.basename(target_path), all_ignore_patterns):
                is_sec = self.enable_secret_scan and filename.endswith(
                    (".py", ".env", ".cfg", ".ini", ".json", ".yaml", ".yml", ".txt")
                )
                is_dep = self.enable_dependency_scan and any(
                    filename == m.lower() or filename.endswith("requirements.txt") for m in MANIFEST_FILENAMES
                )
                if is_sec or is_dep:
                    candidate_files.append((target_path, os.path.basename(target_path), is_sec, is_dep))
                else:
                    candidate_files.append((
                        target_path,
                        os.path.basename(target_path),
                        self.enable_secret_scan,
                        self.enable_dependency_scan,
                    ))
        elif os.path.isdir(target_path):
            for root, dirs, files in os.walk(target_path):
                # Prune common VCS/build/environment directories to prevent redundant crawling
                dirs[:] = [d for d in dirs if d not in self.DEFAULT_PRUNE_DIRS]
                if all_ignore_patterns:
                    pruned_dirs = []
                    for d in dirs:
                        rel_dir = os.path.relpath(os.path.join(root, d), target_path)
                        if not is_path_ignored(rel_dir + "/", all_ignore_patterns):
                            pruned_dirs.append(d)
                    dirs[:] = pruned_dirs

                # Respect directory-local .sidikignore when scanning nested workspaces
                local_ignores = all_ignore_patterns
                if root != target_path:
                    nested = load_sidikignore_patterns(root)
                    if nested:
                        rel_prefix = os.path.relpath(root, target_path).replace("\\", "/")
                        local_ignores = list(all_ignore_patterns) + [
                            f"{rel_prefix}/{pat.lstrip('/')}" for pat in nested
                        ]

                for f in files:
                    f_lower = f.lower()
                    full_path = os.path.join(root, f)
                    rel_name = os.path.relpath(full_path, target_path)
                    if local_ignores and is_path_ignored(rel_name, local_ignores):
                        continue
                    is_sec = self.enable_secret_scan and f_lower.endswith(self.secret_extensions)
                    is_dep = self.enable_dependency_scan and any(
                        f_lower == m.lower() or f_lower.endswith("requirements.txt") for m in MANIFEST_FILENAMES
                    )
                    if is_sec or is_dep:
                        candidate_files.append((full_path, rel_name, is_sec, is_dep))

        return candidate_files

    def scan_path(
        self,
        target_path: str,
        progress_callback: Optional[Callable[[int, int, str], None]] = None
    ) -> ScanReport:
        """Executes unified security scan against a file or directory path.

        Args:
            target_path: Path to file or directory to scan.
            progress_callback: Optional callback invoked as `progress_callback(current_idx, total_count, rel_filepath)`
                               to report real-time scanning progress.
        """
        target_path = os.path.abspath(target_path)
        aggregator = FindingAggregator(target_path=target_path)

        # Pre-warm vulnerability database index outside optional tracemalloc measurement
        if self.enable_dependency_scan:
            _ = self.dependency_analyzer.db.advisories

        started_tracemalloc = False
        if self.measure_memory and not tracemalloc.is_tracing():
            tracemalloc.start()
            started_tracemalloc = True

        start_time = time.perf_counter()
        files_scanned = 0
        candidate_files = self._discover_candidate_files(target_path)
        total_files = len(candidate_files)

        try:
            for idx, (full_path, rel_name, is_sec, is_dep) in enumerate(candidate_files, 1):
                if progress_callback:
                    progress_callback(idx, total_files, rel_name)

                scanned_this_file = False

                # Secret scanning for code/config files
                if is_sec:
                    findings = self.secret_detector.scan_file(full_path)
                    aggregator.add_findings(findings)
                    scanned_this_file = True

                # Dependency scanning for manifests
                if is_dep:
                    dep_findings = self.dependency_analyzer.scan_manifest_file(full_path)
                    aggregator.add_findings(dep_findings)
                    scanned_this_file = True

                if scanned_this_file:
                    files_scanned += 1

            duration = time.perf_counter() - start_time
            peak_mem_bytes = 0
            if self.measure_memory and tracemalloc.is_tracing():
                _, peak_mem_bytes = tracemalloc.get_traced_memory()
        finally:
            if started_tracemalloc:
                tracemalloc.stop()

        aggregator.set_files_scanned_count(files_scanned)
        peak_mb = peak_mem_bytes / (1024 * 1024)
        report = aggregator.build_report(duration_seconds=duration, peak_memory_mb=peak_mb)
        if self.post_scan_plugins:
            report = apply_post_scan_plugins(
                self,
                target_path,
                report,
                plugins=self.post_scan_plugins,
                options=self.plugin_options,
            )
        return report

    def extract_secret_candidates(
        self,
        target_path: str,
        include_filtered: bool = True,
    ) -> List[SecretCandidate]:
        """Extracts structured SecretCandidate objects across target_path for analysis or ML triage."""
        target_path = os.path.abspath(target_path)
        candidate_files = self._discover_candidate_files(target_path)
        extracted: List[SecretCandidate] = []
        for full_path, _, is_sec, _ in candidate_files:
            if is_sec:
                extracted.extend(
                    self.secret_detector.extract_candidates_from_file(full_path, include_filtered=include_filtered)
                )
        return extracted


# Alias for branded usage
SidikScanner = SecurityScanner
