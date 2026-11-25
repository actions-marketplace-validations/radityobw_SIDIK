"""Core unified security scanner orchestrating secret detection and dependency analysis."""

import os
import time
import fnmatch
import tracemalloc
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple
from sidik.models import ScanReport, SecretCandidate
from sidik.plugins import apply_post_scan_plugins
from sidik.secret_detector.detector import DEFAULT_MAX_FILE_SIZE_BYTES, SecretDetector
from sidik.dependency_analyzer.analyzer import DependencyAnalyzer, is_manifest_file
from sidik.dependency_analyzer.database import VulnerabilityDatabase
from sidik.reporting.aggregator import FindingAggregator

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - Python < 3.11 fallback
    import tomli as tomllib  # type: ignore[no-redef]

DEFAULT_SECRET_EXTENSIONS: Tuple[str, ...] = (
    ".py", ".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".vue", ".svelte",
    ".go", ".rs", ".java", ".kt", ".kts", ".scala", ".cs", ".php", ".rb",
    ".swift", ".dart", ".c", ".cpp", ".h", ".sh", ".bash", ".zsh", ".ps1",
    ".env", ".yaml", ".yml", ".toml", ".ini", ".cfg", ".conf", ".properties",
    ".json", ".xml", ".tf", ".tfvars", ".hcl", ".gradle",
)
LOCKFILE_NAMES = {
    "poetry.lock", "pipfile.lock", "uv.lock",
    "package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml",
    "cargo.lock", "go.sum", "composer.lock", "gemfile.lock",
    "packages.lock.json", "flake.lock",
}
SPECIAL_SECRET_FILENAMES = {"dockerfile", ".npmrc", ".pypirc", ".netrc"}
_MINIFIED_SUFFIXES = (".min.js", ".min.css", ".bundle.js", ".map")


def load_pyproject_sidik_config(base_dir: str) -> Dict[str, Any]:
    """Loads optional [tool.sidik] configuration table from pyproject.toml in base_dir."""
    pyproject_path = os.path.join(base_dir, "pyproject.toml")
    if not os.path.isfile(pyproject_path):
        return {}
    try:
        with open(pyproject_path, "rb") as f:
            data = tomllib.load(f)
        cfg = data.get("tool", {}).get("sidik", {})
        return dict(cfg) if isinstance(cfg, dict) else {}
    except Exception:
        return {}


def is_secret_candidate_filename(filename: str, secret_extensions: Tuple[str, ...]) -> bool:
    """Returns True when filename should be scanned for hardcoded secrets."""
    f_lower = filename.lower()
    if f_lower in LOCKFILE_NAMES or f_lower.endswith(_MINIFIED_SUFFIXES):
        return False
    if f_lower in SPECIAL_SECRET_FILENAMES or f_lower.startswith("dockerfile."):
        return True
    if f_lower == ".env" or f_lower.startswith(".env."):
        return True
    return f_lower.endswith(secret_extensions)


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
        ".idea", ".vscode", ".pytest_cache", "dist", "build",
        "target", "vendor", ".next", ".nuxt", "out", "bin", "obj",
        ".gradle", ".terraform", "coverage", "__snapshots__",
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
        max_file_size_bytes: int = DEFAULT_MAX_FILE_SIZE_BYTES,
        post_scan_plugins: Optional[Sequence[Any]] = None,
        plugin_options: Optional[Dict[str, Any]] = None,
    ):
        self.enable_secret_scan = enable_secret_scan
        self.enable_dependency_scan = enable_dependency_scan
        self.secret_detector = SecretDetector(
            enable_context=enable_context,
            enable_entropy=enable_entropy,
            max_file_size_bytes=max_file_size_bytes,
        )
        db = VulnerabilityDatabase(custom_vulnerability_db) if custom_vulnerability_db else None
        self.dependency_analyzer = DependencyAnalyzer(db=db)
        self.custom_ignore_patterns = list(ignore_patterns) if ignore_patterns else []
        self.measure_memory = measure_memory
        self.secret_extensions = secret_extensions or DEFAULT_SECRET_EXTENSIONS
        self.post_scan_plugins = list(post_scan_plugins) if post_scan_plugins else []
        self.plugin_options = dict(plugin_options) if plugin_options else {}

    def _discover_candidate_files(self, target_path: str) -> List[Tuple[str, str, bool, bool]]:
        """Discovers target files for secret and/or dependency scanning honoring .sidikignore and [tool.sidik]."""
        base_dir = target_path if os.path.isdir(target_path) else os.path.dirname(target_path)
        file_ignore_patterns = load_sidikignore_patterns(base_dir)
        cfg = load_pyproject_sidik_config(base_dir)
        cfg_excludes = [str(p) for p in cfg.get("exclude", []) if isinstance(p, str)] if isinstance(cfg.get("exclude"), list) else []
        all_ignore_patterns = list(self.custom_ignore_patterns) + cfg_excludes + file_ignore_patterns

        candidate_files: List[Tuple[str, str, bool, bool]] = []

        if os.path.isfile(target_path):
            filename = os.path.basename(target_path).lower()
            if not is_path_ignored(os.path.basename(target_path), all_ignore_patterns):
                single_exts = tuple(dict.fromkeys((*self.secret_extensions, ".cfg", ".ini", ".json", ".yaml", ".yml", ".txt")))
                is_sec = self.enable_secret_scan and is_secret_candidate_filename(filename, single_exts)
                is_dep = self.enable_dependency_scan and is_manifest_file(target_path)
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
                    full_path = os.path.join(root, f)
                    rel_name = os.path.relpath(full_path, target_path)
                    if local_ignores and is_path_ignored(rel_name, local_ignores):
                        continue
                    is_sec = self.enable_secret_scan and is_secret_candidate_filename(f, self.secret_extensions)
                    is_dep = self.enable_dependency_scan and is_manifest_file(full_path)
                    if is_sec or is_dep:
                        candidate_files.append((full_path, rel_name, is_sec, is_dep))

        return candidate_files

    def _scan_candidate_list(
        self,
        display_target: str,
        candidate_files: List[Tuple[str, str, bool, bool]],
        progress_callback: Optional[Callable[[int, int, str], None]] = None,
    ) -> ScanReport:
        aggregator = FindingAggregator(target_path=display_target)

        # Pre-warm vulnerability database index outside optional tracemalloc measurement
        if self.enable_dependency_scan:
            _ = self.dependency_analyzer.db.advisories

        started_tracemalloc = False
        if self.measure_memory and not tracemalloc.is_tracing():
            tracemalloc.start()
            started_tracemalloc = True

        start_time = time.perf_counter()
        files_scanned = 0
        total_files = len(candidate_files)
        use_single_pass_plugins = bool(self.post_scan_plugins)
        preextracted_candidates: List[SecretCandidate] = []

        try:
            for idx, (full_path, rel_name, is_sec, is_dep) in enumerate(candidate_files, 1):
                if progress_callback:
                    progress_callback(idx, total_files, rel_name)

                scanned_this_file = False

                # Secret scanning for code/config files
                if is_sec:
                    if use_single_pass_plugins:
                        findings, cands = self.secret_detector.scan_and_extract_file(full_path, include_filtered=True)
                        preextracted_candidates.extend(cands)
                    else:
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
            opts = dict(self.plugin_options)
            opts["_preextracted_candidates"] = preextracted_candidates
            report = apply_post_scan_plugins(
                self,
                display_target,
                report,
                plugins=self.post_scan_plugins,
                options=opts,
            )
        return report

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
        candidate_files = self._discover_candidate_files(target_path)
        return self._scan_candidate_list(target_path, candidate_files, progress_callback=progress_callback)

    def scan_paths(
        self,
        target_paths: Sequence[str],
        progress_callback: Optional[Callable[[int, int, str], None]] = None,
    ) -> ScanReport:
        """Executes unified security scan across multiple files or directories."""
        abs_targets = [os.path.abspath(p) for p in target_paths if p]
        if not abs_targets:
            return self.scan_path(".", progress_callback=progress_callback)
        if len(abs_targets) == 1:
            return self.scan_path(abs_targets[0], progress_callback=progress_callback)

        common_root = os.path.commonpath(abs_targets)
        seen_paths = set()
        combined: List[Tuple[str, str, bool, bool]] = []
        for tpath in abs_targets:
            for full_path, _rel, is_sec, is_dep in self._discover_candidate_files(tpath):
                norm_full = os.path.normcase(os.path.abspath(full_path))
                if norm_full in seen_paths:
                    continue
                seen_paths.add(norm_full)
                try:
                    rel_display = os.path.relpath(full_path, common_root)
                except ValueError:
                    rel_display = full_path
                combined.append((full_path, rel_display, is_sec, is_dep))
        return self._scan_candidate_list(common_root, combined, progress_callback=progress_callback)

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
