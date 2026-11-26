"""Decoupled post-scan plugin discovery and execution interface for SIDIK.

Allows external extensions such as SIDIK-ML to register via standard Python
``importlib.metadata.entry_points`` under the ``sidik.plugins`` group without
introducing any ML dependency or import inside SIDIK itself.
"""

from importlib import metadata, resources
import os
from typing import Any, Dict, List, Optional, Protocol, Sequence, runtime_checkable

from sidik.models import ScanReport

PLUGIN_ENTRY_POINT_GROUP = "sidik.plugins"
BRAND_ASSETS_ENTRY_POINT_GROUP = "sidik.brand_assets"


@runtime_checkable
class PostScanPlugin(Protocol):
    """Protocol implemented by SIDIK post-scan enrichment and triage plugins."""

    name: str
    version: str
    description: str

    def triage_report(
        self,
        scanner: Any,
        target_path: str,
        report: ScanReport,
        options: Optional[Dict[str, Any]] = None,
    ) -> ScanReport:
        """Processes a completed ScanReport and returns the updated ScanReport."""
        ...


def _iter_entry_points(group: str) -> Sequence[Any]:
    eps = metadata.entry_points()
    if hasattr(eps, "select"):
        return list(eps.select(group=group))
    return list(eps.get(group, ()))  # type: ignore[union-attr]


def discover_plugins(group: str = PLUGIN_ENTRY_POINT_GROUP) -> List[PostScanPlugin]:
    """Discovers and instantiates valid plugins registered under ``group``."""
    discovered: List[PostScanPlugin] = []
    seen_names: set[str] = set()
    for ep in _iter_entry_points(group):
        try:
            loaded = ep.load()
            instance = loaded() if (callable(loaded) and not hasattr(loaded, "triage_report")) else loaded
            if isinstance(instance, PostScanPlugin):
                pname = str(getattr(instance, "name", getattr(ep, "name", "unknown"))).lower()
                if pname not in seen_names:
                    seen_names.add(pname)
                    discovered.append(instance)
        except Exception:
            continue
    return discovered


def get_plugin(name: str, group: str = PLUGIN_ENTRY_POINT_GROUP) -> Optional[PostScanPlugin]:
    """Returns the first discovered plugin matching ``name`` (case-insensitive), if installed."""
    target = name.strip().lower()
    if not target:
        return None
    for plugin in discover_plugins(group=group):
        if str(getattr(plugin, "name", "")).strip().lower() == target:
            return plugin
    return None


def apply_post_scan_plugins(
    scanner: Any,
    target_path: str,
    report: ScanReport,
    plugins: Optional[Sequence[Any]] = None,
    options: Optional[Dict[str, Any]] = None,
) -> ScanReport:
    """Runs post-scan plugins sequentially over ``report``."""
    current = report
    if not plugins:
        return current
    for plugin in plugins:
        triage_fn = getattr(plugin, "triage_report", None)
        if callable(triage_fn):
            current = triage_fn(scanner, target_path, current, options=options)  # type: ignore[assignment]
    return current


def resolve_brand_asset_path(
    filename: str,
    fallback_dirs: Optional[Sequence[str]] = None,
) -> Optional[str]:
    """Resolves an extension branding asset via env var, entry points, or fallback dirs."""
    env_dir = os.environ.get("SIDIK_BRAND_ASSETS_DIR")
    if env_dir:
        candidate = os.path.join(env_dir, filename)
        if os.path.isfile(candidate):
            return candidate
    for ep in _iter_entry_points(BRAND_ASSETS_ENTRY_POINT_GROUP):
        try:
            res = resources.files(ep.value).joinpath(filename)
            if res.is_file():
                return str(res)
        except Exception:
            continue
    for directory in fallback_dirs or ():
        candidate = os.path.join(directory, filename)
        if os.path.isfile(candidate):
            return candidate
    return None


def read_brand_asset_bytes(
    filename: str,
    fallback_dirs: Optional[Sequence[str]] = None,
) -> Optional[bytes]:
    """Reads bytes for an extension branding asset if available from any decoupled source."""
    env_dir = os.environ.get("SIDIK_BRAND_ASSETS_DIR")
    if env_dir:
        candidate = os.path.join(env_dir, filename)
        if os.path.isfile(candidate):
            try:
                with open(candidate, "rb") as fh:
                    return fh.read()
            except Exception:
                pass
    for ep in _iter_entry_points(BRAND_ASSETS_ENTRY_POINT_GROUP):
        try:
            res = resources.files(ep.value).joinpath(filename)
            if res.is_file():
                return res.read_bytes()
        except Exception:
            continue
    for directory in fallback_dirs or ():
        candidate = os.path.join(directory, filename)
        if os.path.isfile(candidate):
            try:
                with open(candidate, "rb") as fh:
                    return fh.read()
            except Exception:
                pass
    return None
