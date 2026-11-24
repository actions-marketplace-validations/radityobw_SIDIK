"""SIDIK: Secret Identification and Dependency Inspection Kit.

A lightweight static security analyzer for Python detecting hardcoded secrets
and vulnerable dependencies with context-aware analysis and zero data leakage benchmarking.
"""

from sidik.core import SecurityScanner, SidikScanner
from sidik.models import (
    Finding,
    ScanReport,
    SeverityLevel,
    ConfidenceScore,
    SecretCandidate,
    CANDIDATE_SCHEMA_VERSION,
    compute_stable_id,
)
from sidik.i18n import t, set_language, get_current_language
from sidik.plugins import (
    PLUGIN_ENTRY_POINT_GROUP,
    PostScanPlugin,
    discover_plugins,
    get_plugin,
    apply_post_scan_plugins,
)

__version__ = "1.3.6"
__tool_name__ = "SIDIK"
__full_name__ = "Secret Identification and Dependency Inspection Kit"

__all__ = [
    "SecurityScanner",
    "SidikScanner",
    "Finding",
    "ScanReport",
    "SeverityLevel",
    "ConfidenceScore",
    "SecretCandidate",
    "CANDIDATE_SCHEMA_VERSION",
    "compute_stable_id",
    "PLUGIN_ENTRY_POINT_GROUP",
    "PostScanPlugin",
    "discover_plugins",
    "get_plugin",
    "apply_post_scan_plugins",
    "t",
    "set_language",
    "get_current_language",
    "__version__",
    "__tool_name__",
    "__full_name__"
]
