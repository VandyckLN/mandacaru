"""Scanner local de vulnerabilidades (CVE/CVSS via OSV.dev e CISA KEV)."""
from __future__ import annotations

from .inventory import InstalledPackage, detect_ecosystem, find_running_packages, parse_dpkg_status
from .kev_cache import KevCache
from .osv_client import OsvClient
from .scorer import ScoredVulnerability, classify_finding, finding_to_alert, parse_cvss31_base_score

__all__ = [
    "InstalledPackage",
    "KevCache",
    "OsvClient",
    "ScoredVulnerability",
    "classify_finding",
    "detect_ecosystem",
    "find_running_packages",
    "finding_to_alert",
    "parse_cvss31_base_score",
    "parse_dpkg_status",
]
