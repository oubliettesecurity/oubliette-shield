"""
Oubliette Shield - Compliance Mappings
NIST AI RMF, OWASP LLM Top 10, and MITRE ATLAS coverage reports.
"""

from .compliance import (
    NIST_AI_RMF_CONTROLS,
    OWASP_LLM_TOP10,
    MITRE_ATLAS_TTPS,
    get_coverage_report,
)

__all__ = [
    "NIST_AI_RMF_CONTROLS",
    "OWASP_LLM_TOP10",
    "MITRE_ATLAS_TTPS",
    "get_coverage_report",
]
