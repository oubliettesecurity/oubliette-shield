"""Tests for compliance framework mappings."""

import json
import pytest

from oubliette_shield.compliance import (
    NIST_AI_RMF_CONTROLS,
    OWASP_LLM_TOP10,
    MITRE_ATLAS_TTPS,
    get_coverage_report,
)


class TestComplianceData:
    """Tests for compliance mapping data structures."""

    def test_nist_controls_exist(self):
        assert len(NIST_AI_RMF_CONTROLS) > 0
        for key, control in NIST_AI_RMF_CONTROLS.items():
            assert "title" in control
            assert "status" in control
            assert "shield_coverage" in control

    def test_owasp_has_all_10(self):
        """OWASP mapping has all 10 LLM risks."""
        assert len(OWASP_LLM_TOP10) == 10
        for i in range(1, 11):
            key = f"LLM{i:02d}"
            assert key in OWASP_LLM_TOP10, f"Missing {key}"
            assert "title" in OWASP_LLM_TOP10[key]

    def test_mitre_atlas_ttps_exist(self):
        assert len(MITRE_ATLAS_TTPS) > 0
        for key, ttp in MITRE_ATLAS_TTPS.items():
            assert "title" in ttp
            assert "tactic" in ttp
            assert "status" in ttp

    def test_statuses_are_valid(self):
        """All status values are from allowed set."""
        valid_statuses = {
            "covered", "partial", "fully_mitigated", "partially_mitigated",
            "detected", "mitigated", "partially_detected",
        }
        for control in NIST_AI_RMF_CONTROLS.values():
            assert control["status"] in valid_statuses
        for control in OWASP_LLM_TOP10.values():
            assert control["status"] in valid_statuses
        for ttp in MITRE_ATLAS_TTPS.values():
            assert ttp["status"] in valid_statuses


class TestCoverageReport:
    """Tests for programmatic report generation."""

    def test_nist_report_json(self):
        report = get_coverage_report("nist", "json")
        data = json.loads(report)
        assert "nist_ai_rmf" in data
        assert data["nist_ai_rmf"]["framework"] == "NIST AI RMF"
        assert data["nist_ai_rmf"]["total_controls"] > 0

    def test_owasp_report_markdown(self):
        report = get_coverage_report("owasp", "markdown")
        assert "OWASP LLM Top 10" in report
        # Should contain all 10 risks
        for i in range(1, 11):
            assert f"LLM{i:02d}" in report

    def test_mitre_report_json(self):
        report = get_coverage_report("atlas", "json")
        data = json.loads(report)
        assert "mitre_atlas" in data
        assert data["mitre_atlas"]["framework"] == "MITRE ATLAS"

    def test_all_frameworks(self):
        report = get_coverage_report("all", "json")
        data = json.loads(report)
        assert "nist_ai_rmf" in data
        assert "owasp_llm_top10" in data
        assert "mitre_atlas" in data

    def test_html_report(self):
        report = get_coverage_report("all", "html")
        assert "<html>" in report
        assert "NIST AI RMF" in report
        assert "OWASP LLM Top 10" in report
        assert "MITRE ATLAS" in report

    def test_markdown_has_table(self):
        report = get_coverage_report("nist", "markdown")
        assert "| ID |" in report
        assert "| Title |" in report

    def test_json_serializable(self):
        """Report JSON output is valid JSON."""
        report = get_coverage_report("all", "json")
        data = json.loads(report)
        # Round-trip
        assert json.dumps(data) is not None

    def test_unknown_framework(self):
        """Unknown framework returns empty JSON."""
        report = get_coverage_report("unknown_framework", "json")
        data = json.loads(report)
        assert data == {}
