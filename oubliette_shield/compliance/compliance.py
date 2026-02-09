"""
Oubliette Shield - Compliance Framework Mappings
Programmatic access to compliance coverage data for NIST AI RMF,
OWASP LLM Top 10, and MITRE ATLAS frameworks.
"""

import json

# ============================================================================
# NIST AI RMF Controls
# ============================================================================

NIST_AI_RMF_CONTROLS = {
    "GOVERN-1": {
        "title": "Policies and Procedures",
        "description": "Policies, processes, procedures, and practices are in place and enforced for AI risk management.",
        "shield_coverage": "Shield provides configurable detection policies via pre-filter rules, ML thresholds, and LLM judge criteria. All detections are logged via CEF for audit.",
        "status": "covered",
        "components": ["pre_filter", "config", "cef_logger"],
    },
    "GOVERN-2": {
        "title": "Accountability Structures",
        "description": "Accountability structures are in place for AI system risk management.",
        "shield_coverage": "Session tracking, escalation alerts, and webhook notifications enable accountability chains. CEF logs provide audit trails.",
        "status": "covered",
        "components": ["session", "webhooks", "cef_logger"],
    },
    "GOVERN-3": {
        "title": "Workforce Diversity and AI Expertise",
        "description": "Workforce diversity, equity, inclusion, and accessibility processes are prioritized in AI system lifecycle.",
        "shield_coverage": "Shield is open-source (Apache 2.0), enabling community review and contribution from diverse stakeholders.",
        "status": "partial",
        "components": [],
    },
    "GOVERN-4": {
        "title": "Organizational Risk Tolerances",
        "description": "Organizational risk tolerances are determined and documented.",
        "shield_coverage": "Configurable thresholds (ML_HIGH, ML_LOW), escalation rules, and rate limits allow organizations to set risk tolerances.",
        "status": "covered",
        "components": ["config", "rate_limiter"],
    },
    "MAP-1": {
        "title": "Context and Use Case Definition",
        "description": "Context is established and understood for AI system deployment.",
        "shield_coverage": "Shield documents its threat model (prompt injection, jailbreak, data extraction) and detection pipeline in documentation.",
        "status": "covered",
        "components": ["documentation"],
    },
    "MAP-2": {
        "title": "AI System Classification",
        "description": "Categorization of the AI system is performed.",
        "shield_coverage": "Shield classifies threats by type (instruction_override, persona_manipulation, data_extraction, jailbreak) and severity (critical/high/medium/low).",
        "status": "covered",
        "components": ["pattern_detector", "ml_client"],
    },
    "MAP-3": {
        "title": "AI Risks and Benefits",
        "description": "AI risks and benefits are mapped for the specific use case.",
        "shield_coverage": "Compliance reports map specific risks (OWASP LLM01-10) to Shield mitigations. Deception responder documents intelligence benefits.",
        "status": "covered",
        "components": ["compliance", "deception"],
    },
    "MEASURE-1": {
        "title": "Metrics and Monitoring",
        "description": "Appropriate methods and metrics are identified and applied.",
        "shield_coverage": "ML model provides calibrated scores (F1=0.98, AUC=0.99). CEF logs capture all detections with severity scores. Dashboard provides real-time monitoring.",
        "status": "covered",
        "components": ["ml_client", "cef_logger", "dashboard"],
    },
    "MEASURE-2": {
        "title": "AI System Evaluation",
        "description": "AI systems are evaluated for trustworthy characteristics.",
        "shield_coverage": "Red team evaluation framework with 53+ test scenarios. ML model validated with cross-validation (F1 mean=0.986).",
        "status": "covered",
        "components": ["red_team", "ml_client"],
    },
    "MANAGE-1": {
        "title": "Risk Treatment",
        "description": "AI risks based on assessments and other analytical output are prioritized, responded to, and managed.",
        "shield_coverage": "Tiered response: pre-filter block (immediate), ML scoring (2ms), LLM judge (ambiguous cases), session escalation (multi-turn). Webhooks enable real-time incident response.",
        "status": "covered",
        "components": ["ensemble", "session", "webhooks"],
    },
    "MANAGE-2": {
        "title": "Risk Response Strategies",
        "description": "Strategies to maximize AI benefits and minimize negative impacts are planned and prepared.",
        "shield_coverage": "Deception responder provides active defense. Rate limiter prevents abuse. Session escalation enables progressive response.",
        "status": "covered",
        "components": ["deception", "rate_limiter", "session"],
    },
    "MANAGE-3": {
        "title": "Post-Deployment Monitoring",
        "description": "AI risks and impacts are monitored post-deployment.",
        "shield_coverage": "CEF/SIEM integration, webhook alerting, session tracking, and SQLite storage provide continuous post-deployment monitoring.",
        "status": "covered",
        "components": ["cef_logger", "webhooks", "storage", "session"],
    },
    "MANAGE-4": {
        "title": "Incident Response",
        "description": "AI system incidents are documented and processes are followed.",
        "shield_coverage": "CEF logging documents all incidents. Webhook manager dispatches alerts to Slack, Teams, PagerDuty. Session state preserves attack forensics.",
        "status": "covered",
        "components": ["cef_logger", "webhooks", "session"],
    },
}

# ============================================================================
# OWASP LLM Top 10 (2025)
# ============================================================================

OWASP_LLM_TOP10 = {
    "LLM01": {
        "title": "Prompt Injection",
        "description": "Manipulating LLMs through crafted inputs to cause unintended actions.",
        "shield_coverage": "Core capability. Multi-tier detection: input sanitization (9 types), pre-filter pattern matching, ML classifier (F1=0.98), LLM judge, session-based multi-turn tracking.",
        "status": "fully_mitigated",
        "components": ["sanitizer", "pre_filter", "ml_client", "llm_judge", "session"],
    },
    "LLM02": {
        "title": "Insecure Output Handling",
        "description": "Insufficient validation of LLM outputs leading to XSS, SSRF, etc.",
        "shield_coverage": "Input sanitization removes code injection vectors. Output monitoring available via deception responder integration.",
        "status": "partially_mitigated",
        "components": ["sanitizer", "deception"],
    },
    "LLM03": {
        "title": "Training Data Poisoning",
        "description": "Manipulation of training data to compromise model behavior.",
        "shield_coverage": "Shield's ML model is trained on curated, labeled datasets. Model integrity verified via cross-validation. Bundled model prevents supply chain modification.",
        "status": "partially_mitigated",
        "components": ["ml_client", "models"],
    },
    "LLM04": {
        "title": "Model Denial of Service",
        "description": "Resource-consuming interactions that degrade LLM service quality.",
        "shield_coverage": "Rate limiter prevents abuse. Pre-filter blocks obvious attacks before expensive LLM calls (1,550x speedup). Session tracking detects rapid escalation.",
        "status": "fully_mitigated",
        "components": ["rate_limiter", "pre_filter", "session"],
    },
    "LLM05": {
        "title": "Supply Chain Vulnerabilities",
        "description": "Compromised components, models, or data in the LLM supply chain.",
        "shield_coverage": "Bundled ML model eliminates external API dependency. Minimal core dependencies (requests only). All optional deps pinned to minimum versions.",
        "status": "partially_mitigated",
        "components": ["models", "packaging"],
    },
    "LLM06": {
        "title": "Sensitive Information Disclosure",
        "description": "LLMs inadvertently revealing confidential data.",
        "shield_coverage": "Input sanitization detects extraction attempts. Deception responder provides fake data instead of real secrets. Session tracking escalates repeated extraction attempts.",
        "status": "fully_mitigated",
        "components": ["sanitizer", "deception", "session", "pre_filter"],
    },
    "LLM07": {
        "title": "Insecure Plugin Design",
        "description": "LLM plugins with inadequate access controls.",
        "shield_coverage": "Shield acts as a security layer before plugin execution. FastAPI middleware and LangChain/LlamaIndex integrations intercept inputs before they reach plugins.",
        "status": "partially_mitigated",
        "components": ["fastapi_middleware", "integrations"],
    },
    "LLM08": {
        "title": "Excessive Agency",
        "description": "LLM systems with overly broad permissions or autonomy.",
        "shield_coverage": "Shield blocks malicious inputs before they can trigger unintended actions. Configurable blocking vs. logging modes allow graduated responses.",
        "status": "partially_mitigated",
        "components": ["ensemble", "config"],
    },
    "LLM09": {
        "title": "Overreliance",
        "description": "Excessive dependence on LLMs without oversight.",
        "shield_coverage": "Shield provides an independent verification layer. SAFE_REVIEW verdict flags ambiguous cases for human review. Dashboard enables human oversight.",
        "status": "partially_mitigated",
        "components": ["ensemble", "dashboard"],
    },
    "LLM10": {
        "title": "Model Theft",
        "description": "Unauthorized access to proprietary LLM models.",
        "shield_coverage": "API key authentication, rate limiting, and CEF logging detect and prevent systematic model probing attempts.",
        "status": "partially_mitigated",
        "components": ["rate_limiter", "cef_logger", "api_key_auth"],
    },
}

# ============================================================================
# MITRE ATLAS TTPs
# ============================================================================

MITRE_ATLAS_TTPS = {
    "AML.T0051": {
        "title": "LLM Prompt Injection - Direct",
        "tactic": "Initial Access",
        "description": "Adversary crafts direct prompt injection to manipulate LLM behavior.",
        "shield_coverage": "Detected by pre-filter (instruction override patterns), ML classifier, and LLM judge.",
        "status": "detected",
        "components": ["pre_filter", "ml_client", "llm_judge"],
    },
    "AML.T0051.001": {
        "title": "LLM Prompt Injection - Indirect",
        "tactic": "Initial Access",
        "description": "Injection via external data sources consumed by the LLM.",
        "shield_coverage": "Input sanitization removes embedded payloads. ML classifier detects injection patterns regardless of source.",
        "status": "detected",
        "components": ["sanitizer", "ml_client"],
    },
    "AML.T0054": {
        "title": "LLM Jailbreak",
        "tactic": "Defense Evasion",
        "description": "Techniques to bypass LLM safety guardrails.",
        "shield_coverage": "Dedicated jailbreak detection: DAN patterns, hypothetical framing, fictional narrative, persona override, logic traps. Session tracking escalates after 1 attempt.",
        "status": "detected",
        "components": ["pre_filter", "pattern_detector", "session"],
    },
    "AML.T0040": {
        "title": "ML Model Inference API Access",
        "tactic": "Reconnaissance",
        "description": "Adversary accesses ML model inference API to probe behavior.",
        "shield_coverage": "Rate limiter prevents systematic probing. Session tracking detects probe patterns. CEF logs capture all interactions.",
        "status": "detected",
        "components": ["rate_limiter", "session", "cef_logger"],
    },
    "AML.T0043": {
        "title": "Craft Adversarial Data",
        "tactic": "Resource Development",
        "description": "Adversary crafts data designed to exploit ML model weaknesses.",
        "shield_coverage": "Input sanitization (Unicode normalization, encoding attacks, invisible characters). Multi-tier detection catches evasion attempts.",
        "status": "detected",
        "components": ["sanitizer", "ensemble"],
    },
    "AML.T0047": {
        "title": "ML Supply Chain Compromise",
        "tactic": "Initial Access",
        "description": "Compromising ML supply chain to inject malicious components.",
        "shield_coverage": "Bundled ML model with verified training data. No external model download at runtime.",
        "status": "mitigated",
        "components": ["models"],
    },
    "AML.T0048": {
        "title": "Exfiltration via ML Inference API",
        "tactic": "Exfiltration",
        "description": "Using ML inference APIs to extract training data or model parameters.",
        "shield_coverage": "Rate limiting prevents bulk extraction. Data extraction patterns detected by pre-filter and ML classifier.",
        "status": "detected",
        "components": ["rate_limiter", "pre_filter", "ml_client"],
    },
    "AML.T0052": {
        "title": "Phishing via AI-Generated Content",
        "tactic": "Social Engineering",
        "description": "Using AI to generate convincing phishing content.",
        "shield_coverage": "Shield detects attempts to use the LLM for generating malicious content via instruction override detection.",
        "status": "partially_detected",
        "components": ["pre_filter", "llm_judge"],
    },
    "AML.T0056": {
        "title": "LLM Meta Prompt Extraction",
        "tactic": "Collection",
        "description": "Attempting to extract the system prompt or meta-prompt from an LLM.",
        "shield_coverage": "Dedicated extraction indicators in pre-filter. Deception responder provides fake system prompt instead of real one.",
        "status": "detected",
        "components": ["pre_filter", "deception"],
    },
}


def get_coverage_report(framework="all", fmt="json"):
    """
    Generate a compliance coverage report.

    Args:
        framework: "nist", "owasp", "atlas", or "all"
        fmt: "json", "markdown", or "html"

    Returns:
        str: Formatted report
    """
    data = {}

    if framework in ("nist", "all"):
        data["nist_ai_rmf"] = _build_framework_summary(
            "NIST AI RMF", NIST_AI_RMF_CONTROLS
        )

    if framework in ("owasp", "all"):
        data["owasp_llm_top10"] = _build_framework_summary(
            "OWASP LLM Top 10", OWASP_LLM_TOP10
        )

    if framework in ("atlas", "all"):
        data["mitre_atlas"] = _build_framework_summary(
            "MITRE ATLAS", MITRE_ATLAS_TTPS
        )

    if fmt == "json":
        return json.dumps(data, indent=2)
    elif fmt == "markdown":
        return _render_markdown(data)
    elif fmt == "html":
        return _render_html(data)
    else:
        return json.dumps(data, indent=2)


def _build_framework_summary(name, controls):
    """Build summary statistics for a framework."""
    total = len(controls)
    statuses = {}
    items = []
    for control_id, info in controls.items():
        status = info.get("status", "unknown")
        statuses[status] = statuses.get(status, 0) + 1
        items.append({
            "id": control_id,
            "title": info["title"],
            "status": status,
            "coverage": info.get("shield_coverage", ""),
            "components": info.get("components", []),
        })

    return {
        "framework": name,
        "total_controls": total,
        "status_summary": statuses,
        "controls": items,
    }


def _render_markdown(data):
    """Render report as markdown."""
    lines = ["# Oubliette Shield - Compliance Coverage Report\n"]

    for key, framework in data.items():
        lines.append(f"## {framework['framework']}\n")
        lines.append(f"**Total Controls:** {framework['total_controls']}\n")

        # Status summary
        lines.append("### Coverage Summary\n")
        for status, count in framework["status_summary"].items():
            pct = (count / framework["total_controls"]) * 100
            lines.append(f"- **{status}**: {count}/{framework['total_controls']} ({pct:.0f}%)")
        lines.append("")

        # Control details
        lines.append("### Control Details\n")
        lines.append("| ID | Title | Status | Components |")
        lines.append("|-----|-------|--------|------------|")
        for item in framework["controls"]:
            components = ", ".join(item["components"]) if item["components"] else "-"
            lines.append(
                f"| {item['id']} | {item['title']} | {item['status']} | {components} |"
            )
        lines.append("")

    return "\n".join(lines)


def _render_html(data):
    """Render report as HTML."""
    html = [
        "<html><head><title>Oubliette Shield Compliance Report</title>",
        "<style>",
        "body { font-family: sans-serif; max-width: 1000px; margin: 0 auto; padding: 20px; }",
        "table { border-collapse: collapse; width: 100%; margin: 10px 0; }",
        "th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }",
        "th { background: #333; color: white; }",
        ".covered, .fully_mitigated, .detected, .mitigated { color: green; }",
        ".partial, .partially_mitigated, .partially_detected { color: orange; }",
        "</style></head><body>",
        "<h1>Oubliette Shield - Compliance Coverage Report</h1>",
    ]

    for key, framework in data.items():
        html.append(f"<h2>{framework['framework']}</h2>")
        html.append(f"<p>Total Controls: {framework['total_controls']}</p>")
        html.append("<table><tr><th>ID</th><th>Title</th><th>Status</th><th>Coverage</th></tr>")
        for item in framework["controls"]:
            status_class = item["status"].replace(" ", "_")
            html.append(
                f"<tr><td>{item['id']}</td><td>{item['title']}</td>"
                f"<td class='{status_class}'>{item['status']}</td>"
                f"<td>{item['coverage']}</td></tr>"
            )
        html.append("</table>")

    html.append("</body></html>")
    return "\n".join(html)
