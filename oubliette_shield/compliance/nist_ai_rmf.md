# Oubliette Shield - NIST AI Risk Management Framework (AI RMF) Mapping

## Overview

This document maps Oubliette Shield capabilities to the NIST AI Risk Management Framework (AI RMF 1.0, January 2023). The AI RMF provides a structured approach for managing risks associated with AI systems throughout their lifecycle.

Oubliette Shield addresses AI risks specifically in the context of LLM application security, focusing on prompt injection, jailbreak attacks, and adversarial manipulation.

## Framework Coverage Summary

| Function | Controls Mapped | Status |
|----------|----------------|--------|
| GOVERN   | 4/6            | Covered |
| MAP      | 3/5            | Covered |
| MEASURE  | 2/4            | Covered |
| MANAGE   | 4/4            | Fully Covered |

---

## GOVERN Function

The GOVERN function establishes organizational policies, accountability, and risk tolerances for AI systems.

### GOVERN-1: Policies and Procedures

**Requirement:** Policies, processes, procedures, and practices are in place and enforced for AI risk management.

**Shield Coverage:**
- Configurable detection policies via pre-filter rules and ML thresholds
- Environment variable configuration (SHIELD_ML_HIGH, SHIELD_ML_LOW)
- CEF logging provides audit trails for all detection decisions
- Compliance reports document coverage against industry frameworks

**Components:** pre_filter, config, cef_logger, compliance

### GOVERN-2: Accountability Structures

**Requirement:** Accountability structures are in place for AI system risk management.

**Shield Coverage:**
- Session tracking maintains per-user interaction history
- Escalation alerts notify security teams via webhooks (Slack, Teams, PagerDuty)
- CEF logs provide SIEM-compatible audit trails
- Dashboard provides real-time operational visibility

**Components:** session, webhooks, cef_logger, dashboard

### GOVERN-3: Workforce Diversity and AI Expertise

**Requirement:** Workforce diversity, equity, inclusion, and accessibility processes are prioritized.

**Shield Coverage:**
- Open-source (Apache 2.0) enables community contribution
- Comprehensive documentation lowers barrier to entry
- Modular architecture enables contribution at any level

**Status:** Partial - organizational policy, not technical control

### GOVERN-4: Organizational Risk Tolerances

**Requirement:** Organizational risk tolerances are determined and documented.

**Shield Coverage:**
- Configurable ML thresholds define acceptable risk levels
- Rate limiting controls exposure
- Session escalation thresholds are configurable
- Multiple detection modes (block, log-only, deception)

**Components:** config, rate_limiter, session

---

## MAP Function

The MAP function establishes context and identifies AI risks.

### MAP-1: Context and Use Case Definition

**Requirement:** Context is established and understood for AI system deployment.

**Shield Coverage:**
- Documented threat model covering 6+ attack categories
- OWASP LLM Top 10 mapping for industry context
- MITRE ATLAS mapping for adversarial threat context
- Clear deployment documentation (Flask, FastAPI, LangChain, LlamaIndex)

### MAP-2: AI System Classification

**Requirement:** Categorization of the AI system is performed.

**Shield Coverage:**
- Threat classification taxonomy: instruction_override, persona_manipulation, data_extraction, jailbreak, hypothetical_framing
- Severity levels: critical, high, medium, low, none
- ML model provides continuous risk scoring (0.0 - 1.0)

**Components:** pattern_detector, ml_client

### MAP-3: AI Risks and Benefits

**Requirement:** AI risks and benefits are mapped for specific use cases.

**Shield Coverage:**
- Compliance reports map risks to specific mitigations
- Deception responder documents intelligence-gathering benefits
- Cost-benefit analysis: pre-filter (10ms) vs. LLM judge (15s) tradeoffs documented

---

## MEASURE Function

The MEASURE function identifies metrics and methods for evaluating AI systems.

### MEASURE-1: Metrics and Monitoring

**Requirement:** Appropriate methods and metrics are identified and applied.

**Shield Coverage:**
- ML model calibrated scores: F1=0.98, AUC=0.99, cross-validation F1 mean=0.986
- Real-time metrics via dashboard (active sessions, escalated sessions)
- CEF logs capture per-event metrics (ML score, detection method, processing time)
- Processing time metrics: pre-filter ~10ms, ML ~2ms, LLM ~15s

**Components:** ml_client, cef_logger, dashboard

### MEASURE-2: AI System Evaluation

**Requirement:** AI systems are evaluated for trustworthy characteristics.

**Shield Coverage:**
- Red team evaluation framework with 53+ attack scenarios
- Cross-validation ensures model generalization (not overfitting)
- Zero false positives on test set (TN=111, FP=0)
- All 8 tested ATK scenarios detected (scores 0.87-0.99)

**Components:** red_team, ml_client

---

## MANAGE Function

The MANAGE function prioritizes, responds to, and manages AI risks.

### MANAGE-1: Risk Treatment

**Requirement:** AI risks are prioritized, responded to, and managed based on assessments.

**Shield Coverage:**
- Tiered response pipeline: sanitization -> pre-filter -> ML -> LLM
- Priority-based blocking: obvious attacks blocked immediately
- Ambiguous cases escalated to LLM judge for deeper analysis
- Session escalation for persistent threat actors

**Components:** ensemble, session, webhooks

### MANAGE-2: Risk Response Strategies

**Requirement:** Strategies to maximize benefits and minimize negative impacts.

**Shield Coverage:**
- Active defense via deception responder (honeypot, tarpit, redirect modes)
- Rate limiting prevents resource exhaustion
- Progressive session escalation enables graduated response
- Configurable modes allow organizations to choose response strategy

**Components:** deception, rate_limiter, session

### MANAGE-3: Post-Deployment Monitoring

**Requirement:** AI risks and impacts are monitored post-deployment.

**Shield Coverage:**
- CEF/SIEM integration for continuous monitoring
- Webhook alerting for real-time notifications
- SQLite persistent storage for historical analysis
- Session tracking captures interaction patterns over time

**Components:** cef_logger, webhooks, storage, session

### MANAGE-4: Incident Response

**Requirement:** AI system incidents are documented and response processes followed.

**Shield Coverage:**
- CEF logging documents all incidents in SIEM-compatible format
- Webhook manager dispatches real-time alerts to incident response platforms
- Session state preserves complete attack forensics
- Deception responder enables active intelligence gathering during incidents

**Components:** cef_logger, webhooks, session, deception

---

## Summary

Oubliette Shield provides substantial coverage of the NIST AI RMF, particularly in the MANAGE function where all 4 controls are fully addressed. The framework's focus on input protection, monitoring, and incident response aligns well with Shield's core capabilities as an LLM firewall.

**Key strengths:**
- Comprehensive detection pipeline (GOVERN-1, MAP-2)
- Real-time monitoring and alerting (MEASURE-1, MANAGE-3)
- Active defense capabilities (MANAGE-2)
- Incident documentation and response (MANAGE-4)

**Areas for future improvement:**
- GOVERN-5, GOVERN-6: Supply chain and third-party risk management
- MAP-4, MAP-5: Broader AI impact assessment beyond security
- MEASURE-3, MEASURE-4: Continuous improvement and feedback mechanisms
