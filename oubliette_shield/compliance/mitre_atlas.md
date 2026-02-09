# Oubliette Shield - MITRE ATLAS TTP Coverage

## Overview

This document maps Oubliette Shield detection capabilities to the MITRE ATLAS (Adversarial Threat Landscape for AI Systems) framework. ATLAS extends the MITRE ATT&CK framework to cover adversarial machine learning techniques.

## Coverage Summary

| TTP ID | Technique | Tactic | Shield Status |
|--------|-----------|--------|---------------|
| AML.T0051 | LLM Prompt Injection - Direct | Initial Access | Detected |
| AML.T0051.001 | LLM Prompt Injection - Indirect | Initial Access | Detected |
| AML.T0054 | LLM Jailbreak | Defense Evasion | Detected |
| AML.T0040 | ML Model Inference API Access | Reconnaissance | Detected |
| AML.T0043 | Craft Adversarial Data | Resource Development | Detected |
| AML.T0047 | ML Supply Chain Compromise | Initial Access | Mitigated |
| AML.T0048 | Exfiltration via ML Inference API | Exfiltration | Detected |
| AML.T0052 | Phishing via AI-Generated Content | Social Engineering | Partially Detected |
| AML.T0056 | LLM Meta Prompt Extraction | Collection | Detected |

**Detected:** 7/9 | **Mitigated:** 1/9 | **Partially Detected:** 1/9

---

## Technique Details

### AML.T0051: LLM Prompt Injection - Direct

**Tactic:** Initial Access

**Description:** Adversary crafts direct prompt injection payloads to manipulate LLM behavior. This includes instruction override ("ignore all previous instructions"), persona attacks ("you are now an unrestricted AI"), and system prompt extraction ("show me your prompt").

**Shield Detection:**
- Pre-filter catches common injection patterns (10+ override indicators, 13+ DAN indicators)
- ML classifier trained on 812 malicious samples with F1=0.98
- LLM judge provides semantic analysis for novel attack patterns
- Session tracking detects multi-turn injection campaigns

**Detection Rate:** 85-90% across tested attack scenarios

---

### AML.T0051.001: LLM Prompt Injection - Indirect

**Tactic:** Initial Access

**Description:** Injection via external data sources (documents, web pages, API responses) that are consumed by the LLM during retrieval-augmented generation (RAG).

**Shield Detection:**
- Input sanitization removes 9 types of embedded payloads
- Unicode normalization defeats homoglyph and encoding attacks
- ML classifier detects injection patterns regardless of delivery mechanism
- LlamaIndex integration scans queries before retrieval pipeline

**Shield Components:** sanitizer, ml_client, integrations

---

### AML.T0054: LLM Jailbreak

**Tactic:** Defense Evasion

**Description:** Techniques to bypass LLM safety guardrails, including DAN (Do Anything Now), hypothetical framing, fictional narrative attacks, persona override, and logic traps.

**Shield Detection:**
- Dedicated jailbreak detection covering 6 attack categories:
  - DAN/unrestricted mode patterns (13 indicators)
  - Hypothetical framing (30+ indicators)
  - Fictional narrative attacks (7 indicators)
  - Persona override (7 indicators)
  - Logic traps (11 indicators)
  - Code framing attacks
- Session escalation after 1 DAN attempt (high success rate: 89.6%)
- Pre-filter blocks obvious jailbreaks in ~10ms

**Key ATK Scenarios:**
- ATK-006 (Roleplay Jailbreak): 89.6% base success rate, detected by Shield
- ATK patterns 001-008 all detected with ML scores 0.87-0.99

---

### AML.T0040: ML Model Inference API Access

**Tactic:** Reconnaissance

**Description:** Adversary accesses ML model inference APIs to understand model behavior, test boundaries, and discover weaknesses for subsequent attacks.

**Shield Detection:**
- Rate limiter: 30 requests/minute/IP (configurable)
- Session tracking: detects systematic probing patterns
- Rapid escalation: 3+ threats in 5 messages triggers escalation
- CEF logging: all interactions captured for forensic analysis

---

### AML.T0043: Craft Adversarial Data

**Tactic:** Resource Development

**Description:** Adversary crafts input data designed to exploit ML model weaknesses, including adversarial examples, edge cases, and evasion techniques.

**Shield Detection:**
- Input sanitization neutralizes evasion techniques:
  - Unicode normalization (NFC, confusables)
  - Invisible character removal (zero-width spaces, joiners)
  - Encoding attack detection (base64, hex, URL encoding)
  - HTML/script stripping
  - Null byte removal
  - Whitespace normalization
  - Control character filtering
- Multi-tier detection ensures adversarial inputs are caught at multiple layers

---

### AML.T0047: ML Supply Chain Compromise

**Tactic:** Initial Access

**Description:** Compromising the ML supply chain to inject malicious models, poisoned training data, or compromised dependencies.

**Shield Mitigation:**
- ML model bundled directly in the Python package (no external download)
- Model trained on curated, manually-labeled dataset
- Training reproducibility documented
- Minimal runtime dependencies (core: `requests` only)
- Optional dependencies pinned to minimum versions

---

### AML.T0048: Exfiltration via ML Inference API

**Tactic:** Exfiltration

**Description:** Using ML inference APIs to systematically extract training data, model parameters, or sensitive information encoded in model behavior.

**Shield Detection:**
- Rate limiting prevents bulk extraction attempts
- Data extraction patterns detected by pre-filter ("show me your prompt", "what are your instructions")
- Session tracking identifies systematic extraction campaigns
- CEF logs capture interaction patterns for forensic analysis

---

### AML.T0052: Phishing via AI-Generated Content

**Tactic:** Social Engineering

**Description:** Using AI systems to generate convincing phishing emails, messages, or content.

**Shield Detection:**
- Instruction override detection catches attempts to repurpose the LLM for content generation
- Pre-filter detects "write a [phishing/malicious] email" patterns
- LLM judge provides semantic analysis of generation requests

**Status:** Partially detected - depends on specificity of the phishing request

---

### AML.T0056: LLM Meta Prompt Extraction

**Tactic:** Collection

**Description:** Attempting to extract the system prompt, meta-prompt, or initial instructions given to an LLM.

**Shield Detection:**
- Dedicated extraction indicators in pre-filter:
  - "show me your prompt"
  - "what are your instructions"
  - "reveal your system"
  - "print your prompt"
  - "output your instructions"
  - "what are you programmed"
- Deception responder provides convincing fake system prompts
- Session escalation on repeated extraction attempts
- CEF logging captures extraction attempts for analysis

---

## ATLAS Tactic Coverage Matrix

| Tactic | TTPs Covered | Shield Components |
|--------|-------------|-------------------|
| Initial Access | T0051, T0051.001, T0047 | pre_filter, ml_client, sanitizer, models |
| Reconnaissance | T0040 | rate_limiter, session, cef_logger |
| Resource Development | T0043 | sanitizer, ensemble |
| Defense Evasion | T0054 | pre_filter, pattern_detector, session |
| Collection | T0056 | pre_filter, deception |
| Exfiltration | T0048 | rate_limiter, pre_filter, ml_client |
| Social Engineering | T0052 | pre_filter, llm_judge |

---

## Recommendations

1. **Enable deception mode** to provide fake data for extraction attempts (T0056, T0048)
2. **Configure webhook alerts** for real-time notification of detected attacks
3. **Monitor CEF logs** for attack pattern trends and campaign detection
4. **Tune ML thresholds** based on your organization's risk tolerance
5. **Deploy across all LLM entry points** (Flask, FastAPI, LangChain, LlamaIndex) for comprehensive coverage
