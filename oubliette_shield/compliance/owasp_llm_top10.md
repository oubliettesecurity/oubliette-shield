# Oubliette Shield - OWASP Top 10 for LLM Applications Mapping

## Overview

This document maps Oubliette Shield capabilities to the OWASP Top 10 for LLM Applications (2025 edition). Each risk is assessed for Shield's mitigation coverage and the specific components that address it.

## Coverage Summary

| Risk | Title | Shield Status |
|------|-------|---------------|
| LLM01 | Prompt Injection | Fully Mitigated |
| LLM02 | Insecure Output Handling | Partially Mitigated |
| LLM03 | Training Data Poisoning | Partially Mitigated |
| LLM04 | Model Denial of Service | Fully Mitigated |
| LLM05 | Supply Chain Vulnerabilities | Partially Mitigated |
| LLM06 | Sensitive Information Disclosure | Fully Mitigated |
| LLM07 | Insecure Plugin Design | Partially Mitigated |
| LLM08 | Excessive Agency | Partially Mitigated |
| LLM09 | Overreliance | Partially Mitigated |
| LLM10 | Model Theft | Partially Mitigated |

**Fully Mitigated:** 3/10 | **Partially Mitigated:** 7/10

---

## LLM01: Prompt Injection

**Risk:** Manipulating LLMs through crafted inputs, including direct injection ("ignore all instructions") and indirect injection (embedding malicious instructions in external data).

**Shield Mitigation: FULLY MITIGATED**

This is Oubliette Shield's core capability. The multi-tier detection pipeline provides defense in depth:

1. **Input Sanitization** (9 types): Unicode normalization, encoding attack detection, invisible character removal, HTML/script stripping, null byte removal, whitespace normalization, homoglyph detection, control character filtering, payload deobfuscation
2. **Pre-Filter** (pattern matching, ~10ms): Catches obvious injection patterns including instruction overrides, DAN jailbreaks, hypothetical framing, and critical keyword combinations
3. **ML Classifier** (LogisticRegression + TF-IDF, ~2ms): Trained on 1,365 labeled samples, F1=0.98, AUC=0.99
4. **LLM Judge** (pluggable backend): Disambiguates ambiguous cases using a security-tuned LLM
5. **Session Tracking**: Detects multi-turn injection campaigns across conversation turns

**Detection rate:** 85-90% across all tested attack categories

---

## LLM02: Insecure Output Handling

**Risk:** Insufficient validation of LLM-generated outputs leading to downstream vulnerabilities (XSS, SSRF, code execution).

**Shield Mitigation: PARTIALLY MITIGATED**

- Input sanitization removes code injection vectors before they reach the LLM
- Deception responder generates controlled fake outputs instead of passing through LLM responses
- Output-side filtering is application-specific and outside Shield's scope

**Recommendation:** Combine Shield with output sanitization in your application layer.

---

## LLM03: Training Data Poisoning

**Risk:** Manipulation of training data to introduce vulnerabilities, biases, or backdoors.

**Shield Mitigation: PARTIALLY MITIGATED**

- Shield's ML model is trained on a curated, manually-labeled dataset (553 benign, 812 malicious samples)
- Model integrity verified via 5-fold cross-validation (F1 mean=0.986, std=0.006)
- Bundled model (`.pkl` files) prevents runtime model substitution
- Model provenance documented in training logs

**Recommendation:** Periodically retrain with updated attack samples.

---

## LLM04: Model Denial of Service

**Risk:** Resource-consuming interactions that degrade service quality or availability.

**Shield Mitigation: FULLY MITIGATED**

- **Rate Limiter:** Configurable per-IP rate limits (default: 30 requests/minute)
- **Pre-Filter Fast Path:** Obvious attacks blocked in ~10ms, avoiding expensive LLM calls (1,550x speedup)
- **Session Tracking:** Rapid escalation detection (3+ threats in 5 messages triggers escalation)
- **Input Length Limits:** Messages capped at 10,000 characters
- **Tiered Processing:** Only ambiguous cases reach the LLM judge, protecting compute resources

---

## LLM05: Supply Chain Vulnerabilities

**Risk:** Compromised components, pre-trained models, or data pipelines.

**Shield Mitigation: PARTIALLY MITIGATED**

- Core dependency is minimal: only `requests` required
- ML model is bundled in the package, eliminating external model download
- All optional dependencies pinned to minimum versions
- Open-source codebase enables community review

**Recommendation:** Use hash verification for the bundled model files. Pin all transitive dependencies in production.

---

## LLM06: Sensitive Information Disclosure

**Risk:** LLMs inadvertently revealing confidential data through their responses.

**Shield Mitigation: FULLY MITIGATED**

- **Pre-Filter:** Detects system prompt extraction attempts ("show me your prompt", "what are your instructions")
- **ML Classifier:** Trained to detect data extraction patterns
- **Deception Responder:** Provides convincing but fake credentials, system prompts, and configuration data
- **Session Tracking:** Escalates sessions with repeated extraction attempts (threshold: 2 attempts)
- **Input Sanitization:** Removes encoded extraction payloads

---

## LLM07: Insecure Plugin Design

**Risk:** LLM plugins operating without proper access controls or input validation.

**Shield Mitigation: PARTIALLY MITIGATED**

- **FastAPI Middleware:** Intercepts requests before they reach plugins/tools
- **LangChain Integration:** Callback handler analyzes prompts before LLM + tool execution
- **LlamaIndex Integration:** Query transform validates inputs before retrieval pipeline

**Recommendation:** Deploy Shield as the first layer in your plugin execution pipeline.

---

## LLM08: Excessive Agency

**Risk:** LLM systems executing actions beyond intended scope due to overly broad permissions.

**Shield Mitigation: PARTIALLY MITIGATED**

- Shield blocks malicious inputs before they can trigger unintended actions
- Configurable modes: block (prevent execution), log-only (monitor without blocking), deception (active intelligence gathering)
- SAFE_REVIEW verdict flags ambiguous cases for human decision

**Recommendation:** Combine Shield with application-level permission controls and action allowlists.

---

## LLM09: Overreliance

**Risk:** Excessive dependence on LLM outputs without adequate verification.

**Shield Mitigation: PARTIALLY MITIGATED**

- Shield provides an independent verification layer separate from the LLM
- SAFE_REVIEW verdict explicitly flags cases requiring human review
- Dashboard provides real-time operational visibility
- Webhook alerts enable human-in-the-loop for critical decisions

**Recommendation:** Use Shield's SAFE_REVIEW verdict to implement human review workflows.

---

## LLM10: Model Theft

**Risk:** Unauthorized access to, copying of, or extraction of proprietary LLM models.

**Shield Mitigation: PARTIALLY MITIGATED**

- API key authentication prevents unauthorized API access
- Rate limiting prevents systematic model probing/extraction
- CEF logging detects and documents probing attempts
- Session tracking identifies systematic extraction campaigns

**Recommendation:** Combine Shield with network-level access controls and model watermarking.

---

## Integration Recommendations

For maximum OWASP LLM Top 10 coverage:

1. Deploy Shield as the primary input filter (LLM01, LLM04, LLM06)
2. Enable deception mode for intelligence gathering (LLM01, LLM06)
3. Configure webhook alerts for security team notifications (LLM01, LLM04)
4. Use SAFE_REVIEW verdicts for human-in-the-loop decisions (LLM08, LLM09)
5. Implement output sanitization in your application layer (LLM02)
6. Pin dependencies and verify model integrity (LLM03, LLM05)
