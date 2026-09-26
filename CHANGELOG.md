# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed
- MITRE ATLAS mapping: `DETECTION_TO_MITRE` and `MITRE_ATLAS_TECHNIQUES` used bare IDs
  (e.g. `T0030`, `T0070`) that aren't valid ATLAS technique IDs, and several names didn't
  match ATLAS. Detections now map to real ATLAS v2026.06 IDs in the `AML.T####` form
  (e.g. prompt injection -> `AML.T0051.000` LLM Prompt Injection: Direct). This changes
  the `mitre_atlas` values emitted in `threat_mapping`.
- `exploitation` detections are no longer mapped to an ATLAS technique (no accurate match).

### Added
- Vendored ATLAS v2026.06 technique ID list (`oubliette_shield/data/atlas_techniques.json`)
  with `load_atlas_catalog()` / `atlas_technique_name()` helpers and `ATLAS_VERSION`.
- `tests/test_atlas_ids.py` validates every emitted ATLAS ID against the vendored list.

## [0.1.0] - 2026-02-08

### Added
- 4-tier detection pipeline: input sanitization, pre-filter, ML classifier, LLM judge
- 7 LLM provider adapters: Ollama, OpenAI, Anthropic, Azure OpenAI, AWS Bedrock, Google Vertex AI, Google Gemini
- Multi-turn session tracking with attack pattern escalation
- Flask Blueprint integration (`/analyze`, `/health`, `/sessions`, `/dashboard`)
- CEF/SIEM logging in ArcSight Common Event Format
- Rate limiting per IP address
- Input sanitization for 9 attack surface types (HTML, script tags, markdown injection, CSV formulas, CDATA, event handlers, etc.)
- Pre-filter pattern matching for instruction override, persona override, DAN/jailbreak, prompt extraction, logic traps, hypothetical framing, and context switching
- ML classifier using TF-IDF + LogisticRegression (~2ms inference)
- Typed package with `py.typed` marker
- Apache 2.0 license

[0.1.0]: https://github.com/oubliettesecurity/oubliette-shield/releases/tag/v0.1.0
