# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
