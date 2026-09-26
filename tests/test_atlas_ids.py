"""Validate every MITRE ATLAS ID Shield emits against the vendored ATLAS release.

The catalog in ``oubliette_shield/data/atlas_techniques.json`` is a small,
IDs-and-names-only extract of the official ATLAS data release named by
``oubliette_shield.frameworks.ATLAS_VERSION``. If ATLAS renames or retires a
technique, regenerate that file from the release YAML and fix the mappings
until this module passes.
"""

from __future__ import annotations

import json
import re
from importlib import resources
from pathlib import Path

import pytest

from oubliette_shield import frameworks

REPO_ROOT = Path(__file__).resolve().parent.parent
ATLAS_ID_RE = re.compile(r"^AML\.T\d{4}(\.\d{3})?$")
# Bare ATLAS-style technique IDs ("T0030") without the AML. prefix. These were
# the pre-2026 invalid/mismatched codes; none should remain in shipped code.
BARE_TECHNIQUE_RE = re.compile(r"(?<![\w.])T0\d{3}(?:\.\d{3})?\b")


def _catalog() -> dict[str, str]:
    return frameworks.load_atlas_catalog()


def _emitted_ids() -> set[str]:
    ids: set[str] = set()
    for tids in frameworks.DETECTION_TO_MITRE.values():
        ids.update(tids)
    ids.update(frameworks.MITRE_ATLAS_TECHNIQUES)
    return ids


def test_vendored_catalog_metadata() -> None:
    raw = resources.files("oubliette_shield").joinpath("data/atlas_techniques.json")
    data = json.loads(raw.read_text(encoding="utf-8"))
    assert data["atlas_version"] == frameworks.ATLAS_VERSION
    assert data["source"].startswith("https://github.com/mitre-atlas/atlas-data/releases/")
    assert frameworks.ATLAS_VERSION in data["source"]
    techniques = data["techniques"]
    assert len(techniques) > 100
    assert all(ATLAS_ID_RE.match(tid) for tid in techniques), "malformed ID in catalog"
    assert all(isinstance(name, str) and name for name in techniques.values())


def test_catalog_has_no_known_bogus_ids() -> None:
    catalog = _catalog()
    for bogus in ("AML.T0030", "AML.T0120", "AML.T0122"):
        assert bogus not in catalog


@pytest.mark.parametrize("tid", sorted(_emitted_ids()))
def test_emitted_id_is_valid_atlas_id(tid: str) -> None:
    assert ATLAS_ID_RE.match(tid), f"{tid!r} is not in full ATLAS form (AML.T####[.###])"
    assert tid in _catalog(), f"{tid!r} is not a technique in ATLAS {frameworks.ATLAS_VERSION}"


def _expected_name(tid: str) -> str:
    catalog = _catalog()
    if "." in tid[len("AML.") :]:
        parent = tid.rsplit(".", 1)[0]
        return f"{catalog[parent]}: {catalog[tid]}"
    return catalog[tid]


@pytest.mark.parametrize("tid", sorted(frameworks.MITRE_ATLAS_TECHNIQUES))
def test_technique_names_match_atlas(tid: str) -> None:
    assert frameworks.MITRE_ATLAS_TECHNIQUES[tid]["name"] == _expected_name(tid)


def test_every_mapped_id_is_named() -> None:
    for tids in frameworks.DETECTION_TO_MITRE.values():
        for tid in tids:
            assert tid in frameworks.MITRE_ATLAS_TECHNIQUES


def test_atlas_technique_name_falls_back_to_catalog() -> None:
    assert frameworks.atlas_technique_name("AML.T0024.000") == "Infer Training Data Membership"
    assert frameworks.atlas_technique_name("AML.T9999") == "AML.T9999"


def test_build_threat_mapping_emits_valid_ids() -> None:
    catalog = _catalog()
    samples = [
        frameworks.build_threat_mapping("pre_filter", llm_verdict="PRE_BLOCKED_DANGEROUS_PATTERN_X"),
        frameworks.build_threat_mapping("pre_filter", llm_verdict="PRE_BLOCKED_DAN_JAILBREAK_DAN_MODE"),
        frameworks.build_threat_mapping("ml_only", ml_result={"threat_type": "prompt_injection"}),
        frameworks.build_threat_mapping("pre_filter", llm_verdict="PRE_BLOCKED_PROMPT_EXTRACTION"),
    ]
    for mapping in samples:
        assert mapping["mitre_atlas"], mapping
        for tid in mapping["mitre_atlas"]:
            assert tid in catalog


def _shipped_sources() -> list[Path]:
    return sorted((REPO_ROOT / "oubliette_shield").rglob("*.py"))


def test_no_bare_or_unknown_atlas_ids_in_source() -> None:
    """Catch hard-coded IDs that bypass the mapping tables."""
    catalog = _catalog()
    problems = []
    for path in _shipped_sources():
        text = path.read_text(encoding="utf-8")
        for m in BARE_TECHNIQUE_RE.finditer(text):
            problems.append(f"{path.relative_to(REPO_ROOT)}: bare ID {m.group(0)}")
        for tid in re.findall(r"AML\.T\d{4}(?:\.\d{3})?", text):
            if tid not in catalog:
                problems.append(f"{path.relative_to(REPO_ROOT)}: unknown ID {tid}")
    assert not problems, "\n".join(problems)
