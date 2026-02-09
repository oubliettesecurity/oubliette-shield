"""
Oubliette Shield - Local ML Inference
Bundled LogisticRegression + TF-IDF model for prompt injection detection.
Replaces external API dependency with ~2ms local inference.
"""

import os
import time
import pathlib


_MODEL_DIR = pathlib.Path(__file__).parent

# Lazy-loaded singletons
_classifier = None
_pipeline = None
_load_error = None


def _load_models():
    """Load bundled model files on first use."""
    global _classifier, _pipeline, _load_error
    if _classifier is not None:
        return
    if _load_error is not None:
        return

    try:
        import joblib
    except ImportError:
        _load_error = (
            "joblib package required for local ML inference. "
            "Install with: pip install oubliette-shield[ml]"
        )
        return

    classifier_path = _MODEL_DIR / "chat_classifier.pkl"
    pipeline_path = _MODEL_DIR / "chat_feature_pipeline.pkl"

    if not classifier_path.exists():
        _load_error = f"Model file not found: {classifier_path}"
        return
    if not pipeline_path.exists():
        _load_error = f"Pipeline file not found: {pipeline_path}"
        return

    try:
        # Register the bundled pipeline module under the original pickle module name
        # so joblib can unpickle the ChatFeaturePipeline class
        import sys
        from . import chat_feature_pipeline as _cfp_module
        if "chat_feature_pipeline" not in sys.modules:
            sys.modules["chat_feature_pipeline"] = _cfp_module

        _classifier = joblib.load(classifier_path)
        _pipeline = joblib.load(pipeline_path)
    except Exception as e:
        _load_error = f"Failed to load ML models: {e}"


def _extract_features(text):
    """Extract structural features matching the training pipeline."""
    text_lower = text.lower()
    features = {}

    # Structural features
    features["length"] = len(text)
    features["word_count"] = len(text.split())
    features["special_char_ratio"] = (
        sum(1 for c in text if not c.isalnum() and not c.isspace()) / max(len(text), 1)
    )
    features["uppercase_ratio"] = (
        sum(1 for c in text if c.isupper()) / max(len(text), 1)
    )
    features["has_code_block"] = 1 if "```" in text else 0
    features["line_count"] = text.count("\n") + 1
    features["avg_word_length"] = (
        sum(len(w) for w in text.split()) / max(len(text.split()), 1)
    )

    # Keyword presence features
    injection_keywords = [
        "ignore", "instructions", "password", "secret", "admin",
        "system prompt", "bypass", "override", "jailbreak", "dan",
        "pretend", "roleplay", "hypothetically", "fictional",
        "unrestricted", "no restrictions", "forget everything",
    ]
    for kw in injection_keywords:
        features[f"kw_{kw.replace(' ', '_')}"] = 1 if kw in text_lower else 0

    # Pattern features
    features["has_instruction_override"] = 1 if any(
        p in text_lower for p in [
            "ignore all previous", "forget everything",
            "disregard all", "new instructions",
        ]
    ) else 0
    features["has_persona_attack"] = 1 if any(
        p in text_lower for p in [
            "you are now", "pretend you are", "act as", "roleplay as",
        ]
    ) else 0
    features["has_extraction_attempt"] = 1 if any(
        p in text_lower for p in [
            "show me your prompt", "what are your instructions",
            "reveal your system", "print your prompt",
        ]
    ) else 0

    return features


def _severity_from_score(score):
    """Map anomaly score to severity label."""
    if score >= 0.9:
        return "critical"
    elif score >= 0.7:
        return "high"
    elif score >= 0.5:
        return "medium"
    elif score >= 0.3:
        return "low"
    return "none"


def _threat_type_from_text(text):
    """Infer threat type from input text."""
    text_lower = text.lower()
    if any(p in text_lower for p in ["ignore", "forget", "disregard", "override"]):
        return "instruction_override"
    if any(p in text_lower for p in ["you are now", "pretend", "roleplay", "act as"]):
        return "persona_manipulation"
    if any(p in text_lower for p in ["password", "secret", "credential", "system prompt"]):
        return "data_extraction"
    if any(p in text_lower for p in ["jailbreak", "dan", "unrestricted", "no restrictions"]):
        return "jailbreak"
    if any(p in text_lower for p in ["hypothetically", "fictional", "in a story"]):
        return "hypothetical_framing"
    return "prompt_injection"


class LocalMLClient:
    """
    Local ML inference client using bundled scikit-learn model.
    Drop-in replacement for MLClient with same score() interface.

    The model is loaded lazily on first score() call (~50ms load, ~2ms inference).
    """

    def __init__(self):
        self._loaded = False

    def _ensure_loaded(self):
        if not self._loaded:
            _load_models()
            self._loaded = True

    def score(self, user_input, session=None, source_ip=None):
        """
        Score a user message for prompt injection probability.

        Args:
            user_input: The user's message text
            session: Session state dict (unused for local model, kept for API compat)
            source_ip: Client IP (unused for local model, kept for API compat)

        Returns:
            dict with score, threat_type, severity, processing_time_ms
            or None if model cannot be loaded
        """
        self._ensure_loaded()

        if _load_error:
            print(f"[SHIELD-ML-LOCAL] {_load_error}")
            return None

        start = time.perf_counter()

        try:
            # Use the pipeline to transform input
            features = _pipeline.transform([user_input])
            proba = _classifier.predict_proba(features)
            # Class 1 = malicious probability
            score = float(proba[0][1]) if proba.shape[1] > 1 else float(proba[0][0])

            elapsed_ms = (time.perf_counter() - start) * 1000

            return {
                "score": round(score, 4),
                "threat_type": _threat_type_from_text(user_input) if score > 0.3 else "none",
                "severity": _severity_from_score(score),
                "processing_time_ms": round(elapsed_ms, 2),
            }
        except Exception as e:
            print(f"[SHIELD-ML-LOCAL] Inference error: {e}")
            return None
