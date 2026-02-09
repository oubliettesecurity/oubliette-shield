"""
Oubliette Shield - ML Anomaly Detection Client
Supports local inference (default) and external API backends.
"""

import datetime

import requests

from . import config


class MLClient:
    """
    Client for ML-based scoring.

    Supports two backends:
    - "local" (default): Bundled scikit-learn model, no external service needed
    - "api": External Anomaly Detection API

    The backend is selected via SHIELD_ML_BACKEND env var or the backend parameter.
    """

    def __init__(self, api_url=None, timeout=None, backend=None):
        self.backend = backend or config.ML_BACKEND
        self.api_url = api_url or config.ANOMALY_API_URL
        self.timeout = timeout or config.ANOMALY_API_TIMEOUT
        self._local_client = None

    def _get_local_client(self):
        if self._local_client is None:
            try:
                from .models.local_inference import LocalMLClient
                self._local_client = LocalMLClient()
            except Exception as e:
                print(f"[SHIELD-ML] Failed to load local model: {e}")
                self._local_client = False  # Sentinel: don't retry
        return self._local_client

    def score(self, user_input, session, source_ip):
        """
        Get ML anomaly score for a user message.

        Args:
            user_input: The user's message text
            session: Session state dict with 'interactions' list
            source_ip: Client IP address

        Returns:
            dict with score/threat_type/severity/processing_time_ms, or None on failure
        """
        # Use local model if configured
        if self.backend == "local":
            local = self._get_local_client()
            if local:
                return local.score(user_input, session, source_ip)
            # Fall through to API if local model failed to load
            print("[SHIELD-ML] Local model unavailable, falling back to API")

        if not self.api_url:
            return None

        try:
            context_events = session.get("interactions", [])[-20:]

            suspicious_keywords = [
                "password", "secret", "admin", "ignore", "instructions",
                "system prompt", "credentials", "token", "api key",
            ]
            action = "failed" if any(kw in user_input.lower() for kw in suspicious_keywords) else "success"

            current_event = {
                "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "user": "chat_user",
                "source_ip": source_ip,
                "dest_ip": "oubliette_server",
                "event_type": "chat",
                "action": action,
                "message": user_input,
                "severity": "low",
            }

            all_events = context_events + [current_event]

            response = requests.post(
                f"{self.api_url}/analyze",
                json={"logs": all_events, "return_all_events": False},
                timeout=self.timeout,
            )

            if response.status_code != 200:
                return None

            data = response.json()

            if data.get("anomalies_detected", 0) > 0:
                for anomaly in data.get("anomalies", []):
                    if anomaly.get("message") == user_input:
                        return {
                            "score": anomaly.get("anomaly_score", 0.0),
                            "threat_type": anomaly.get("threat_type", "unknown"),
                            "severity": anomaly.get("severity", "low"),
                            "processing_time_ms": data.get("processing_time_ms", 0.0),
                        }

            return {
                "score": 0.0,
                "threat_type": "none",
                "severity": "low",
                "processing_time_ms": data.get("processing_time_ms", 0.0),
            }

        except requests.exceptions.Timeout:
            print(f"[SHIELD-ML] API timeout after {self.timeout}s")
            return None
        except Exception as e:
            print(f"[SHIELD-ML] API error: {e}")
            return None
