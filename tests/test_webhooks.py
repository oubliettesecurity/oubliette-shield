"""Tests for webhook alerting module."""

import pytest
from unittest.mock import patch, MagicMock

from oubliette_shield.webhooks import WebhookManager


class TestWebhookManager:
    """Tests for webhook dispatch and formatting."""

    def test_no_urls_no_dispatch(self):
        """No URLs configured means no dispatching."""
        manager = WebhookManager(urls=[])
        # Should not raise
        manager.notify("malicious", {"verdict": "MALICIOUS"})

    def test_event_filtering(self):
        """Only configured events are dispatched."""
        manager = WebhookManager(
            urls=["https://example.com/webhook"],
            events=["malicious"],
        )
        with patch.object(manager, "_dispatch") as mock_dispatch:
            manager.notify("safe", {"verdict": "SAFE"})
            mock_dispatch.assert_not_called()

    @patch("oubliette_shield.webhooks.requests.post")
    def test_notify_sends_post(self, mock_post):
        """Notify dispatches HTTP POST to configured URLs."""
        mock_post.return_value = MagicMock(status_code=200)
        manager = WebhookManager(
            urls=["https://example.com/webhook"],
            events=["malicious"],
        )
        # Call _dispatch directly to avoid threading
        manager._dispatch(
            "https://example.com/webhook",
            "malicious",
            {"verdict": "MALICIOUS"},
        )
        mock_post.assert_called_once()
        call_kwargs = mock_post.call_args
        assert call_kwargs[0][0] == "https://example.com/webhook"

    def test_slack_format(self):
        """Slack payload has blocks structure."""
        manager = WebhookManager(urls=["https://hooks.slack.com/services/xxx"])
        payload = manager._format_payload(
            "https://hooks.slack.com/services/xxx",
            "malicious",
            {"verdict": "MALICIOUS", "session_id": "test123", "detection_method": "pre_filter"},
        )
        assert "blocks" in payload
        assert isinstance(payload["blocks"], list)
        assert len(payload["blocks"]) >= 2

    def test_teams_format(self):
        """Teams payload has Adaptive Card structure."""
        manager = WebhookManager(urls=["https://outlook.office.com/webhook/xxx"])
        payload = manager._format_payload(
            "https://outlook.office.com/webhook/xxx",
            "malicious",
            {"verdict": "MALICIOUS", "session_id": "test123", "detection_method": "ml_only"},
        )
        assert "attachments" in payload
        card = payload["attachments"][0]["content"]
        assert card["type"] == "AdaptiveCard"
        assert "body" in card

    def test_pagerduty_format(self):
        """PagerDuty payload has Events API v2 structure."""
        manager = WebhookManager(urls=["https://events.pagerduty.com/v2/enqueue"])
        payload = manager._format_payload(
            "https://events.pagerduty.com/v2/enqueue",
            "malicious",
            {"verdict": "MALICIOUS", "session_id": "test123", "detection_method": "ensemble"},
        )
        assert "event_action" in payload
        assert payload["event_action"] == "trigger"
        assert "payload" in payload
        assert payload["payload"]["severity"] == "critical"

    def test_generic_format(self):
        """Generic payload wraps data with source and timestamp."""
        manager = WebhookManager(urls=["https://example.com/api/events"])
        payload = manager._format_payload(
            "https://example.com/api/events",
            "malicious",
            {"verdict": "MALICIOUS"},
        )
        assert payload["source"] == "oubliette-shield"
        assert payload["event_type"] == "malicious"
        assert "timestamp" in payload
        assert "data" in payload

    @patch("oubliette_shield.webhooks.requests.post")
    def test_timeout_handling(self, mock_post):
        """Timeouts are handled gracefully."""
        import requests
        mock_post.side_effect = requests.exceptions.Timeout("timeout")
        manager = WebhookManager(
            urls=["https://example.com/webhook"],
            events=["malicious"],
            max_retries=0,
        )
        # Should not raise
        manager._dispatch(
            "https://example.com/webhook",
            "malicious",
            {"verdict": "MALICIOUS"},
        )

    def test_urls_from_string(self):
        """URLs can be provided as comma-separated string."""
        manager = WebhookManager(urls="https://a.com/hook,https://b.com/hook")
        assert len(manager.urls) == 2

    def test_events_from_string(self):
        """Events can be provided as comma-separated string."""
        manager = WebhookManager(urls=[], events="malicious,escalation,safe")
        assert "malicious" in manager.events
        assert "escalation" in manager.events
        assert "safe" in manager.events

    @patch("oubliette_shield.webhooks.requests.post")
    def test_retry_on_failure(self, mock_post):
        """Retries on HTTP error with exponential backoff."""
        mock_post.side_effect = [
            MagicMock(status_code=500),  # First attempt fails
            MagicMock(status_code=200),  # Retry succeeds
        ]
        manager = WebhookManager(
            urls=["https://example.com/webhook"],
            events=["malicious"],
            max_retries=1,
        )
        manager._dispatch(
            "https://example.com/webhook",
            "malicious",
            {"verdict": "MALICIOUS"},
        )
        assert mock_post.call_count == 2

    def test_slack_with_ml_score(self):
        """Slack format includes ML score when provided."""
        manager = WebhookManager(urls=[])
        payload = manager._format_slack("malicious", {
            "verdict": "MALICIOUS",
            "session_id": "test",
            "detection_method": "ml_only",
            "ml_score": 0.95,
        })
        # Should have a block with ML score
        blocks_text = str(payload["blocks"])
        assert "0.95" in blocks_text
