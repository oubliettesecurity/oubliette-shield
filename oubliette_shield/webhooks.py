"""
Oubliette Shield - Webhook Alerting
Dispatches detection events to Slack, Teams, PagerDuty, and generic JSON endpoints.

Usage:
    from oubliette_shield.webhooks import WebhookManager

    manager = WebhookManager(urls=["https://hooks.slack.com/services/..."])
    manager.notify("malicious", {
        "verdict": "MALICIOUS",
        "session_id": "abc123",
        "detection_method": "pre_filter",
    })
"""

import os
import json
import time
import threading
import datetime

import requests


class WebhookManager:
    """
    Dispatches detection events to configured webhook URLs.

    Auto-detects the payload format from the URL:
    - slack.com -> Slack Block Kit
    - office.com / webhook.office -> Microsoft Teams Adaptive Card
    - pagerduty.com -> PagerDuty Events API v2
    - Everything else -> Generic JSON POST

    Args:
        urls: List of webhook URLs (or comma-separated string)
        events: Event types to dispatch (default: malicious, escalation)
        timeout: HTTP timeout in seconds (default: 5)
        max_retries: Max retry attempts on failure (default: 1)
    """

    def __init__(self, urls=None, events=None, timeout=5, max_retries=1):
        raw_urls = urls or os.getenv("SHIELD_WEBHOOK_URLS", "")
        if isinstance(raw_urls, str):
            self.urls = [u.strip() for u in raw_urls.split(",") if u.strip()]
        else:
            self.urls = list(raw_urls)

        raw_events = events or os.getenv("SHIELD_WEBHOOK_EVENTS", "malicious,escalation")
        if isinstance(raw_events, str):
            self.events = {e.strip() for e in raw_events.split(",") if e.strip()}
        else:
            self.events = set(raw_events)

        self.timeout = int(os.getenv("SHIELD_WEBHOOK_TIMEOUT", str(timeout)))
        self.max_retries = max_retries

    def notify(self, event_type, payload):
        """
        Dispatch an event to all configured webhook URLs.

        Args:
            event_type: Event type string (e.g., "malicious", "escalation")
            payload: dict with event data
        """
        if not self.urls:
            return

        if event_type not in self.events:
            return

        for url in self.urls:
            thread = threading.Thread(
                target=self._dispatch,
                args=(url, event_type, payload),
                daemon=True,
            )
            thread.start()

    def _dispatch(self, url, event_type, payload):
        """Send webhook notification with retry."""
        formatted = self._format_payload(url, event_type, payload)

        for attempt in range(1 + self.max_retries):
            try:
                response = requests.post(
                    url,
                    json=formatted,
                    timeout=self.timeout,
                    headers={"Content-Type": "application/json"},
                )
                if response.status_code < 300:
                    return
                print(
                    f"[SHIELD-WEBHOOK] {url}: HTTP {response.status_code} "
                    f"(attempt {attempt + 1})"
                )
            except requests.exceptions.Timeout:
                print(f"[SHIELD-WEBHOOK] {url}: timeout (attempt {attempt + 1})")
            except Exception as e:
                print(f"[SHIELD-WEBHOOK] {url}: error: {e} (attempt {attempt + 1})")

            if attempt < self.max_retries:
                time.sleep(2 ** attempt)  # Exponential backoff

    def _format_payload(self, url, event_type, payload):
        """Auto-detect format from URL and build appropriate payload."""
        url_lower = url.lower()
        if "hooks.slack.com" in url_lower or "slack.com" in url_lower:
            return self._format_slack(event_type, payload)
        elif "office.com" in url_lower or "webhook.office" in url_lower:
            return self._format_teams(event_type, payload)
        elif "pagerduty.com" in url_lower:
            return self._format_pagerduty(event_type, payload)
        else:
            return self._format_generic(event_type, payload)

    def _format_slack(self, event_type, payload):
        """Format as Slack Block Kit message."""
        verdict = payload.get("verdict", "UNKNOWN")
        session_id = payload.get("session_id", "")[:8]
        method = payload.get("detection_method", "unknown")
        ml_score = payload.get("ml_score")
        timestamp = payload.get("timestamp") or datetime.datetime.now().isoformat()

        emoji = ":rotating_light:" if verdict == "MALICIOUS" else ":warning:"
        color = "#dc3545" if verdict == "MALICIOUS" else "#ffc107"

        blocks = [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": f"{emoji} Oubliette Shield Alert",
                },
            },
            {
                "type": "section",
                "fields": [
                    {"type": "mrkdwn", "text": f"*Event:* {event_type}"},
                    {"type": "mrkdwn", "text": f"*Verdict:* {verdict}"},
                    {"type": "mrkdwn", "text": f"*Method:* {method}"},
                    {"type": "mrkdwn", "text": f"*Session:* {session_id}..."},
                ],
            },
        ]

        if ml_score is not None:
            blocks.append({
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"*ML Score:* {ml_score:.2f}",
                },
            })

        user_input = payload.get("user_input", "")
        if user_input:
            truncated = user_input[:200]
            blocks.append({
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"*Input:* ```{truncated}```",
                },
            })

        blocks.append({
            "type": "context",
            "elements": [
                {"type": "mrkdwn", "text": f"Timestamp: {timestamp}"},
            ],
        })

        return {"blocks": blocks}

    def _format_teams(self, event_type, payload):
        """Format as Microsoft Teams Adaptive Card."""
        verdict = payload.get("verdict", "UNKNOWN")
        session_id = payload.get("session_id", "")[:8]
        method = payload.get("detection_method", "unknown")
        ml_score = payload.get("ml_score")
        user_input = payload.get("user_input", "")[:200]

        card = {
            "type": "message",
            "attachments": [
                {
                    "contentType": "application/vnd.microsoft.card.adaptive",
                    "content": {
                        "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
                        "type": "AdaptiveCard",
                        "version": "1.4",
                        "body": [
                            {
                                "type": "TextBlock",
                                "text": "Oubliette Shield Alert",
                                "weight": "bolder",
                                "size": "large",
                                "color": "attention",
                            },
                            {
                                "type": "FactSet",
                                "facts": [
                                    {"title": "Event", "value": event_type},
                                    {"title": "Verdict", "value": verdict},
                                    {"title": "Method", "value": method},
                                    {"title": "Session", "value": f"{session_id}..."},
                                ],
                            },
                        ],
                    },
                }
            ],
        }

        body = card["attachments"][0]["content"]["body"]

        if ml_score is not None:
            body[1]["facts"].append(
                {"title": "ML Score", "value": f"{ml_score:.2f}"}
            )

        if user_input:
            body.append({
                "type": "TextBlock",
                "text": f"Input: {user_input}",
                "wrap": True,
                "size": "small",
            })

        return card

    def _format_pagerduty(self, event_type, payload):
        """Format as PagerDuty Events API v2 payload."""
        verdict = payload.get("verdict", "UNKNOWN")
        session_id = payload.get("session_id", "default")
        method = payload.get("detection_method", "unknown")

        severity = "critical" if verdict == "MALICIOUS" else "warning"

        return {
            "routing_key": os.getenv("PAGERDUTY_ROUTING_KEY", ""),
            "event_action": "trigger",
            "dedup_key": f"oubliette-{session_id}-{event_type}",
            "payload": {
                "summary": f"Oubliette Shield: {event_type} - {verdict}",
                "source": "oubliette-shield",
                "severity": severity,
                "component": "llm-firewall",
                "custom_details": {
                    "verdict": verdict,
                    "detection_method": method,
                    "session_id": session_id,
                    "ml_score": payload.get("ml_score"),
                    "user_input": payload.get("user_input", "")[:200],
                },
            },
        }

    def _format_generic(self, event_type, payload):
        """Format as generic JSON payload."""
        return {
            "source": "oubliette-shield",
            "event_type": event_type,
            "timestamp": datetime.datetime.now().isoformat(),
            "data": payload,
        }
