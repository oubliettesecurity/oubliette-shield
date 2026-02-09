"""
Oubliette Shield - Session Manager
Thread-safe session state tracking with multi-turn attack detection.
"""

import datetime
import time
import threading

from . import config
from .pattern_detector import detect_attack_patterns


class SessionManager:
    """
    Manages session state for multi-turn attack detection.
    Thread-safe with RLock. Supports pluggable storage backends.
    """

    def __init__(self, ttl=None, max_count=None, cleanup_interval=None, storage=None):
        self.ttl = ttl or config.SESSION_TTL_SECONDS
        self.max_count = max_count or config.SESSION_MAX_COUNT
        self.cleanup_interval = cleanup_interval or config.SESSION_CLEANUP_INTERVAL
        self._cleanup_thread = None

        if storage is not None:
            self.storage = storage
        else:
            backend = getattr(config, "STORAGE_BACKEND", "memory")
            if backend == "sqlite":
                from .storage import SQLiteStorage
                db_path = getattr(config, "DB_PATH", "oubliette_shield.db")
                self.storage = SQLiteStorage(db_path=db_path)
            else:
                from .storage import MemoryStorage
                self.storage = MemoryStorage()

        # Keep backward-compat internal dict reference for direct dict access
        self._sessions = {}
        self._lock = threading.RLock()

    def start_cleanup(self):
        """Start background session cleanup thread."""
        if self._cleanup_thread is not None:
            return
        self._cleanup_thread = threading.Thread(target=self._cleanup_loop, daemon=True)
        self._cleanup_thread.start()

    def _cleanup_loop(self):
        while True:
            time.sleep(self.cleanup_interval)
            self.cleanup_expired()

    def cleanup_expired(self):
        """Remove expired sessions."""
        removed = self.storage.cleanup_expired(self.ttl)
        if removed:
            print(f"[SHIELD-SESSION] Cleaned up {removed} expired. Active: {self.storage.count_active()}")

    def get(self, session_id):
        """Get session state (read-only copy)."""
        return self.storage.get_session(session_id)

    def get_all(self):
        """Get all sessions (read-only snapshot)."""
        return self.storage.list_sessions()

    @property
    def active_count(self):
        return self.storage.count_active()

    @property
    def escalated_count(self):
        return self.storage.count_escalated()

    def update(self, session_id, user_input, verdict, ml_result, source_ip, sanitizations=None):
        """
        Update session state with a new interaction.

        Returns:
            dict: Updated session state
        """
        now = datetime.datetime.now()
        return self._update_impl(
            session_id, user_input, verdict, ml_result, source_ip, now, sanitizations
        )

    def _update_impl(self, session_id, user_input, verdict, ml_result, source_ip, now, sanitizations=None):
        """Update session and persist to storage."""
        session = self.storage.get_session(session_id)

        if not session:
            if self.storage.session_count() >= self.max_count:
                return {}
            session = {
                "interactions": [],
                "cumulative_risk_score": 0.0,
                "threat_count": 0,
                "safe_count": 0,
                "escalated": False,
                "created_at": now,
                "last_activity": now,
                "source_ip": source_ip,
                "instruction_override_attempts": 0,
                "context_switch_attempts": 0,
                "persona_override_attempts": 0,
                "hypothetical_framing_count": 0,
                "dan_jailbreak_attempts": 0,
                "logic_trap_attempts": 0,
                "rapid_escalation_detected": False,
                "attack_patterns": [],
                "sanitization_events": 0,
                "sanitization_types": [],
            }

        # Detect multi-turn attack patterns
        attack_patterns_detected = detect_attack_patterns(user_input, session)

        for pattern in attack_patterns_detected:
            if pattern not in session["attack_patterns"]:
                session["attack_patterns"].append(pattern)

            counter_map = {
                "instruction_override": "instruction_override_attempts",
                "context_switch": "context_switch_attempts",
                "persona_override": "persona_override_attempts",
                "hypothetical_framing": "hypothetical_framing_count",
                "dan_jailbreak": "dan_jailbreak_attempts",
                "logic_trap": "logic_trap_attempts",
            }
            if pattern in counter_map:
                session[counter_map[pattern]] += 1

        # Track sanitization events
        if sanitizations:
            session["sanitization_events"] += 1
            for san_type in sanitizations:
                if san_type not in session["sanitization_types"]:
                    session["sanitization_types"].append(san_type)

        # Append interaction
        log_event = {
            "timestamp": now.strftime("%Y-%m-%d %H:%M:%S"),
            "user": "chat_user",
            "source_ip": source_ip,
            "dest_ip": "oubliette_server",
            "event_type": "chat",
            "action": "success" if verdict == "SAFE" else "failed",
            "message": user_input,
            "severity": ml_result.get("severity", "low") if ml_result else "low",
            "attack_patterns": attack_patterns_detected,
        }
        session["interactions"].append(log_event)

        # Update counters
        if verdict in ("MALICIOUS", "SAFE_REVIEW"):
            session["threat_count"] += 1
        else:
            session["safe_count"] += 1

        # Accumulate risk
        if ml_result:
            session["cumulative_risk_score"] += ml_result.get("score", 0.0)

        # Rapid escalation detection
        if len(session["interactions"]) >= 2:
            recent = session["interactions"][-5:]
            recent_threats = sum(1 for i in recent if i.get("action") == "failed")
            if recent_threats >= 3:
                session["rapid_escalation_detected"] = True

        # Escalation check
        escalation_reasons = []

        if session["threat_count"] >= config.SESSION_MAX_THREATS:
            escalation_reasons.append(f"threat_count={session['threat_count']}")
        if session["cumulative_risk_score"] >= config.SESSION_RISK_ESCALATION:
            escalation_reasons.append(f"cumulative_risk={session['cumulative_risk_score']:.2f}")
        if session["instruction_override_attempts"] >= 2:
            escalation_reasons.append(f"instruction_overrides={session['instruction_override_attempts']}")
        if session["persona_override_attempts"] >= 2:
            escalation_reasons.append(f"persona_overrides={session['persona_override_attempts']}")
        if session["hypothetical_framing_count"] >= 2:
            escalation_reasons.append(f"hypothetical_attacks={session['hypothetical_framing_count']}")
        if session["dan_jailbreak_attempts"] >= 1:
            escalation_reasons.append(f"dan_jailbreak={session['dan_jailbreak_attempts']}")
        if session["logic_trap_attempts"] >= 1:
            escalation_reasons.append(f"logic_traps={session['logic_trap_attempts']}")
        if session["rapid_escalation_detected"]:
            escalation_reasons.append("rapid_escalation")
        if len(session["attack_patterns"]) >= 3:
            escalation_reasons.append(f"diverse_attacks={len(session['attack_patterns'])}")

        if escalation_reasons:
            session["escalated"] = True
            session["escalation_reason"] = "; ".join(escalation_reasons)
            print(f"[SHIELD-SESSION] Session {session_id[:8]} escalated: {session['escalation_reason']}")

        session["last_activity"] = now

        # Persist to storage backend
        self.storage.put_session(session_id, session)

        return dict(session)
