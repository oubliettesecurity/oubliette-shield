"""
Tests for Shield storage backends (Memory and SQLite).
Run: python -m pytest tests/test_shield_storage.py -v
"""

import os
import tempfile

import pytest

from oubliette_shield.storage import (
    MemoryBackend,
    SQLiteBackend,
    create_backend,
)
from oubliette_shield.session import SessionManager


# ============================================================
# MemoryBackend Tests
# ============================================================


class TestMemoryBackend:

    def test_save_and_load_session(self):
        b = MemoryBackend()
        b.save_session("s1", {"threat_count": 3, "escalated": True})
        s = b.load_session("s1")
        assert s["threat_count"] == 3
        assert s["escalated"] is True

    def test_load_missing_returns_none(self):
        b = MemoryBackend()
        assert b.load_session("missing") is None

    def test_delete_session(self):
        b = MemoryBackend()
        b.save_session("s1", {"x": 1})
        assert b.delete_session("s1") is True
        assert b.load_session("s1") is None
        assert b.delete_session("s1") is False

    def test_list_sessions(self):
        b = MemoryBackend()
        b.save_session("a", {"n": 1})
        b.save_session("b", {"n": 2})
        sessions = b.list_sessions()
        assert set(sessions.keys()) == {"a", "b"}

    def test_log_and_query_detections(self):
        b = MemoryBackend()
        b.log_detection({"verdict": "MALICIOUS", "session_id": "s1"})
        b.log_detection({"verdict": "SAFE", "session_id": "s1"})
        b.log_detection({"verdict": "MALICIOUS", "session_id": "s2"})

        all_events = b.query_detections()
        assert len(all_events) == 3

        mal = b.query_detections(verdict="MALICIOUS")
        assert len(mal) == 2

        s1 = b.query_detections(session_id="s1")
        assert len(s1) == 2

    def test_query_detections_limit(self):
        b = MemoryBackend()
        for i in range(20):
            b.log_detection({"verdict": "SAFE", "n": i})
        assert len(b.query_detections(limit=5)) == 5

    def test_save_and_query_iocs(self):
        b = MemoryBackend()
        b.save_ioc({"payload_hash": "abc123", "severity": "high"})
        iocs = b.query_iocs()
        assert len(iocs) == 1
        assert iocs[0]["severity"] == "high"

    def test_ioc_deduplication(self):
        b = MemoryBackend()
        b.save_ioc({"payload_hash": "abc", "severity": "high", "sighting_count": 1})
        b.save_ioc({"payload_hash": "abc", "severity": "high"})
        iocs = b.query_iocs()
        assert len(iocs) == 1
        assert iocs[0]["sighting_count"] == 2


# ============================================================
# SQLiteBackend Tests
# ============================================================


class TestSQLiteBackend:

    def _make_backend(self, tmp_path):
        db_path = os.path.join(tmp_path, "test.db")
        return SQLiteBackend(db_path), db_path

    def test_save_and_load_session(self, tmp_path):
        b, _ = self._make_backend(tmp_path)
        b.save_session("s1", {"threat_count": 5, "escalated": False})
        s = b.load_session("s1")
        assert s["threat_count"] == 5
        assert s["escalated"] is False

    def test_load_missing_returns_none(self, tmp_path):
        b, _ = self._make_backend(tmp_path)
        assert b.load_session("missing") is None

    def test_delete_session(self, tmp_path):
        b, _ = self._make_backend(tmp_path)
        b.save_session("s1", {"x": 1})
        assert b.delete_session("s1") is True
        assert b.load_session("s1") is None
        assert b.delete_session("s1") is False

    def test_list_sessions(self, tmp_path):
        b, _ = self._make_backend(tmp_path)
        b.save_session("a", {"n": 1})
        b.save_session("b", {"n": 2})
        sessions = b.list_sessions()
        assert set(sessions.keys()) == {"a", "b"}

    def test_session_update_overwrites(self, tmp_path):
        b, _ = self._make_backend(tmp_path)
        b.save_session("s1", {"v": 1})
        b.save_session("s1", {"v": 2})
        assert b.load_session("s1")["v"] == 2

    def test_persistence_across_restarts(self, tmp_path):
        """Create backend, write, close, reopen, read back."""
        db_path = os.path.join(tmp_path, "persist.db")
        b1 = SQLiteBackend(db_path)
        b1.save_session("s1", {"threat_count": 7})
        b1.log_detection({"verdict": "MALICIOUS", "session_id": "s1"})
        b1.save_ioc({"payload_hash": "hash1", "severity": "critical"})
        b1.close()

        b2 = SQLiteBackend(db_path)
        assert b2.load_session("s1")["threat_count"] == 7
        assert len(b2.query_detections(verdict="MALICIOUS")) == 1
        assert len(b2.query_iocs()) == 1
        b2.close()

    def test_log_and_query_detections(self, tmp_path):
        b, _ = self._make_backend(tmp_path)
        b.log_detection({"verdict": "MALICIOUS", "session_id": "s1", "ml_score": 0.95})
        b.log_detection({"verdict": "SAFE", "session_id": "s1"})

        all_events = b.query_detections()
        assert len(all_events) == 2

        mal = b.query_detections(verdict="MALICIOUS")
        assert len(mal) == 1
        assert mal[0]["ml_score"] == 0.95

    def test_save_and_query_iocs(self, tmp_path):
        b, _ = self._make_backend(tmp_path)
        b.save_ioc({"payload_hash": "h1", "severity": "high", "type": "injection"})
        iocs = b.query_iocs()
        assert len(iocs) == 1

    def test_ioc_deduplication(self, tmp_path):
        b, _ = self._make_backend(tmp_path)
        b.save_ioc({"payload_hash": "h1", "severity": "high"})
        b.save_ioc({"payload_hash": "h1", "severity": "high"})
        iocs = b.query_iocs()
        assert len(iocs) == 1


# ============================================================
# SessionManager + Storage Integration
# ============================================================


class TestSessionManagerWithStorage:

    def test_session_persisted_to_memory_backend(self):
        b = MemoryBackend()
        mgr = SessionManager(storage_backend=b)
        mgr.update("sess-1", "hello", "SAFE", None, "127.0.0.1")
        stored = b.load_session("sess-1")
        assert stored is not None
        assert stored["safe_count"] >= 1

    def test_session_rehydrated_from_backend(self):
        b = MemoryBackend()
        b.save_session("sess-1", {
            "interactions": [],
            "cumulative_risk_score": 1.5,
            "threat_count": 2,
            "safe_count": 0,
            "escalated": False,
            "source_ip": "10.0.0.1",
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
        })

        mgr = SessionManager(storage_backend=b)
        session = mgr.get("sess-1")
        assert session["threat_count"] == 2
        assert session["cumulative_risk_score"] == 1.5

    def test_no_backend_works_normally(self):
        mgr = SessionManager()
        mgr.update("sess-1", "hello", "SAFE", None, "127.0.0.1")
        session = mgr.get("sess-1")
        assert session["safe_count"] >= 1

    def test_sqlite_session_persistence(self, tmp_path):
        db_path = os.path.join(tmp_path, "session_test.db")
        b1 = SQLiteBackend(db_path)
        mgr1 = SessionManager(storage_backend=b1)
        mgr1.update("s1", "test input", "SAFE", None, "127.0.0.1")
        b1.close()

        b2 = SQLiteBackend(db_path)
        mgr2 = SessionManager(storage_backend=b2)
        session = mgr2.get("s1")
        assert session is not None
        assert session["safe_count"] >= 1
        b2.close()


# ============================================================
# create_backend Factory
# ============================================================


class TestCreateBackend:

    def test_default_is_memory(self):
        b = create_backend()
        assert isinstance(b, MemoryBackend)

    def test_explicit_memory(self):
        b = create_backend("memory")
        assert isinstance(b, MemoryBackend)

    def test_explicit_sqlite(self, tmp_path):
        db_path = os.path.join(tmp_path, "factory.db")
        b = create_backend("sqlite", db_path)
        assert isinstance(b, SQLiteBackend)
        b.close()

    def test_env_var_sqlite(self, tmp_path, monkeypatch):
        db_path = os.path.join(tmp_path, "env.db")
        monkeypatch.setenv("SHIELD_STORAGE_BACKEND", "sqlite")
        monkeypatch.setenv("SHIELD_STORAGE_PATH", db_path)
        b = create_backend()
        assert isinstance(b, SQLiteBackend)
        b.close()


# ============================================================
# Package exports
# ============================================================


class TestStorageExports:

    def test_imports_from_package(self):
        from oubliette_shield import (
            StorageBackend,
            MemoryBackend,
            SQLiteBackend,
            create_backend,
        )
        assert StorageBackend is not None
        assert MemoryBackend is not None
        assert SQLiteBackend is not None
        assert callable(create_backend)
