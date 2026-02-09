"""Tests for storage backends (Memory and SQLite)."""

import os
import datetime
import tempfile
import pytest

from oubliette_shield.storage import MemoryStorage, SQLiteStorage


def _make_session(escalated=False, threat_count=0):
    """Create a test session dict."""
    return {
        "interactions": [],
        "cumulative_risk_score": 0.0,
        "threat_count": threat_count,
        "safe_count": 0,
        "escalated": escalated,
        "created_at": datetime.datetime.now(),
        "last_activity": datetime.datetime.now(),
        "source_ip": "127.0.0.1",
        "attack_patterns": [],
    }


class TestMemoryStorage:
    """Tests for in-memory session storage."""

    def test_put_and_get(self):
        store = MemoryStorage()
        session = _make_session()
        store.put_session("s1", session)
        got = store.get_session("s1")
        assert got["source_ip"] == "127.0.0.1"

    def test_get_missing(self):
        store = MemoryStorage()
        assert store.get_session("nonexistent") == {}

    def test_delete(self):
        store = MemoryStorage()
        store.put_session("s1", _make_session())
        store.delete_session("s1")
        assert store.get_session("s1") == {}

    def test_list_sessions(self):
        store = MemoryStorage()
        store.put_session("s1", _make_session())
        store.put_session("s2", _make_session())
        all_sessions = store.list_sessions()
        assert len(all_sessions) == 2
        assert "s1" in all_sessions
        assert "s2" in all_sessions

    def test_count_active(self):
        store = MemoryStorage()
        assert store.count_active() == 0
        store.put_session("s1", _make_session())
        assert store.count_active() == 1

    def test_count_escalated(self):
        store = MemoryStorage()
        store.put_session("s1", _make_session(escalated=True))
        store.put_session("s2", _make_session(escalated=False))
        assert store.count_escalated() == 1

    def test_cleanup_expired(self):
        store = MemoryStorage()
        old_session = _make_session()
        old_session["last_activity"] = datetime.datetime.now() - datetime.timedelta(hours=2)
        store.put_session("old", old_session)
        store.put_session("new", _make_session())
        removed = store.cleanup_expired(ttl_seconds=3600)
        assert removed == 1
        assert store.count_active() == 1

    def test_session_count(self):
        store = MemoryStorage()
        store.put_session("s1", _make_session())
        assert store.session_count() == 1


class TestSQLiteStorage:
    """Tests for SQLite persistent storage."""

    def _make_store(self, tmp_path=None):
        if tmp_path:
            db_path = os.path.join(str(tmp_path), "test.db")
        else:
            fd, db_path = tempfile.mkstemp(suffix=".db")
            os.close(fd)
        return SQLiteStorage(db_path=db_path), db_path

    def test_put_and_get(self, tmp_path):
        store, _ = self._make_store(tmp_path)
        session = _make_session()
        store.put_session("s1", session)
        got = store.get_session("s1")
        assert got["source_ip"] == "127.0.0.1"

    def test_get_missing(self, tmp_path):
        store, _ = self._make_store(tmp_path)
        assert store.get_session("nonexistent") == {}

    def test_delete(self, tmp_path):
        store, _ = self._make_store(tmp_path)
        store.put_session("s1", _make_session())
        store.delete_session("s1")
        assert store.get_session("s1") == {}

    def test_list_sessions(self, tmp_path):
        store, _ = self._make_store(tmp_path)
        store.put_session("s1", _make_session())
        store.put_session("s2", _make_session())
        all_sessions = store.list_sessions()
        assert len(all_sessions) == 2

    def test_count_active(self, tmp_path):
        store, _ = self._make_store(tmp_path)
        assert store.count_active() == 0
        store.put_session("s1", _make_session())
        assert store.count_active() == 1

    def test_count_escalated(self, tmp_path):
        store, _ = self._make_store(tmp_path)
        store.put_session("s1", _make_session(escalated=True))
        store.put_session("s2", _make_session(escalated=False))
        assert store.count_escalated() == 1

    def test_persistence_across_reconnect(self, tmp_path):
        """Data persists after creating a new storage instance."""
        db_path = os.path.join(str(tmp_path), "persist.db")
        store1 = SQLiteStorage(db_path=db_path)
        store1.put_session("s1", _make_session())
        # Create new instance pointing to same DB
        store2 = SQLiteStorage(db_path=db_path)
        got = store2.get_session("s1")
        assert got["source_ip"] == "127.0.0.1"

    def test_cleanup_expired(self, tmp_path):
        store, _ = self._make_store(tmp_path)
        old_session = _make_session()
        old_session["last_activity"] = datetime.datetime.now() - datetime.timedelta(hours=2)
        store.put_session("old", old_session)
        store.put_session("new", _make_session())
        removed = store.cleanup_expired(ttl_seconds=3600)
        assert removed == 1
        assert store.count_active() == 1

    def test_update_existing(self, tmp_path):
        store, _ = self._make_store(tmp_path)
        session = _make_session()
        store.put_session("s1", session)
        session["threat_count"] = 5
        session["escalated"] = True
        store.put_session("s1", session)
        got = store.get_session("s1")
        assert got["threat_count"] == 5
        assert got["escalated"] is True


class TestSessionManagerWithStorage:
    """Tests for SessionManager using different backends."""

    def test_memory_backend(self):
        from oubliette_shield.session import SessionManager
        from oubliette_shield.storage import MemoryStorage
        sm = SessionManager(storage=MemoryStorage())
        assert sm.active_count == 0

    def test_sqlite_backend(self, tmp_path):
        from oubliette_shield.session import SessionManager
        from oubliette_shield.storage import SQLiteStorage
        db_path = os.path.join(str(tmp_path), "session_test.db")
        sm = SessionManager(storage=SQLiteStorage(db_path=db_path))
        assert sm.active_count == 0

    def test_session_update_persists(self, tmp_path):
        from oubliette_shield.session import SessionManager
        from oubliette_shield.storage import SQLiteStorage
        db_path = os.path.join(str(tmp_path), "update_test.db")
        store = SQLiteStorage(db_path=db_path)
        sm = SessionManager(storage=store)
        sm.update("test", "hello", "SAFE", None, "127.0.0.1")
        got = sm.get("test")
        assert got["safe_count"] == 1
