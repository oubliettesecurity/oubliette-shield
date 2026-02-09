"""
Oubliette Shield - Storage Backends
Abstract storage for sessions with Memory (default) and SQLite backends.
"""

import abc
import json
import sqlite3
import datetime
import threading


class StorageBackend(abc.ABC):
    """Abstract base class for session storage."""

    @abc.abstractmethod
    def get_session(self, session_id):
        """Get session data by ID. Returns dict or empty dict if not found."""

    @abc.abstractmethod
    def put_session(self, session_id, session_data):
        """Store session data."""

    @abc.abstractmethod
    def delete_session(self, session_id):
        """Delete a session."""

    @abc.abstractmethod
    def list_sessions(self):
        """Return dict of all sessions {session_id: session_data}."""

    @abc.abstractmethod
    def count_active(self):
        """Return count of active sessions."""

    @abc.abstractmethod
    def count_escalated(self):
        """Return count of escalated sessions."""

    @abc.abstractmethod
    def cleanup_expired(self, ttl_seconds):
        """Remove sessions older than ttl_seconds. Returns count removed."""

    @abc.abstractmethod
    def session_count(self):
        """Return total number of sessions."""


class MemoryStorage(StorageBackend):
    """In-memory session storage (default). Data lost on restart."""

    def __init__(self):
        self._sessions = {}
        self._lock = threading.RLock()

    def get_session(self, session_id):
        with self._lock:
            return dict(self._sessions.get(session_id, {}))

    def put_session(self, session_id, session_data):
        with self._lock:
            self._sessions[session_id] = session_data

    def delete_session(self, session_id):
        with self._lock:
            self._sessions.pop(session_id, None)

    def list_sessions(self):
        with self._lock:
            return {sid: dict(s) for sid, s in self._sessions.items()}

    def count_active(self):
        with self._lock:
            return len(self._sessions)

    def count_escalated(self):
        with self._lock:
            return sum(1 for s in self._sessions.values() if s.get("escalated"))

    def cleanup_expired(self, ttl_seconds):
        with self._lock:
            now = datetime.datetime.now()
            expired = [
                sid for sid, s in self._sessions.items()
                if (now - s.get("last_activity", now)).total_seconds() > ttl_seconds
            ]
            for sid in expired:
                del self._sessions[sid]
            return len(expired)

    def session_count(self):
        with self._lock:
            return len(self._sessions)


class SQLiteStorage(StorageBackend):
    """SQLite-backed persistent session storage."""

    def __init__(self, db_path="oubliette_shield.db"):
        self._db_path = db_path
        self._lock = threading.RLock()
        self._init_db()

    def _init_db(self):
        """Create tables if they don't exist."""
        with self._lock:
            conn = sqlite3.connect(self._db_path)
            try:
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS sessions (
                        session_id TEXT PRIMARY KEY,
                        data TEXT NOT NULL,
                        escalated INTEGER DEFAULT 0,
                        threat_count INTEGER DEFAULT 0,
                        created_at TEXT,
                        last_activity TEXT
                    )
                """)
                conn.commit()
            finally:
                conn.close()

    def _get_conn(self):
        return sqlite3.connect(self._db_path, check_same_thread=False)

    def get_session(self, session_id):
        with self._lock:
            conn = self._get_conn()
            try:
                row = conn.execute(
                    "SELECT data FROM sessions WHERE session_id = ?",
                    (session_id,)
                ).fetchone()
                if row:
                    return json.loads(row[0])
                return {}
            finally:
                conn.close()

    def put_session(self, session_id, session_data):
        with self._lock:
            conn = self._get_conn()
            try:
                # Serialize datetime objects
                data = self._serialize_session(session_data)
                data_json = json.dumps(data)
                escalated = 1 if session_data.get("escalated") else 0
                threat_count = session_data.get("threat_count", 0)
                created_at = self._dt_to_str(session_data.get("created_at"))
                last_activity = self._dt_to_str(session_data.get("last_activity"))

                conn.execute("""
                    INSERT OR REPLACE INTO sessions
                    (session_id, data, escalated, threat_count, created_at, last_activity)
                    VALUES (?, ?, ?, ?, ?, ?)
                """, (session_id, data_json, escalated, threat_count,
                      created_at, last_activity))
                conn.commit()
            finally:
                conn.close()

    def delete_session(self, session_id):
        with self._lock:
            conn = self._get_conn()
            try:
                conn.execute("DELETE FROM sessions WHERE session_id = ?", (session_id,))
                conn.commit()
            finally:
                conn.close()

    def list_sessions(self):
        with self._lock:
            conn = self._get_conn()
            try:
                rows = conn.execute("SELECT session_id, data FROM sessions").fetchall()
                result = {}
                for sid, data_json in rows:
                    data = json.loads(data_json)
                    self._deserialize_session(data)
                    result[sid] = data
                return result
            finally:
                conn.close()

    def count_active(self):
        with self._lock:
            conn = self._get_conn()
            try:
                row = conn.execute("SELECT COUNT(*) FROM sessions").fetchone()
                return row[0] if row else 0
            finally:
                conn.close()

    def count_escalated(self):
        with self._lock:
            conn = self._get_conn()
            try:
                row = conn.execute(
                    "SELECT COUNT(*) FROM sessions WHERE escalated = 1"
                ).fetchone()
                return row[0] if row else 0
            finally:
                conn.close()

    def cleanup_expired(self, ttl_seconds):
        with self._lock:
            conn = self._get_conn()
            try:
                cutoff = (
                    datetime.datetime.now() - datetime.timedelta(seconds=ttl_seconds)
                ).strftime("%Y-%m-%d %H:%M:%S")
                cursor = conn.execute(
                    "DELETE FROM sessions WHERE last_activity < ?", (cutoff,)
                )
                conn.commit()
                return cursor.rowcount
            finally:
                conn.close()

    def session_count(self):
        return self.count_active()

    @staticmethod
    def _dt_to_str(dt):
        if isinstance(dt, datetime.datetime):
            return dt.strftime("%Y-%m-%d %H:%M:%S")
        if isinstance(dt, str):
            return dt
        return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    @staticmethod
    def _serialize_session(data):
        """Convert datetime objects to strings for JSON serialization."""
        result = {}
        for key, value in data.items():
            if isinstance(value, datetime.datetime):
                result[key] = value.strftime("%Y-%m-%d %H:%M:%S")
            elif isinstance(value, list):
                result[key] = [
                    SQLiteStorage._serialize_item(item) for item in value
                ]
            else:
                result[key] = value
        return result

    @staticmethod
    def _serialize_item(item):
        if isinstance(item, dict):
            return {k: SQLiteStorage._serialize_item(v) for k, v in item.items()}
        if isinstance(item, datetime.datetime):
            return item.strftime("%Y-%m-%d %H:%M:%S")
        return item

    @staticmethod
    def _deserialize_session(data):
        """Convert datetime strings back to datetime objects."""
        for key in ("created_at", "last_activity"):
            if key in data and isinstance(data[key], str):
                try:
                    data[key] = datetime.datetime.strptime(
                        data[key], "%Y-%m-%d %H:%M:%S"
                    )
                except ValueError:
                    pass
