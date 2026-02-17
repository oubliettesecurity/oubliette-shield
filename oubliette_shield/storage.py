"""
Oubliette Shield - Storage Backends
Abstract storage interface with Memory and SQLite implementations.

Provides persistent storage for sessions, detection events, and IOCs.

Usage::

    from oubliette_shield.storage import create_backend

    # Auto-detect from environment variables
    backend = create_backend()

    # Or explicit SQLite
    backend = SQLiteBackend("shield.db")
    backend.save_session("sess-1", {"threat_count": 3, "escalated": True})
    session = backend.load_session("sess-1")
"""

from __future__ import annotations

import json
import os
import sqlite3
import threading
import time
from abc import ABC, abstractmethod
from datetime import datetime
from typing import Any, Dict, List, Optional


def _make_serializable(obj: Any) -> Any:
    """Convert datetime and other non-JSON types to strings."""
    if isinstance(obj, datetime):
        return obj.isoformat()
    if isinstance(obj, set):
        return sorted(obj)
    return obj


def _serialize_session(data: Dict[str, Any]) -> str:
    """Serialize a session dict to JSON."""
    clean = {}
    for k, v in data.items():
        clean[k] = _make_serializable(v)
    return json.dumps(clean, default=str)


# ---- Abstract Backend ----


class StorageBackend(ABC):
    """Abstract interface for Shield storage."""

    # -- Sessions --

    @abstractmethod
    def save_session(self, session_id: str, data: Dict[str, Any]) -> None:
        """Persist session state."""

    @abstractmethod
    def load_session(self, session_id: str) -> Optional[Dict[str, Any]]:
        """Load session state.  Returns None if not found."""

    @abstractmethod
    def delete_session(self, session_id: str) -> bool:
        """Delete a session.  Returns True if deleted."""

    @abstractmethod
    def list_sessions(self) -> Dict[str, Dict[str, Any]]:
        """Return all sessions as {session_id: data}."""

    # -- Detection events --

    @abstractmethod
    def log_detection(self, event: Dict[str, Any]) -> None:
        """Store a detection event."""

    @abstractmethod
    def query_detections(
        self,
        verdict: Optional[str] = None,
        session_id: Optional[str] = None,
        limit: int = 100,
    ) -> List[Dict[str, Any]]:
        """Query detection events with optional filters."""

    # -- IOCs --

    @abstractmethod
    def save_ioc(self, ioc: Dict[str, Any]) -> None:
        """Store or update an IOC (deduplicated by payload_hash)."""

    @abstractmethod
    def query_iocs(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Query stored IOCs."""


# ---- Memory Backend ----


class MemoryBackend(StorageBackend):
    """In-memory storage (no persistence across restarts).

    Thread-safe.  This is the default when no backend is configured.
    """

    def __init__(self):
        self._sessions: Dict[str, Dict[str, Any]] = {}
        self._detections: List[Dict[str, Any]] = []
        self._iocs: Dict[str, Dict[str, Any]] = {}  # payload_hash -> ioc
        self._lock = threading.RLock()

    def save_session(self, session_id: str, data: Dict[str, Any]) -> None:
        with self._lock:
            self._sessions[session_id] = dict(data)

    def load_session(self, session_id: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            s = self._sessions.get(session_id)
            return dict(s) if s else None

    def delete_session(self, session_id: str) -> bool:
        with self._lock:
            return self._sessions.pop(session_id, None) is not None

    def list_sessions(self) -> Dict[str, Dict[str, Any]]:
        with self._lock:
            return {sid: dict(s) for sid, s in self._sessions.items()}

    def log_detection(self, event: Dict[str, Any]) -> None:
        with self._lock:
            self._detections.append(dict(event))

    def query_detections(
        self,
        verdict: Optional[str] = None,
        session_id: Optional[str] = None,
        limit: int = 100,
    ) -> List[Dict[str, Any]]:
        with self._lock:
            results = list(reversed(self._detections))
            if verdict:
                results = [e for e in results if e.get("verdict") == verdict]
            if session_id:
                results = [e for e in results if e.get("session_id") == session_id]
            return results[:limit]

    def save_ioc(self, ioc: Dict[str, Any]) -> None:
        with self._lock:
            ph = ioc.get("payload_hash", "")
            if ph in self._iocs:
                existing = self._iocs[ph]
                existing["sighting_count"] = existing.get("sighting_count", 1) + 1
                existing["last_seen"] = ioc.get("last_seen", datetime.now().isoformat())
            else:
                self._iocs[ph] = dict(ioc)

    def query_iocs(self, limit: int = 100) -> List[Dict[str, Any]]:
        with self._lock:
            items = sorted(
                self._iocs.values(),
                key=lambda x: x.get("last_seen", ""),
                reverse=True,
            )
            return items[:limit]


# ---- SQLite Backend ----


_SHIELD_SCHEMA = """
CREATE TABLE IF NOT EXISTS shield_sessions (
    session_id  TEXT PRIMARY KEY,
    data        TEXT NOT NULL,
    created_at  TEXT NOT NULL,
    updated_at  TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS shield_detections (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp        TEXT NOT NULL,
    session_id       TEXT,
    verdict          TEXT,
    detection_method TEXT,
    ml_score         REAL,
    user_input       TEXT,
    data             TEXT DEFAULT '{}'
);

CREATE INDEX IF NOT EXISTS idx_sd_verdict    ON shield_detections(verdict);
CREATE INDEX IF NOT EXISTS idx_sd_session    ON shield_detections(session_id);
CREATE INDEX IF NOT EXISTS idx_sd_ts         ON shield_detections(timestamp);

CREATE TABLE IF NOT EXISTS shield_iocs (
    payload_hash    TEXT PRIMARY KEY,
    data            TEXT NOT NULL,
    first_seen      TEXT NOT NULL,
    last_seen       TEXT NOT NULL,
    sighting_count  INTEGER DEFAULT 1
);

CREATE INDEX IF NOT EXISTS idx_si_last ON shield_iocs(last_seen);
"""


class SQLiteBackend(StorageBackend):
    """SQLite-based persistent storage with WAL mode.

    Thread-safe via thread-local connections.

    Args:
        db_path: Path to the SQLite database file.
    """

    def __init__(self, db_path: str = "shield.db"):
        self.db_path = db_path
        self._local = threading.local()
        self._init_db()

    @property
    def _conn(self) -> sqlite3.Connection:
        if not hasattr(self._local, "conn") or self._local.conn is None:
            conn = sqlite3.connect(self.db_path, timeout=10)
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA journal_mode=WAL")
            self._local.conn = conn
        return self._local.conn

    def _init_db(self) -> None:
        self._conn.executescript(_SHIELD_SCHEMA)
        self._conn.commit()

    def close(self) -> None:
        if hasattr(self._local, "conn") and self._local.conn:
            self._local.conn.close()
            self._local.conn = None

    # -- Sessions --

    def save_session(self, session_id: str, data: Dict[str, Any]) -> None:
        now = datetime.now().isoformat()
        serialized = _serialize_session(data)
        self._conn.execute(
            """INSERT INTO shield_sessions (session_id, data, created_at, updated_at)
               VALUES (?, ?, ?, ?)
               ON CONFLICT(session_id) DO UPDATE SET data=excluded.data, updated_at=excluded.updated_at""",
            (session_id, serialized, now, now),
        )
        self._conn.commit()

    def load_session(self, session_id: str) -> Optional[Dict[str, Any]]:
        row = self._conn.execute(
            "SELECT data FROM shield_sessions WHERE session_id = ?", (session_id,)
        ).fetchone()
        if row is None:
            return None
        return json.loads(row["data"])

    def delete_session(self, session_id: str) -> bool:
        cur = self._conn.execute(
            "DELETE FROM shield_sessions WHERE session_id = ?", (session_id,)
        )
        self._conn.commit()
        return cur.rowcount > 0

    def list_sessions(self) -> Dict[str, Dict[str, Any]]:
        rows = self._conn.execute("SELECT session_id, data FROM shield_sessions").fetchall()
        result = {}
        for row in rows:
            result[row["session_id"]] = json.loads(row["data"])
        return result

    # -- Detection events --

    def log_detection(self, event: Dict[str, Any]) -> None:
        now = event.get("timestamp", datetime.now().isoformat())
        self._conn.execute(
            """INSERT INTO shield_detections
               (timestamp, session_id, verdict, detection_method, ml_score, user_input, data)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (
                now,
                event.get("session_id"),
                event.get("verdict"),
                event.get("detection_method"),
                event.get("ml_score"),
                event.get("user_input"),
                json.dumps(event, default=str),
            ),
        )
        self._conn.commit()

    def query_detections(
        self,
        verdict: Optional[str] = None,
        session_id: Optional[str] = None,
        limit: int = 100,
    ) -> List[Dict[str, Any]]:
        clauses = []
        params: list = []
        if verdict:
            clauses.append("verdict = ?")
            params.append(verdict)
        if session_id:
            clauses.append("session_id = ?")
            params.append(session_id)

        where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
        rows = self._conn.execute(
            f"SELECT data FROM shield_detections{where} ORDER BY timestamp DESC LIMIT ?",
            params + [limit],
        ).fetchall()
        return [json.loads(row["data"]) for row in rows]

    # -- IOCs --

    def save_ioc(self, ioc: Dict[str, Any]) -> None:
        now = datetime.now().isoformat()
        ph = ioc.get("payload_hash", "")
        self._conn.execute(
            """INSERT INTO shield_iocs (payload_hash, data, first_seen, last_seen, sighting_count)
               VALUES (?, ?, ?, ?, 1)
               ON CONFLICT(payload_hash) DO UPDATE SET
                   last_seen = excluded.last_seen,
                   sighting_count = shield_iocs.sighting_count + 1,
                   data = excluded.data""",
            (ph, json.dumps(ioc, default=str), now, now),
        )
        self._conn.commit()

    def query_iocs(self, limit: int = 100) -> List[Dict[str, Any]]:
        rows = self._conn.execute(
            "SELECT data FROM shield_iocs ORDER BY last_seen DESC LIMIT ?", (limit,)
        ).fetchall()
        return [json.loads(row["data"]) for row in rows]


# ---- Factory ----


def create_backend(
    backend_type: Optional[str] = None,
    db_path: Optional[str] = None,
) -> StorageBackend:
    """Create a storage backend from config or environment variables.

    Environment variables:
        SHIELD_STORAGE_BACKEND  -- ``memory`` (default) or ``sqlite``
        SHIELD_STORAGE_PATH     -- path to SQLite DB (default: ``shield.db``)
    """
    btype = backend_type or os.getenv("SHIELD_STORAGE_BACKEND", "memory")
    if btype == "sqlite":
        path = db_path or os.getenv("SHIELD_STORAGE_PATH", "shield.db")
        return SQLiteBackend(path)
    return MemoryBackend()
