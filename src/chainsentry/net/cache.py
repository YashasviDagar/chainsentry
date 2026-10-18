"""A tiny on-disk key/value cache with per-entry expiry, backed by SQLite.

Why cache at all?
    OSV.dev, npm and PyPI are free public services. Re-scanning the same
    project (every CI run, every local run) would re-download the same data
    and quickly hit rate limits. With the cache, a second scan of an
    unchanged project makes almost no network requests.

Why SQLite (stdlib ``sqlite3``) instead of one JSON file per entry?
    * one file, atomic transactions - a crash never leaves a half-written entry
    * indexed lookups - fast even with tens of thousands of entries
    * safe to share between threads (we serialise access with a lock)

Schema::

    entries(key TEXT PRIMARY KEY, value TEXT, expires_at REAL)

Values are JSON text. Keys are short readable strings such as
``"osv-query:PyPI:django:3.2.0"`` (callers build them, see ``make_key`` for
hashing arbitrary request data).
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
import threading
import time
from pathlib import Path
from typing import Any

_SCHEMA = """
CREATE TABLE IF NOT EXISTS entries (
    key        TEXT PRIMARY KEY,
    value      TEXT NOT NULL,
    expires_at REAL NOT NULL
)
"""

#: Returned by :meth:`Cache.get_json` when there is no (fresh) entry. A
#: sentinel is needed because ``None`` is a legitimate cached value (we cache
#: "package not found" as ``None``).
MISS: Any = object()


class Cache:
    """SQLite-backed cache. ``Cache(None)`` is a disabled cache that stores nothing.

    Args:
        path: Database file, created on first use. ``None`` disables caching
            (used for ``--no-cache`` and in most unit tests).
        clock: Function returning the current time; injectable for tests.
    """

    def __init__(self, path: Path | None, *, clock=time.time) -> None:
        self._clock = clock
        self._lock = threading.Lock()
        self._conn: sqlite3.Connection | None = None
        self.path = path
        if path is not None:
            path.parent.mkdir(parents=True, exist_ok=True)
            # check_same_thread=False: the connection is shared by our worker
            # threads; the lock above guarantees one user at a time.
            self._conn = sqlite3.connect(path, check_same_thread=False)
            with self._lock:
                self._conn.execute(_SCHEMA)
                self._conn.commit()

    @property
    def enabled(self) -> bool:
        return self._conn is not None

    def get_json(self, key: str) -> Any:
        """Return the cached value for ``key``, or :data:`MISS` if absent/expired."""
        if self._conn is None:
            return MISS
        with self._lock:
            row = self._conn.execute(
                "SELECT value, expires_at FROM entries WHERE key = ?", (key,)
            ).fetchone()
        if row is None or row[1] < self._clock():
            return MISS
        # SECURITY: values are JSON written by us; json.loads cannot execute
        # code (never use pickle for a cache an attacker might be able to edit).
        return json.loads(row[0])

    def set_json(self, key: str, value: Any, ttl: float) -> None:
        """Store ``value`` (anything JSON-serialisable) for ``ttl`` seconds."""
        if self._conn is None:
            return
        payload = json.dumps(value, separators=(",", ":"))
        with self._lock:
            self._conn.execute(
                "INSERT OR REPLACE INTO entries (key, value, expires_at) VALUES (?, ?, ?)",
                (key, payload, self._clock() + ttl),
            )
            self._conn.commit()

    def clear(self) -> int:
        """Delete every entry. Returns how many were removed."""
        if self._conn is None:
            return 0
        with self._lock:
            removed = self._conn.execute("DELETE FROM entries").rowcount
            self._conn.commit()
            self._conn.execute("VACUUM")  # actually shrink the file on disk
        return removed

    def purge_expired(self) -> int:
        """Delete expired entries. Returns how many were removed."""
        if self._conn is None:
            return 0
        with self._lock:
            removed = self._conn.execute(
                "DELETE FROM entries WHERE expires_at < ?", (self._clock(),)
            ).rowcount
            self._conn.commit()
        return removed

    def close(self) -> None:
        if self._conn is not None:
            with self._lock:
                self._conn.close()
            self._conn = None


def make_key(*parts: Any) -> str:
    """Build a fixed-length cache key from arbitrary request data (e.g. a POST body).

    SHA-256 keeps keys short and uniform no matter how big the input is.
    """
    raw = json.dumps(parts, sort_keys=True, separators=(",", ":"), default=str)
    return "h:" + hashlib.sha256(raw.encode()).hexdigest()
