"""Tiny SQLite key/value cache for threat-intel API responses."""
from __future__ import annotations

import json
import sqlite3
import threading
import time
from pathlib import Path


class IntelCache:
    def __init__(self, path: Path):
        self.path = Path(path)
        self._lock = threading.Lock()
        with self._conn() as c:
            c.execute("CREATE TABLE IF NOT EXISTS cache (key TEXT PRIMARY KEY, fetched REAL NOT NULL, payload TEXT NOT NULL)")

    def _conn(self):
        return sqlite3.connect(self.path, timeout=30)

    def get(self, key: str, max_age_seconds: float | None = None):
        with self._lock, self._conn() as c:
            row = c.execute("SELECT fetched, payload FROM cache WHERE key=?", (key,)).fetchone()
        if not row:
            return None
        if max_age_seconds is not None and time.time() - row[0] > max_age_seconds:
            return None
        return json.loads(row[1])

    def set(self, key: str, value) -> None:
        with self._lock, self._conn() as c:
            c.execute("INSERT OR REPLACE INTO cache(key, fetched, payload) VALUES (?,?,?)", (key, time.time(), json.dumps(value)))

    def search(self, prefix: str) -> list:
        with self._lock, self._conn() as c:
            rows = c.execute("SELECT payload FROM cache WHERE key LIKE ?", (prefix + "%",)).fetchall()
        return [json.loads(r[0]) for r in rows]

    def stats(self) -> dict:
        with self._lock, self._conn() as c:
            rows = c.execute("SELECT substr(key, 1, instr(key, ':') - 1) AS kind, count(*) FROM cache GROUP BY kind").fetchall()
        return {k: n for k, n in rows}

    def clear(self) -> None:
        with self._lock, self._conn() as c:
            c.execute("DELETE FROM cache")
