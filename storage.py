"""Atomic reports and persistent lookup/checkpoint storage."""

from contextlib import contextmanager
import json
import os
from pathlib import Path
import sqlite3
import tempfile
import time


@contextmanager
def atomic_output(path, overwrite=False, binary=False):
    """Commit a complete file in one operation, never truncate the old report."""
    path = Path(path)
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w+b" if binary else "w+", dir=path.parent,
            prefix=f".{path.name}.", suffix=".tmp", delete=False,
            **({} if binary else {"encoding": "utf-8", "newline": ""}),
        ) as target:
            temporary = Path(target.name)
            yield target
            target.flush()
            os.fsync(target.fileno())
        if overwrite:
            os.replace(temporary, path)
        else:
            # Unlike rename/replace, link cannot overwrite a competing writer.
            os.link(temporary, path)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


class StateStore:
    """SQLite commits each address independently, including failed attempts."""

    def __init__(self, directory):
        directory = Path(directory)
        directory.mkdir(parents=True, exist_ok=True)
        self.connection = sqlite3.connect(directory / "state.sqlite3")
        self.connection.execute("PRAGMA journal_mode=WAL")
        self.connection.executescript("""
            CREATE TABLE IF NOT EXISTS cache (
                cache_key TEXT PRIMARY KEY, saved_at REAL NOT NULL, payload TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS checkpoints (
                run_key TEXT NOT NULL, ip TEXT NOT NULL, payload TEXT NOT NULL,
                PRIMARY KEY (run_key, ip)
            );
        """)

    def cached(self, key, ttl):
        row = self.connection.execute(
            "SELECT saved_at, payload FROM cache WHERE cache_key=?", (key,)
        ).fetchone()
        if row and 0 <= time.time() - row[0] < ttl:
            return json.loads(row[1])
        return None

    def checkpoint(self, run_key, ip):
        row = self.connection.execute(
            "SELECT payload FROM checkpoints WHERE run_key=? AND ip=?", (run_key, ip)
        ).fetchone()
        return json.loads(row[0]) if row else None

    def save(self, run_key, cache_key, result, cacheable=True):
        payload = json.dumps(result, ensure_ascii=False, allow_nan=False)
        with self.connection:
            self.connection.execute(
                "INSERT OR REPLACE INTO checkpoints VALUES (?, ?, ?)",
                (run_key, result["ip"], payload),
            )
            if cacheable:
                self.connection.execute(
                    "INSERT OR REPLACE INTO cache VALUES (?, ?, ?)",
                    (cache_key, time.time(), payload),
                )

    def close(self):
        self.connection.close()
