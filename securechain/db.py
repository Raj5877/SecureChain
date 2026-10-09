from __future__ import annotations

import sqlite3
from contextlib import contextmanager
from pathlib import Path

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY, username TEXT UNIQUE NOT NULL, name TEXT NOT NULL,
    password_hash TEXT NOT NULL, role TEXT NOT NULL CHECK(role IN ('admin','investigator','viewer')),
    public_key TEXT NOT NULL, private_key BLOB NOT NULL, created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS evidence (
    id TEXT PRIMARY KEY, manifest TEXT NOT NULL, signature TEXT NOT NULL,
    signer_key TEXT NOT NULL, blob_name TEXT UNIQUE NOT NULL, imported_history TEXT NOT NULL DEFAULT '[]',
    status TEXT NOT NULL DEFAULT 'verified' CHECK(status IN ('verified','unverified','alert')),
    last_verified TEXT, registered_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS evidence_archive (
    evidence_id TEXT PRIMARY KEY REFERENCES evidence(id), archived_at TEXT NOT NULL,
    archived_by TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY, evidence_id TEXT, payload TEXT NOT NULL, previous_hash TEXT NOT NULL,
    event_hash TEXT NOT NULL UNIQUE, signature TEXT NOT NULL, public_key TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS peers (
    node_id TEXT PRIMARY KEY, descriptor TEXT NOT NULL, url TEXT NOT NULL DEFAULT '',
    token BLOB, added_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS transfers (
    id TEXT PRIMARY KEY, evidence_id TEXT NOT NULL, peer_id TEXT NOT NULL, direction TEXT NOT NULL,
    status TEXT NOT NULL, bytes INTEGER NOT NULL, elapsed_ms REAL NOT NULL,
    created_at TEXT NOT NULL, detail TEXT NOT NULL, encryption_ms REAL, decryption_ms REAL
);
CREATE TABLE IF NOT EXISTS receipts (package_id TEXT PRIMARY KEY, evidence_id TEXT NOT NULL, received_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS metrics (
    id INTEGER PRIMARY KEY, evidence_id TEXT, operation TEXT NOT NULL,
    hash_ms REAL NOT NULL, signature_ms REAL NOT NULL, total_ms REAL NOT NULL, size_bytes INTEGER NOT NULL, created_at TEXT NOT NULL,
    encryption_ms REAL, decryption_ms REAL
);
CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY, evidence_id TEXT, message TEXT NOT NULL, created_at TEXT NOT NULL, acknowledged INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS login_attempts (key TEXT PRIMARY KEY, failures INTEGER NOT NULL, last_attempt REAL NOT NULL);
CREATE TRIGGER IF NOT EXISTS events_no_update BEFORE UPDATE ON events BEGIN SELECT RAISE(ABORT, 'Audit events are append-only'); END;
CREATE TRIGGER IF NOT EXISTS events_no_delete BEFORE DELETE ON events BEGIN SELECT RAISE(ABORT, 'Audit events are append-only'); END;
CREATE TRIGGER IF NOT EXISTS evidence_original_immutable BEFORE UPDATE OF id,manifest,signature,signer_key,blob_name,imported_history,registered_at ON evidence
BEGIN SELECT RAISE(ABORT, 'Original evidence metadata is immutable'); END;
CREATE TRIGGER IF NOT EXISTS evidence_no_delete BEFORE DELETE ON evidence BEGIN SELECT RAISE(ABORT, 'Evidence cannot be deleted'); END;
"""


class Database:
    def __init__(self, path: Path):
        self.path = path
        with self.connect() as db:
            db.executescript(SCHEMA)
            # Preserve existing measurements; NULL means the time was not recorded.
            db.execute("BEGIN IMMEDIATE")
            for table in ("metrics", "transfers"):
                columns = {row["name"] for row in db.execute(f"PRAGMA table_info({table})")}
                for column in ("encryption_ms", "decryption_ms"):
                    if column not in columns:
                        db.execute(f"ALTER TABLE {table} ADD COLUMN {column} REAL")

    @contextmanager
    def connect(self):
        db = sqlite3.connect(self.path, timeout=30)
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA foreign_keys=ON")
        db.execute("PRAGMA journal_mode=WAL")
        try:
            yield db
            db.commit()
        except Exception:
            db.rollback()
            raise
        finally:
            db.close()

    def rows(self, sql, params=()):
        with self.connect() as db:
            return [dict(row) for row in db.execute(sql, params).fetchall()]

    def one(self, sql, params=()):
        rows = self.rows(sql, params)
        return rows[0] if rows else None
