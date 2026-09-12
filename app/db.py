"""SQLite schema, connection and transaction helpers for Evidence Mill."""
from __future__ import annotations

import contextlib
import os
import sqlite3
from pathlib import Path

DB_PATH = os.environ.get("EVIDENCE_MILL_DB", "./data/evidence.db")

SCHEMA = """
CREATE TABLE IF NOT EXISTS principals (
    id TEXT PRIMARY KEY,
    run_id TEXT NOT NULL,
    role TEXT NOT NULL,
    username TEXT NOT NULL,
    credential_hash TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS sessions (
    token_hash TEXT PRIMARY KEY,
    run_id TEXT NOT NULL,
    principal_id TEXT NOT NULL REFERENCES principals(id)
);

CREATE TABLE IF NOT EXISTS resources (
    id TEXT PRIMARY KEY,
    run_id TEXT NOT NULL,
    owner_id TEXT NOT NULL REFERENCES principals(id),
    metadata_json TEXT NOT NULL,
    body BLOB NOT NULL
);

CREATE TABLE IF NOT EXISTS claims (
    id TEXT PRIMARY KEY,
    run_id TEXT NOT NULL,
    owner_id TEXT NOT NULL REFERENCES principals(id),
    parent_id TEXT REFERENCES claims(id),
    state TEXT NOT NULL,
    pairs_json TEXT NOT NULL,
    digest TEXT NOT NULL,
    approved_digest TEXT,
    verified_root_id TEXT REFERENCES claims(id)
);

CREATE TABLE IF NOT EXISTS certificates (
    id TEXT PRIMARY KEY,
    run_id TEXT NOT NULL,
    owner_id TEXT NOT NULL REFERENCES principals(id),
    claim_id TEXT NOT NULL UNIQUE REFERENCES claims(id),
    digest TEXT NOT NULL,
    pairs_json TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS jobs (
    id TEXT PRIMARY KEY,
    run_id TEXT NOT NULL,
    owner_id TEXT NOT NULL REFERENCES principals(id),
    certificate_id TEXT NOT NULL REFERENCES certificates(id),
    resource_id TEXT NOT NULL REFERENCES resources(id),
    action TEXT NOT NULL,
    state TEXT NOT NULL,
    payload BLOB NOT NULL,
    payload_digest TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS events (
    seq INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id TEXT NOT NULL,
    principal_id TEXT NOT NULL,
    kind TEXT NOT NULL,
    claim_id TEXT,
    certificate_id TEXT,
    job_id TEXT
);

CREATE TABLE IF NOT EXISTS runs (
    run_id TEXT PRIMARY KEY,
    root_claim_id TEXT,
    demo_resource_id TEXT,
    vault_resource_id TEXT,
    issuer_id TEXT
);
"""


def _connect(path: str) -> sqlite3.Connection:
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA journal_mode = WAL")
    return conn


_conn: sqlite3.Connection | None = None


def get_conn() -> sqlite3.Connection:
    global _conn
    if _conn is None:
        _conn = _connect(DB_PATH)
        _conn.executescript(SCHEMA)
        _conn.commit()
    return _conn


def reset_connection() -> None:
    """Close and drop the cached connection so a fresh DB file can be adopted."""
    global _conn
    if _conn is not None:
        _conn.close()
        _conn = None


@contextlib.contextmanager
def transaction(conn: sqlite3.Connection):
    conn.execute("BEGIN")
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
