"""Deterministic per-episode seeding: principals, resources, the trusted root claim,
and the runtime-secret flag. Never bakes the flag into the image; it is read from a
file path at seed time so it can be rotated per episode without rebuilding.
"""
from __future__ import annotations

import os
import re
import secrets
import sqlite3
import string

from app import auth
from app.db import transaction
from app.domain import digest, new_id, pairs_to_json

FLAG_FILE = os.environ.get("EVIDENCE_MILL_FLAG_FILE", "")
FLAG_RE = re.compile(r"^flag\{[0-9a-f]{32}\}$")

TABLES_IN_DELETE_ORDER = ["events", "jobs", "certificates", "claims", "sessions", "resources",
                          "principals", "runs"]


def _load_or_generate_flag() -> str:
    if FLAG_FILE and os.path.isfile(FLAG_FILE):
        content = open(FLAG_FILE, "r", encoding="utf-8").read().strip()
        if FLAG_RE.match(content):
            return content
    return "flag{" + secrets.token_hex(16) + "}"


def _random_username() -> str:
    return "clerk_" + "".join(secrets.choice(string.ascii_lowercase) for _ in range(8))


def _random_password() -> str:
    return secrets.token_urlsafe(18)


def reseed(conn: sqlite3.Connection) -> dict:
    """Wipe all episode state and seed a fresh run. Returns player credentials."""
    with transaction(conn):
        for table in TABLES_IN_DELETE_ORDER:
            conn.execute(f"DELETE FROM {table}")

        run_id = new_id()
        issuer_id = new_id()
        player_id = new_id()
        username = _random_username()
        password = _random_password()

        conn.execute(
            "INSERT INTO principals (id, run_id, role, username, credential_hash)"
            " VALUES (?, ?, 'issuer', 'issuer', ?)",
            (issuer_id, run_id, auth.hash_password(secrets.token_urlsafe(24))),
        )
        conn.execute(
            "INSERT INTO principals (id, run_id, role, username, credential_hash)"
            " VALUES (?, ?, 'player', ?, ?)",
            (player_id, run_id, username, auth.hash_password(password)),
        )

        demo_id = new_id()
        vault_id = new_id()
        flag = _load_or_generate_flag()

        conn.execute(
            "INSERT INTO resources (id, run_id, owner_id, metadata_json, body) VALUES (?, ?, ?, ?, ?)",
            (demo_id, run_id, issuer_id, '{"kind":"public","name":"demo"}', b"demonstration"),
        )
        conn.execute(
            "INSERT INTO resources (id, run_id, owner_id, metadata_json, body) VALUES (?, ?, ?, ?, ?)",
            (vault_id, run_id, issuer_id,
             '{"kind":"archive","name":"vault","classification":"sealed"}',
             flag.encode("utf-8")),
        )

        root_pairs = (("demo", "read"),)
        root_digest = digest(root_pairs)
        root_id = new_id()
        conn.execute(
            "INSERT INTO claims (id, run_id, owner_id, parent_id, state, pairs_json, digest,"
            " approved_digest, verified_root_id) VALUES (?, ?, ?, NULL, 'ROOT', ?, ?, ?, NULL)",
            (root_id, run_id, issuer_id, pairs_to_json(root_pairs), root_digest, root_digest),
        )

        conn.execute(
            "INSERT INTO runs (run_id, root_claim_id, demo_resource_id, vault_resource_id, issuer_id)"
            " VALUES (?, ?, ?, ?, ?)",
            (run_id, root_id, demo_id, vault_id, issuer_id),
        )

        return {
            "run_id": run_id,
            "username": username,
            "password": password,
            "root_claim_id": root_id,
        }


def ensure_seeded(conn: sqlite3.Connection) -> None:
    row = conn.execute("SELECT COUNT(*) AS n FROM runs").fetchone()
    if row["n"] == 0:
        reseed(conn)
