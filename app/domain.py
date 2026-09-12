"""Core Evidence Mill domain logic: claims, verification, certificates, exports.

Contains exactly two intentional vulnerabilities (marked BUG 1 / BUG 2 below).
Every other check in this module is intended to be correct and must stay that way.
"""
from __future__ import annotations

import hashlib
import json
import secrets
import sqlite3
from dataclasses import dataclass
from typing import Iterable

from app.db import transaction

# The only pairs a player claim may ever contain. Fixed game design, not a secret.
BASE_PAIRS: frozenset[tuple[str, str]] = frozenset({("demo", "read"), ("vault", "stat")})

MAX_BODY_BYTES = 4096


class NotFound(Exception):
    pass


class Forbidden(Exception):
    pass


class Conflict(Exception):
    pass


class Invalid(Exception):
    pass


@dataclass
class Principal:
    id: str
    run_id: str
    role: str
    username: str


def canonical_pairs(pairs: Iterable[Iterable[str]]) -> tuple[tuple[str, str], ...]:
    """Parse+validate pairs: list of exactly-2-element [resource, action] entries,
    no duplicates. Returns a sorted, de-duplicated tuple of tuples."""
    seen: set[tuple[str, str]] = set()
    for item in pairs:
        item = list(item)
        if len(item) != 2:
            raise Invalid("each pair must have exactly 2 elements")
        resource, action = item
        if not isinstance(resource, str) or not isinstance(action, str):
            raise Invalid("pair elements must be strings")
        if not resource or not action:
            raise Invalid("pair elements must be non-empty")
        pair = (resource, action)
        if pair in seen:
            raise Invalid("duplicate pair")
        seen.add(pair)
    return tuple(sorted(seen))


def digest(pairs: tuple[tuple[str, str], ...]) -> str:
    """Canonical SHA-256 digest of a sorted, unique, compact-JSON pair set."""
    canonical = json.dumps([list(p) for p in sorted(set(pairs))], separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def pairs_to_json(pairs: tuple[tuple[str, str], ...]) -> str:
    return json.dumps([list(p) for p in pairs], separators=(",", ":"))


def pairs_from_json(raw: str) -> tuple[tuple[str, str], ...]:
    return tuple(tuple(p) for p in json.loads(raw))


def new_id(nbytes: int = 16) -> str:
    return secrets.token_hex(nbytes)


# ---------------------------------------------------------------------------
# Lookups (every lookup below scopes strictly by run_id + owner_id)
# ---------------------------------------------------------------------------

def owned_claim(conn: sqlite3.Connection, principal: Principal, claim_id: str) -> sqlite3.Row:
    row = conn.execute(
        "SELECT * FROM claims WHERE id = ? AND run_id = ? AND owner_id = ?",
        (claim_id, principal.run_id, principal.id),
    ).fetchone()
    if row is None:
        raise NotFound("claim not found")
    return row


def designated_immutable_root(conn: sqlite3.Connection, run_id: str, parent_id: str | None) -> sqlite3.Row:
    run = conn.execute("SELECT * FROM runs WHERE run_id = ?", (run_id,)).fetchone()
    if run is None or parent_id is None or parent_id != run["root_claim_id"]:
        raise NotFound("parent must be the designated root specimen")
    root = conn.execute(
        "SELECT * FROM claims WHERE id = ? AND run_id = ? AND state = 'ROOT'",
        (parent_id, run_id),
    ).fetchone()
    if root is None:
        raise NotFound("root claim not found")
    return root


def owned_episode_certificate(conn: sqlite3.Connection, principal: Principal, cert_id: str) -> sqlite3.Row:
    row = conn.execute(
        "SELECT * FROM certificates WHERE id = ? AND run_id = ? AND owner_id = ?",
        (cert_id, principal.run_id, principal.id),
    ).fetchone()
    if row is None:
        raise NotFound("certificate not found")
    return row


def owned_resource_by_name(conn: sqlite3.Connection, run_id: str, name: str) -> sqlite3.Row:
    run = conn.execute("SELECT * FROM runs WHERE run_id = ?", (run_id,)).fetchone()
    if run is None:
        raise NotFound("run not found")
    rid = {"demo": run["demo_resource_id"], "vault": run["vault_resource_id"]}.get(name)
    if rid is None:
        raise NotFound("unknown resource")
    row = conn.execute("SELECT * FROM resources WHERE id = ? AND run_id = ?", (rid, run_id)).fetchone()
    if row is None:
        raise NotFound("resource not found")
    return row


def owned_job(conn: sqlite3.Connection, principal: Principal, job_id: str) -> sqlite3.Row:
    row = conn.execute(
        "SELECT * FROM jobs WHERE id = ? AND run_id = ? AND owner_id = ?",
        (job_id, principal.run_id, principal.id),
    ).fetchone()
    if row is None:
        raise NotFound("job not found")
    return row


def record_event(conn: sqlite3.Connection, run_id: str, principal_id: str, kind: str,
                  claim_id: str | None = None, certificate_id: str | None = None,
                  job_id: str | None = None) -> None:
    conn.execute(
        "INSERT INTO events (run_id, principal_id, kind, claim_id, certificate_id, job_id)"
        " VALUES (?, ?, ?, ?, ?, ?)",
        (run_id, principal_id, kind, claim_id, certificate_id, job_id),
    )


# ---------------------------------------------------------------------------
# Claim lifecycle: DRAFT -> VERIFIED -> SEALED
# ---------------------------------------------------------------------------

def create_claim(conn: sqlite3.Connection, principal: Principal, parent_id: str) -> sqlite3.Row:
    with transaction(conn):
        root = designated_immutable_root(conn, principal.run_id, parent_id)
        root_pairs = pairs_from_json(root["pairs_json"])
        cid = new_id()
        d = digest(root_pairs)
        conn.execute(
            "INSERT INTO claims (id, run_id, owner_id, parent_id, state, pairs_json, digest,"
            " approved_digest, verified_root_id) VALUES (?, ?, ?, ?, 'DRAFT', ?, ?, NULL, NULL)",
            (cid, principal.run_id, principal.id, root["id"], pairs_to_json(root_pairs), d),
        )
        record_event(conn, principal.run_id, principal.id, "claim_created", claim_id=cid)
        return conn.execute("SELECT * FROM claims WHERE id = ?", (cid,)).fetchone()


def update_claim(conn: sqlite3.Connection, principal: Principal, claim_id: str,
                  raw_pairs: list) -> sqlite3.Row:
    with transaction(conn):
        c = owned_claim(conn, principal, claim_id)
        if c["state"] != "DRAFT":
            raise Conflict("claim is not editable")
        pairs = canonical_pairs(raw_pairs)
        pair_set = set(pairs)
        # KEEP SECURE: exact-pair subset check against the fixed base entitlement.
        # Player-controlled pairs may never exceed BASE_PAIRS.
        if not pair_set or not pair_set.issubset(BASE_PAIRS):
            raise Forbidden("pairs must be a non-empty subset of the base entitlement")
        d = digest(pairs)
        conn.execute(
            "UPDATE claims SET pairs_json = ?, digest = ? WHERE id = ?",
            (pairs_to_json(pairs), d, claim_id),
        )
        record_event(conn, principal.run_id, principal.id, "claim_updated", claim_id=claim_id)
        return conn.execute("SELECT * FROM claims WHERE id = ?", (claim_id,)).fetchone()


def verify_claim(conn: sqlite3.Connection, principal: Principal, claim_id: str) -> sqlite3.Row:
    with transaction(conn):
        c = owned_claim(conn, principal, claim_id)
        if c["state"] != "DRAFT":
            raise Conflict("claim is not in DRAFT state")
        root = designated_immutable_root(conn, principal.run_id, c["parent_id"])
        if root["approved_digest"] is None:
            raise Conflict("root has no approved digest")
        # BUG 1 (intentional): the correct check would be
        #   require(c["digest"] == root["approved_digest"])
        # i.e. the claim's current content must match what the root actually approved.
        # This implementation only checks that the claim's parent IS the trusted root,
        # and accepts ANY claim digest as verified. Do not "fix" this — it is one of
        # the two deliberate vulnerabilities the challenge depends on.
        conn.execute(
            "UPDATE claims SET state = 'VERIFIED', verified_root_id = ? WHERE id = ?",
            (root["id"], claim_id),
        )
        record_event(conn, principal.run_id, principal.id, "claim_verified", claim_id=claim_id)
        return conn.execute("SELECT * FROM claims WHERE id = ?", (claim_id,)).fetchone()


def seal_claim(conn: sqlite3.Connection, principal: Principal, claim_id: str) -> sqlite3.Row:
    with transaction(conn):
        c = owned_claim(conn, principal, claim_id)
        if c["state"] != "VERIFIED":
            raise Conflict("claim is not VERIFIED")
        pairs = pairs_from_json(c["pairs_json"])
        if digest(pairs) != c["digest"]:
            raise Conflict("claim digest inconsistent")
        kid = new_id(32)  # 256-bit opaque certificate id
        conn.execute(
            "INSERT INTO certificates (id, run_id, owner_id, claim_id, digest, pairs_json)"
            " VALUES (?, ?, ?, ?, ?, ?)",
            (kid, principal.run_id, principal.id, claim_id, c["digest"], c["pairs_json"]),
        )
        conn.execute("UPDATE claims SET state = 'SEALED' WHERE id = ?", (claim_id,))
        record_event(conn, principal.run_id, principal.id, "certificate_issued",
                     claim_id=claim_id, certificate_id=kid)
        return conn.execute("SELECT * FROM certificates WHERE id = ?", (kid,)).fetchone()


# ---------------------------------------------------------------------------
# Export / materialization
# ---------------------------------------------------------------------------

RESOURCE_ACTIONS = {"stat", "read"}


def _fixed_stat(resource_row: sqlite3.Row) -> bytes:
    meta = json.loads(resource_row["metadata_json"])
    return json.dumps(meta, separators=(",", ":")).encode("utf-8")


def export(conn: sqlite3.Connection, principal: Principal, certificate_id: str,
           resource: str, action: str) -> sqlite3.Row:
    if action not in RESOURCE_ACTIONS:
        raise Invalid("unsupported action")
    with transaction(conn):
        k = owned_episode_certificate(conn, principal, certificate_id)
        claim = conn.execute(
            "SELECT * FROM claims WHERE id = ? AND run_id = ?",
            (k["claim_id"], principal.run_id),
        ).fetchone()
        if claim is None or claim["state"] != "SEALED" or claim["digest"] != k["digest"]:
            raise Conflict("certificate does not match a sealed claim")
        pairs = pairs_from_json(k["pairs_json"])
        # BUG 2 (intentional): the correct check is the exact pair membership test
        #   require((resource, action) in pairs)
        # This implementation instead checks resource-membership and action-membership
        # SEPARATELY against the projected sets, which lets an attacker combine a
        # resource from one authorized pair with an action from a DIFFERENT authorized
        # pair. Do not "fix" this — it is one of the two deliberate vulnerabilities the
        # challenge depends on.
        resources_ok = {r for r, a in pairs}
        actions_ok = {a for r, a in pairs}
        if not (resource in resources_ok and action in actions_ok):
            raise Forbidden("export not authorized by certificate")
        # Correct check (kept here only as documentation, intentionally unused):
        #   if (resource, action) not in pairs: raise Forbidden(...)
        resource_row = owned_resource_by_name(conn, principal.run_id, resource)
        payload = _fixed_stat(resource_row) if action == "stat" else bytes(resource_row["body"])
        if len(payload) > MAX_BODY_BYTES:
            raise Invalid("payload too large")
        jid = new_id()
        pdigest = hashlib.sha256(payload).hexdigest()
        conn.execute(
            "INSERT INTO jobs (id, run_id, owner_id, certificate_id, resource_id, action,"
            " state, payload, payload_digest) VALUES (?, ?, ?, ?, ?, ?, 'READY', ?, ?)",
            (jid, principal.run_id, principal.id, certificate_id, resource_row["id"], action,
             payload, pdigest),
        )
        record_event(conn, principal.run_id, principal.id, "job_materialized",
                     certificate_id=certificate_id, job_id=jid)
        return conn.execute("SELECT * FROM jobs WHERE id = ?", (jid,)).fetchone()
