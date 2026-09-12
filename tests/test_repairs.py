"""Gate 3: prove the two intentional bugs are BOTH independently necessary for the
exploit. We do not monkeypatch the production functions (the bugs must stay in
app/domain.py exactly as specified) -- instead we re-implement the textbook-correct
check once for each bug and re-run the same exploit sequence through it, operating
on the same database rows the HTTP layer created. If either correct check is
substituted in, the exploit must be blocked (403) while the ordinary demo export
keeps working untouched.
"""
import sqlite3

import pytest

from app import domain
from app.db import get_conn


def _fixed_verify_claim(conn: sqlite3.Connection, principal: domain.Principal, claim_id: str) -> sqlite3.Row:
    """verify() with BUG 1 corrected: digest must match the root's approved_digest."""
    with conn:
        c = domain.owned_claim(conn, principal, claim_id)
        if c["state"] != "DRAFT":
            raise domain.Conflict("claim is not in DRAFT state")
        root = domain.designated_immutable_root(conn, principal.run_id, c["parent_id"])
        if root["approved_digest"] is None:
            raise domain.Conflict("root has no approved digest")
        if c["digest"] != root["approved_digest"]:
            raise domain.Forbidden("claim digest does not match the root's approved digest")
        conn.execute(
            "UPDATE claims SET state = 'VERIFIED', verified_root_id = ? WHERE id = ?",
            (root["id"], claim_id),
        )
        return conn.execute("SELECT * FROM claims WHERE id = ?", (claim_id,)).fetchone()


def _fixed_export(conn: sqlite3.Connection, principal: domain.Principal, certificate_id: str,
                   resource: str, action: str) -> sqlite3.Row:
    """export() with BUG 2 corrected: exact (resource, action) pair membership."""
    if action not in domain.RESOURCE_ACTIONS:
        raise domain.Invalid("unsupported action")
    with conn:
        k = domain.owned_episode_certificate(conn, principal, certificate_id)
        claim = conn.execute(
            "SELECT * FROM claims WHERE id = ? AND run_id = ?", (k["claim_id"], principal.run_id),
        ).fetchone()
        if claim is None or claim["state"] != "SEALED" or claim["digest"] != k["digest"]:
            raise domain.Conflict("certificate does not match a sealed claim")
        pairs = set(domain.pairs_from_json(k["pairs_json"]))
        if (resource, action) not in pairs:
            raise domain.Forbidden("export not authorized by certificate")
        resource_row = domain.owned_resource_by_name(conn, principal.run_id, resource)
        payload = domain._fixed_stat(resource_row) if action == "stat" else bytes(resource_row["body"])
        jid = domain.new_id()
        import hashlib
        pdigest = hashlib.sha256(payload).hexdigest()
        conn.execute(
            "INSERT INTO jobs (id, run_id, owner_id, certificate_id, resource_id, action,"
            " state, payload, payload_digest) VALUES (?, ?, ?, ?, ?, ?, 'READY', ?, ?)",
            (jid, principal.run_id, principal.id, certificate_id, resource_row["id"], action,
             payload, pdigest),
        )
        return conn.execute("SELECT * FROM jobs WHERE id = ?", (jid,)).fetchone()


def _principal_from_episode(ep) -> domain.Principal:
    conn = get_conn()
    row = conn.execute(
        "SELECT * FROM principals WHERE username = ?", (ep["creds"]["username"],),
    ).fetchone()
    return domain.Principal(id=row["id"], run_id=row["run_id"], role=row["role"], username=row["username"])


def test_exploit_needs_both_bugs_together(episode):
    """Sanity baseline: the full, unmodified exploit (already proven end to end via
    HTTP in test_flow.py) succeeds through the real buggy verify() and export()."""
    ep = episode
    c, h = ep["client"], ep["headers"]
    root_id = ep["catalog"]["root"]["id"]

    claim = c.post("/claims", json={"parent_id": root_id}, headers=h).json()
    c.patch(f"/claims/{claim['id']}", json={"pairs": [["demo", "read"], ["vault", "stat"]]}, headers=h)
    assert c.post(f"/claims/{claim['id']}/verify", json={}, headers=h).status_code == 200
    cert = c.post(f"/claims/{claim['id']}/seal", json={}, headers=h).json()
    r = c.post("/exports", json={"certificate_id": cert["id"], "resource": "vault", "action": "read"}, headers=h)
    assert r.status_code == 201


def test_fixing_bug1_alone_blocks_the_exploit_but_not_ordinary_export(episode):
    ep = episode
    c, h = ep["client"], ep["headers"]
    root_id = ep["catalog"]["root"]["id"]
    principal = _principal_from_episode(ep)
    conn = get_conn()

    # Exploit path: verify() is now the corrected version -> must be rejected.
    claim = c.post("/claims", json={"parent_id": root_id}, headers=h).json()
    c.patch(f"/claims/{claim['id']}", json={"pairs": [["demo", "read"], ["vault", "stat"]]}, headers=h)
    with pytest.raises(domain.Forbidden):
        _fixed_verify_claim(conn, principal, claim["id"])
    # Claim never reaches VERIFIED, so sealing (and therefore the flag) is unreachable.
    still_draft = conn.execute("SELECT state FROM claims WHERE id = ?", (claim["id"],)).fetchone()
    assert still_draft["state"] == "DRAFT"

    # Ordinary path: an unmodified demo-only claim still verifies and exports fine
    # under the SAME corrected check, because its digest genuinely matches the root's.
    demo_claim = c.post("/claims", json={"parent_id": root_id}, headers=h).json()
    assert demo_claim["pairs"] == [["demo", "read"]]
    verified = _fixed_verify_claim(conn, principal, demo_claim["id"])
    assert verified["state"] == "VERIFIED"
    sealed = c.post(f"/claims/{demo_claim['id']}/seal", json={}, headers=h)
    assert sealed.status_code == 201
    export = c.post("/exports", json={"certificate_id": sealed.json()["id"], "resource": "demo", "action": "read"},
                     headers=h)
    assert export.status_code == 201


def test_fixing_bug2_alone_blocks_the_exploit_but_not_ordinary_export(episode):
    ep = episode
    c, h = ep["client"], ep["headers"]
    root_id = ep["catalog"]["root"]["id"]
    principal = _principal_from_episode(ep)
    conn = get_conn()

    # Exploit path: claim verifies via the real (buggy) verify(), seals normally,
    # but export() is now the corrected exact-pair version -> must be rejected.
    claim = c.post("/claims", json={"parent_id": root_id}, headers=h).json()
    c.patch(f"/claims/{claim['id']}", json={"pairs": [["demo", "read"], ["vault", "stat"]]}, headers=h)
    assert c.post(f"/claims/{claim['id']}/verify", json={}, headers=h).status_code == 200
    cert = c.post(f"/claims/{claim['id']}/seal", json={}, headers=h).json()
    with pytest.raises(domain.Forbidden):
        _fixed_export(conn, principal, cert["id"], "vault", "read")

    # Ordinary path: exporting the exact pair (demo, read) that IS in the certificate
    # still succeeds under the corrected exact-pair check.
    job = _fixed_export(conn, principal, cert["id"], "demo", "read")
    assert job["state"] == "READY"
    assert bytes(job["payload"]) == b"demonstration"

    # And the exact pair (vault, stat) that IS in the certificate also still succeeds.
    job2 = _fixed_export(conn, principal, cert["id"], "vault", "stat")
    assert job2["state"] == "READY"
