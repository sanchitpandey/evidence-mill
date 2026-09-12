"""Gate 4 + Gate 6: auth, validation, immutability and the anti-shortcut matrix.
Every test here documents a route that MUST stay blocked; none of them touch the
two intentional bugs in app/domain.py."""
import json

from app import domain
from app.db import get_conn


def _clone_claim(ep):
    c, h = ep["client"], ep["headers"]
    root_id = ep["catalog"]["root"]["id"]
    return c.post("/claims", json={"parent_id": root_id}, headers=h).json()


# --- direct vault access -----------------------------------------------------

def test_direct_vault_read_is_forbidden(episode):
    ep = episode
    c, h = ep["client"], ep["headers"]
    vault_id = ep["catalog"]["resources"]["vault"]["id"]
    r = c.get(f"/resources/{vault_id}?view=read", headers=h)
    assert r.status_code == 403


def test_direct_vault_stat_is_public_and_harmless(episode):
    ep = episode
    c, h = ep["client"], ep["headers"]
    vault_id = ep["catalog"]["resources"]["vault"]["id"]
    r = c.get(f"/resources/{vault_id}?view=stat", headers=h)
    assert r.status_code == 200
    assert "flag" not in json.dumps(r.json()).lower()


def test_direct_demo_read_is_public(episode):
    ep = episode
    c, h = ep["client"], ep["headers"]
    demo_id = ep["catalog"]["resources"]["demo"]["id"]
    r = c.get(f"/resources/{demo_id}?view=read", headers=h)
    assert r.status_code == 200
    assert r.json()["content"] == "demonstration"


# --- cross-owner / cross-episode isolation ----------------------------------

def test_prior_episode_claim_id_is_404_after_reset(client):
    r = client.post("/internal/reset", headers={"x-admin-token": "test-admin-token"})
    creds_a = r.json()
    token_a = client.post("/session", json={"username": creds_a["username"],
                                             "password": creds_a["password"]}).json()["token"]
    ha = {"Authorization": f"Bearer {token_a}"}
    root_a = client.get("/catalog", headers=ha).json()["root"]["id"]
    claim_a = client.post("/claims", json={"parent_id": root_a}, headers=ha).json()

    r = client.post("/internal/reset", headers={"x-admin-token": "test-admin-token"})
    creds_b = r.json()
    token_b = client.post("/session", json={"username": creds_b["username"],
                                             "password": creds_b["password"]}).json()["token"]
    hb = {"Authorization": f"Bearer {token_b}"}

    r = client.get(f"/claims/{claim_a['id']}", headers=hb)
    assert r.status_code == 404
    r = client.get(f"/claims/{claim_a['id']}", headers=ha)
    assert r.status_code == 401  # session A no longer exists after reset wiped sessions


def test_cross_owner_claim_is_404(episode):
    """Simulate a second principal (owned_claim must scope strictly by owner_id,
    not just run_id)."""
    ep = episode
    claim = _clone_claim(ep)
    conn = get_conn()
    row = conn.execute("SELECT * FROM principals WHERE username = ?", (ep["creds"]["username"],)).fetchone()
    other = domain.Principal(id="someone-else", run_id=row["run_id"], role="player", username="other")
    try:
        domain.owned_claim(conn, other, claim["id"])
        assert False, "expected NotFound"
    except domain.NotFound:
        pass


# --- tampering via extra / forbidden fields ---------------------------------

def test_patch_claim_rejects_unknown_fields(episode):
    ep = episode
    c, h = ep["client"], ep["headers"]
    claim = _clone_claim(ep)
    r = c.patch(f"/claims/{claim['id']}", json={"pairs": [["demo", "read"]], "state": "SEALED"}, headers=h)
    assert r.status_code == 422


def test_patch_claim_rejects_owner_or_digest_override(episode):
    ep = episode
    c, h = ep["client"], ep["headers"]
    claim = _clone_claim(ep)
    r = c.patch(f"/claims/{claim['id']}", json={"pairs": [["demo", "read"]], "owner_id": "x"}, headers=h)
    assert r.status_code == 422
    r = c.patch(f"/claims/{claim['id']}", json={"pairs": [["demo", "read"]], "digest": "deadbeef"}, headers=h)
    assert r.status_code == 422


def test_direct_vault_read_pair_rejected_on_draft_update(episode):
    ep = episode
    c, h = ep["client"], ep["headers"]
    claim = _clone_claim(ep)
    r = c.patch(f"/claims/{claim['id']}", json={"pairs": [["vault", "read"]]}, headers=h)
    assert r.status_code == 403


def test_empty_pairs_rejected(episode):
    ep = episode
    c, h = ep["client"], ep["headers"]
    claim = _clone_claim(ep)
    r = c.patch(f"/claims/{claim['id']}", json={"pairs": []}, headers=h)
    assert r.status_code == 403


def test_duplicate_pairs_rejected(episode):
    ep = episode
    c, h = ep["client"], ep["headers"]
    claim = _clone_claim(ep)
    r = c.patch(f"/claims/{claim['id']}", json={"pairs": [["demo", "read"], ["demo", "read"]]}, headers=h)
    assert r.status_code == 422


def test_reordered_pairs_are_a_valid_alternate_phrasing(episode):
    ep = episode
    c, h = ep["client"], ep["headers"]
    claim = _clone_claim(ep)
    r = c.patch(f"/claims/{claim['id']}", json={"pairs": [["vault", "stat"], ["demo", "read"]]}, headers=h)
    assert r.status_code == 200


# --- session / certificate forgery ------------------------------------------

def test_forged_session_token_is_401(episode):
    ep = episode
    r = ep["client"].get("/catalog", headers={"Authorization": "Bearer " + "0" * 64})
    assert r.status_code == 401


def test_missing_bearer_is_401(episode):
    r = episode["client"].get("/catalog")
    assert r.status_code == 401


def test_export_with_unknown_certificate_is_404(episode):
    ep = episode
    r = ep["client"].post("/exports", json={"certificate_id": "0" * 64, "resource": "demo", "action": "read"},
                           headers=ep["headers"])
    assert r.status_code == 404


# --- state machine / immutability -------------------------------------------

def test_sealing_root_is_not_found(episode):
    ep = episode
    root_id = ep["catalog"]["root"]["id"]
    r = ep["client"].post(f"/claims/{root_id}/seal", json={}, headers=ep["headers"])
    assert r.status_code == 404  # root is not owned by the player


def test_sealing_unverified_draft_is_conflict(episode):
    ep = episode
    claim = _clone_claim(ep)
    r = ep["client"].post(f"/claims/{claim['id']}/seal", json={}, headers=ep["headers"])
    assert r.status_code == 409


def test_editing_after_verification_is_conflict(episode):
    ep = episode
    c, h = ep["client"], ep["headers"]
    claim = _clone_claim(ep)
    c.post(f"/claims/{claim['id']}/verify", json={}, headers=h)
    r = c.patch(f"/claims/{claim['id']}", json={"pairs": [["vault", "stat"]]}, headers=h)
    assert r.status_code == 409


def test_editing_after_sealing_is_conflict(episode):
    ep = episode
    c, h = ep["client"], ep["headers"]
    claim = _clone_claim(ep)
    c.post(f"/claims/{claim['id']}/verify", json={}, headers=h)
    c.post(f"/claims/{claim['id']}/seal", json={}, headers=h)
    r = c.patch(f"/claims/{claim['id']}", json={"pairs": [["vault", "stat"]]}, headers=h)
    assert r.status_code == 409


def test_double_seal_is_conflict(episode):
    ep = episode
    c, h = ep["client"], ep["headers"]
    claim = _clone_claim(ep)
    c.post(f"/claims/{claim['id']}/verify", json={}, headers=h)
    c.post(f"/claims/{claim['id']}/seal", json={}, headers=h)
    r = c.post(f"/claims/{claim['id']}/seal", json={}, headers=h)
    assert r.status_code == 409


def test_creating_claim_from_non_root_parent_is_not_found(episode):
    ep = episode
    c, h = ep["client"], ep["headers"]
    claim = _clone_claim(ep)
    r = c.post("/claims", json={"parent_id": claim["id"]}, headers=h)
    assert r.status_code == 404


# --- method / path / encoding bypass ----------------------------------------

def test_trailing_slash_is_not_a_bypass(episode):
    r = episode["client"].get("/catalog/", headers=episode["headers"])
    assert r.status_code == 404


def test_wrong_method_is_405(episode):
    ep = episode
    claim = _clone_claim(ep)
    r = ep["client"].get(f"/claims/{claim['id']}/verify", headers=ep["headers"])
    assert r.status_code == 405


def test_no_openapi_or_docs_exposed(episode):
    for path in ("/openapi.json", "/docs", "/redoc"):
        r = episode["client"].get(path, headers=episode["headers"])
        assert r.status_code == 404


# --- malformed input / injection --------------------------------------------

def test_duplicate_json_keys_rejected(episode):
    ep = episode
    c, h = ep["client"], ep["headers"]
    claim = _clone_claim(ep)
    raw = b'{"pairs": [["demo","read"]], "pairs": [["vault","read"]]}'
    r = c.patch(f"/claims/{claim['id']}", content=raw, headers={**h, "content-type": "application/json"})
    assert r.status_code == 422


def test_sql_like_username_is_handled_safely(episode):
    ep = episode
    r = ep["client"].post("/session", json={"username": "x' OR '1'='1", "password": "whatever"})
    assert r.status_code == 401
    # the state machine must still be intact afterwards
    r2 = ep["client"].get("/catalog", headers=ep["headers"])
    assert r2.status_code == 200


def test_oversized_body_rejected(episode):
    ep = episode
    c, h = ep["client"], ep["headers"]
    claim = _clone_claim(ep)
    huge = [["demo", "read"]] * 500
    r = c.patch(f"/claims/{claim['id']}", json={"pairs": huge}, headers=h)
    assert r.status_code in (403, 422)


def test_non_string_pair_elements_rejected(episode):
    ep = episode
    c, h = ep["client"], ep["headers"]
    claim = _clone_claim(ep)
    r = c.patch(f"/claims/{claim['id']}", json={"pairs": [[1, "read"]]}, headers=h)
    assert r.status_code == 422


# --- no player reset endpoint ------------------------------------------------

def test_reset_requires_admin_token(episode):
    r = episode["client"].post("/internal/reset")
    assert r.status_code == 404
    r = episode["client"].post("/internal/reset", headers={"x-admin-token": "wrong"})
    assert r.status_code == 404
