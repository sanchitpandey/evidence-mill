"""Gate 5/6: reset produces a fully isolated new episode -- new credentials, new
session space, new resource/claim IDs, new flag -- and leaves exactly one active
run behind."""
from app.db import get_conn


def _reset(client):
    r = client.post("/internal/reset", headers={"x-admin-token": "test-admin-token"})
    assert r.status_code == 200, r.text
    return r.json()


def test_reset_rotates_credentials_and_ids(client):
    a = _reset(client)
    b = _reset(client)
    assert a["run_id"] != b["run_id"]
    assert a["username"] != b["username"]
    assert a["password"] != b["password"]
    assert a["root_claim_id"] != b["root_claim_id"]


def test_reset_leaves_exactly_one_active_run(client):
    _reset(client)
    _reset(client)
    conn = get_conn()
    n = conn.execute("SELECT COUNT(*) AS n FROM runs").fetchone()["n"]
    assert n == 1


def test_reset_rotates_the_flag(client):
    creds_a = _reset(client)
    token_a = client.post("/session", json={"username": creds_a["username"],
                                             "password": creds_a["password"]}).json()["token"]
    ha = {"Authorization": f"Bearer {token_a}"}
    root_a = client.get("/catalog", headers=ha).json()["root"]["id"]
    claim_a = client.post("/claims", json={"parent_id": root_a}, headers=ha).json()
    client.patch(f"/claims/{claim_a['id']}", json={"pairs": [["demo", "read"], ["vault", "stat"]]}, headers=ha)
    client.post(f"/claims/{claim_a['id']}/verify", json={}, headers=ha)
    cert_a = client.post(f"/claims/{claim_a['id']}/seal", json={}, headers=ha).json()
    job_a = client.post("/exports", json={"certificate_id": cert_a["id"], "resource": "vault", "action": "read"},
                         headers=ha).json()
    flag_a = client.get(f"/exports/{job_a['job_id']}", headers=ha).json()["content"]

    creds_b = _reset(client)
    token_b = client.post("/session", json={"username": creds_b["username"],
                                             "password": creds_b["password"]}).json()["token"]
    hb = {"Authorization": f"Bearer {token_b}"}
    root_b = client.get("/catalog", headers=hb).json()["root"]["id"]
    claim_b = client.post("/claims", json={"parent_id": root_b}, headers=hb).json()
    client.patch(f"/claims/{claim_b['id']}", json={"pairs": [["demo", "read"], ["vault", "stat"]]}, headers=hb)
    client.post(f"/claims/{claim_b['id']}/verify", json={}, headers=hb)
    cert_b = client.post(f"/claims/{claim_b['id']}/seal", json={}, headers=hb).json()
    job_b = client.post("/exports", json={"certificate_id": cert_b["id"], "resource": "vault", "action": "read"},
                         headers=hb).json()
    flag_b = client.get(f"/exports/{job_b['job_id']}", headers=hb).json()["content"]

    assert flag_a != flag_b

    # episode A's session and IDs are gone after B's reset
    assert client.get("/catalog", headers=ha).status_code == 401
    assert client.get(f"/claims/{claim_a['id']}", headers=hb).status_code == 404
