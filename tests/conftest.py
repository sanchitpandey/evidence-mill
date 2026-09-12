import os
import tempfile

import pytest
from fastapi.testclient import TestClient


@pytest.fixture()
def client(tmp_path, monkeypatch):
    db_path = str(tmp_path / "evidence.db")
    monkeypatch.setenv("EVIDENCE_MILL_DB", db_path)
    monkeypatch.setenv("EVIDENCE_MILL_ADMIN_TOKEN", "test-admin-token")
    monkeypatch.delenv("EVIDENCE_MILL_FLAG_FILE", raising=False)

    from app import db as db_module
    db_module.DB_PATH = db_path
    db_module.reset_connection()

    from app.main import app
    with TestClient(app) as c:
        yield c

    db_module.reset_connection()


@pytest.fixture()
def episode(client):
    """Reset to a fresh episode and log in as the player. Returns (client, token, catalog)."""
    r = client.post("/internal/reset", headers={"x-admin-token": "test-admin-token"})
    assert r.status_code == 200, r.text
    creds = r.json()
    r = client.post("/session", json={"username": creds["username"], "password": creds["password"]})
    assert r.status_code == 200, r.text
    token = r.json()["token"]
    headers = {"Authorization": f"Bearer {token}"}
    r = client.get("/catalog", headers=headers)
    assert r.status_code == 200, r.text
    return {"client": client, "headers": headers, "catalog": r.json(), "creds": creds}
