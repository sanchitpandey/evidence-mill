import os
import tempfile

import pytest
from fastapi.testclient import TestClient


@pytest.fixture()
def client(tmp_path, monkeypatch):
    db_path = str(tmp_path / "evidence.db")
    monkeypatch.setenv("EVIDENCE_MILL_DB", db_path)
    monkeypatch.setenv("EVIDENCE_MILL_ADMIN_TOKEN", "test-admin-token")
    # compose sets the *_FILE form for the tooling image; without clearing it the
    # real container secret wins and every /internal/reset in the suite 404s.
    monkeypatch.delenv("EVIDENCE_MILL_ADMIN_TOKEN_FILE", raising=False)
    monkeypatch.delenv("EVIDENCE_MILL_EPISODE_KEY_FILE", raising=False)

    from app import db as db_module
    db_module.DB_PATH = db_path
    db_module.reset_connection()

    from app.main import app
    with TestClient(app) as c:
        yield c

    db_module.reset_connection()


@pytest.fixture()
def keyed_client(tmp_path, monkeypatch):
    """Client running the SHIPPED container configuration: an episode-key file is
    present, exactly as compose.yml mounts one. The plain `client` fixture runs
    keyless, so flag rotation has to be asserted under this configuration too --
    not only in the keyless test setup -- to confirm every episode gets a
    distinct flag under the configuration that actually ships."""
    key_file = tmp_path / "episode_key"
    key_file.write_text("0123456789abcdef" * 4, encoding="utf-8")
    db_path = str(tmp_path / "evidence_keyed.db")
    monkeypatch.setenv("EVIDENCE_MILL_DB", db_path)
    monkeypatch.setenv("EVIDENCE_MILL_ADMIN_TOKEN", "test-admin-token")
    # compose sets the *_FILE form for the tooling image; without clearing it the
    # real container secret wins and every /internal/reset in the suite 404s.
    monkeypatch.delenv("EVIDENCE_MILL_ADMIN_TOKEN_FILE", raising=False)
    monkeypatch.setenv("EVIDENCE_MILL_EPISODE_KEY_FILE", str(key_file))

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
