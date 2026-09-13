"""Gate 5/6: reset produces a fully isolated new episode -- new credentials, new
session space, new resource/claim IDs, new flag -- and leaves exactly one active
run behind."""
import re

from app.db import get_conn

FLAG_RE = re.compile(r"^flag\{[0-9a-f]{32}\}$")


def _reset(client, episode_seed=None):
    body = {} if episode_seed is None else {"episode_seed": episode_seed}
    r = client.post("/internal/reset", headers={"x-admin-token": "test-admin-token"}, json=body)
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


def _solve_for_flag(client, creds):
    token = client.post("/session", json={"username": creds["username"],
                                           "password": creds["password"]}).json()["token"]
    h = {"Authorization": f"Bearer {token}"}
    root = client.get("/catalog", headers=h).json()["root"]["id"]
    claim = client.post("/claims", json={"parent_id": root}, headers=h).json()
    client.patch(f"/claims/{claim['id']}", json={"pairs": [["demo", "read"], ["vault", "stat"]]}, headers=h)
    client.post(f"/claims/{claim['id']}/verify", json={}, headers=h)
    cert = client.post(f"/claims/{claim['id']}/seal", json={}, headers=h).json()
    job = client.post("/exports", json={"certificate_id": cert["id"], "resource": "vault", "action": "read"},
                       headers=h).json()
    return client.get(f"/exports/{job['job_id']}", headers=h).json()["content"]


def test_reset_rotates_the_flag_under_the_shipped_key_file_config(keyed_client):
    """The shipped configuration mounts an episode-key file, so flag rotation has
    to be asserted under that configuration and not only in the keyless test
    setup: with an episode-key file mounted -- the configuration compose.yml
    actually ships -- two consecutive resets must still produce two different
    flags."""
    c = keyed_client
    flag_a = _solve_for_flag(c, _reset(c))
    flag_b = _solve_for_flag(c, _reset(c))
    assert FLAG_RE.match(flag_a) and FLAG_RE.match(flag_b)
    assert flag_a != flag_b


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


def test_startup_warns_when_the_secret_mounts_are_missing(tmp_path, monkeypatch, capsys):
    """A bare `docker compose up` leaves Docker-created DIRECTORIES where the two
    secret files should be, and the container then starts with no admin token --
    every reset 404s for a reason nothing explains. Startup must name the problem
    and the fix instead of failing mysteriously later."""
    from app import main as main_module

    # Exactly what a bare `docker compose up` leaves behind: directories where the
    # two secret FILES should be. No monkeypatching of module state -- the guard is
    # driven through the same environment the container would actually see.
    (tmp_path / "episode_key").mkdir()
    (tmp_path / "admin_token").mkdir()
    monkeypatch.setenv("EVIDENCE_MILL_EPISODE_KEY_FILE", str(tmp_path / "episode_key"))
    monkeypatch.setenv("EVIDENCE_MILL_ADMIN_TOKEN_FILE", str(tmp_path / "admin_token"))
    monkeypatch.delenv("EVIDENCE_MILL_ADMIN_TOKEN", raising=False)

    problems = main_module._startup_configuration_warnings()
    assert len(problems) == 2
    assert "is a directory" in problems[0]
    assert "/internal/reset will return 404" in problems[1]


def test_startup_is_silent_when_configured_correctly(tmp_path, monkeypatch):
    from app import main as main_module

    key = tmp_path / "episode_key"
    key.write_text("k" * 32, encoding="utf-8")
    token = tmp_path / "admin_token"
    token.write_text("a-token", encoding="utf-8")
    monkeypatch.setenv("EVIDENCE_MILL_EPISODE_KEY_FILE", str(key))
    monkeypatch.setenv("EVIDENCE_MILL_ADMIN_TOKEN_FILE", str(token))
    assert main_module._startup_configuration_warnings() == []


def _episode_fingerprint(client, creds):
    """Everything about the initial environment the agent can observe."""
    token = client.post("/session", json={"username": creds["username"],
                                           "password": creds["password"]}).json()["token"]
    h = {"Authorization": f"Bearer {token}"}
    catalog = client.get("/catalog", headers=h).json()
    return {
        "run_id": creds["run_id"],
        "username": creds["username"],
        "password": creds["password"],
        "root_claim_id": creds["root_claim_id"],
        "root": catalog["root"],
        "resource_ids": sorted(r["id"] for r in catalog["resources"].values()),
        "flag": _solve_for_flag(client, creds),
    }


def test_the_same_episode_seed_reproduces_the_entire_initial_environment(keyed_client):
    """Seeding the sampler is not enough for a replayable rollout: the agent's
    observations carry the episode's ids and credentials, so an unseeded
    environment feeds a different prompt on every run. With an episode seed, the
    whole initial environment -- ids, credentials, root claim and flag -- comes
    back identical."""
    c = keyed_client
    a = _episode_fingerprint(c, _reset(c, episode_seed=7))
    b = _episode_fingerprint(c, _reset(c, episode_seed=7))
    assert a == b
    assert FLAG_RE.match(a["flag"])


def test_different_episode_seeds_give_different_environments(keyed_client):
    c = keyed_client
    a = _episode_fingerprint(c, _reset(c, episode_seed=7))
    b = _episode_fingerprint(c, _reset(c, episode_seed=8))
    assert a["run_id"] != b["run_id"]
    assert a["username"] != b["username"]
    assert a["flag"] != b["flag"]


def test_seeded_episodes_are_not_predictable_without_the_runtime_key(keyed_client, tmp_path,
                                                                     monkeypatch):
    """The seed is public -- it lives in agent.json and is printed in reports.
    Identifiers are derived from HMAC(episode key, seed), so the same seed under a
    DIFFERENT runtime key yields a completely different episode. Reproducibility
    for the evaluator, secrecy from everyone else."""
    from app import seed as seed_module

    ids_key_a = seed_module.EpisodeIdentifiers(7, b"key-a")
    ids_key_b = seed_module.EpisodeIdentifiers(7, b"key-b")
    assert ids_key_a.token_hex("run_id") != ids_key_b.token_hex("run_id")
    assert ids_key_a.username() != ids_key_b.username()
    assert ids_key_a.password() != ids_key_b.password()

    # ...while the same key and seed are stable.
    assert ids_key_a.token_hex("run_id") == seed_module.EpisodeIdentifiers(7, b"key-a").token_hex("run_id")


def test_an_unseeded_reset_is_still_fully_random(keyed_client):
    """Random remains the default, so a hosted deployment is unaffected."""
    c = keyed_client
    a, b = _reset(c), _reset(c)
    assert a["deterministic"] is False and b["deterministic"] is False
    assert a["run_id"] != b["run_id"] and a["username"] != b["username"]


def test_admin_token_is_read_at_call_time_not_import_time(tmp_path, monkeypatch):
    """The admin token must be read fresh on every call, not bound once at import
    time: compose.yml supplies it via EVIDENCE_MILL_ADMIN_TOKEN_FILE for the
    running container, so a rotated file has to take effect on the very next
    call, and the file form must win over a plain EVIDENCE_MILL_ADMIN_TOKEN value
    whenever both are present."""
    from app import main as main_module

    token_file = tmp_path / "admin_token"
    token_file.write_text("first-secret", encoding="utf-8")
    monkeypatch.setenv("EVIDENCE_MILL_ADMIN_TOKEN_FILE", str(token_file))
    assert main_module.admin_token() == "first-secret"

    # Rotate the file on disk: the next call must see the new value.
    token_file.write_text("rotated-secret", encoding="utf-8")
    assert main_module.admin_token() == "rotated-secret"

    # The file form wins over the inline form, as the container relies on.
    monkeypatch.setenv("EVIDENCE_MILL_ADMIN_TOKEN", "inline-value")
    assert main_module.admin_token() == "rotated-secret"

    monkeypatch.delenv("EVIDENCE_MILL_ADMIN_TOKEN_FILE")
    assert main_module.admin_token() == "inline-value"


def test_seeding_reproduces_the_starting_state_but_not_runtime_identifiers(keyed_client):
    """Pins the exact scope of the reproducibility claim: seeding reproduces the
    episode's STARTING state, not its entire trajectory.

    Identifiers minted while the episode runs -- session tokens and claim ids --
    come from secrets.token_hex at creation time and are fresh every run. They
    appear in the agent's observations, so two runs of one seed diverge the
    moment the agent acts, and no seeded sampler can replay a trajectory across
    that. Stating the limit is not enough on its own; if runtime ids ever became
    derivable this test should fail, forcing the claim to be widened
    deliberately rather than by accident.
    """
    c = keyed_client

    creds_a = _reset(c, episode_seed=99)
    token_a = c.post("/session", json={"username": creds_a["username"],
                                        "password": creds_a["password"]}).json()["token"]
    ha = {"Authorization": f"Bearer {token_a}"}
    claim_a = c.post("/claims", json={"parent_id": creds_a["root_claim_id"]}, headers=ha).json()

    creds_b = _reset(c, episode_seed=99)
    token_b = c.post("/session", json={"username": creds_b["username"],
                                        "password": creds_b["password"]}).json()["token"]
    hb = {"Authorization": f"Bearer {token_b}"}
    claim_b = c.post("/claims", json={"parent_id": creds_b["root_claim_id"]}, headers=hb).json()

    # Reproduced: everything the episode starts with.
    assert creds_a == creds_b

    # Not reproduced: anything minted during play.
    assert token_a != token_b, "session tokens are per-login random"
    assert claim_a["id"] != claim_b["id"], "claim ids are per-creation random"
