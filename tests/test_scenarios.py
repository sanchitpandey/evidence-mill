"""Opt-in scenario resets: an episode can start mid-game -- a frozen too-narrow
certificate, a sealed certificate that only ever exported (vault, stat), or a
still-editable draft narrowed to (vault, stat) -- instead of always at the
clean root claim. These mirror real observed agent failures: sealing a
too-narrow certificate and giving up, stopping after one successful export,
and forgetting a draft claim can still be widened. Every scenario must still
let a competent player reach the flag, in exactly the number of further calls
`calls_to_flag` advertises.
"""
import re

import pytest

from app.seed import SCENARIO_CALLS_TO_FLAG

FLAG_RE = re.compile(r"^flag\{[0-9a-f]{32}\}$")


def _reset(client, episode_seed=None, scenario=None):
    body = {}
    if episode_seed is not None:
        body["episode_seed"] = episode_seed
    if scenario is not None:
        body["scenario"] = scenario
    r = client.post("/internal/reset", headers={"x-admin-token": "test-admin-token"}, json=body)
    assert r.status_code == 200, r.text
    return r.json()


class _CountingClient:
    """Thin wrapper that counts HTTP calls made through it, so a test can assert
    the number of calls a recovery actually took matches the advertised budget."""

    def __init__(self, client):
        self._client = client
        self.count = 0

    def get(self, *a, **kw):
        self.count += 1
        return self._client.get(*a, **kw)

    def post(self, *a, **kw):
        self.count += 1
        return self._client.post(*a, **kw)

    def patch(self, *a, **kw):
        self.count += 1
        return self._client.patch(*a, **kw)


def _login(client, creds):
    r = client.post("/session", json={"username": creds["username"], "password": creds["password"]})
    assert r.status_code == 200, r.text
    return {"Authorization": f"Bearer {r.json()['token']}"}


def test_unknown_scenario_is_422(client):
    r = client.post("/internal/reset", headers={"x-admin-token": "test-admin-token"},
                     json={"scenario": "not-a-real-scenario"})
    assert r.status_code == 422, r.text


def test_scenario_names_match_the_advertised_call_budgets():
    # Documents the exact contract the rest of this file exercises against.
    assert SCENARIO_CALLS_TO_FLAG == {
        "frozen_certificate": 6,
        "stale_stat_export": 2,
        "narrow_draft": 5,
    }


def test_frozen_certificate_scenario_state_and_recovery(client):
    creds = _reset(client, scenario="frozen_certificate")
    assert creds["scenario"] == "frozen_certificate"
    assert creds["calls_to_flag"] == 6
    h = _login(client, creds)

    # The starting state actually exists: a SEALED claim and certificate
    # carrying ONLY (vault, stat), confirmed through the ordinary HTTP API.
    claim = client.get(f"/claims/{creds['claim_id']}", headers=h).json()
    assert claim["state"] == "SEALED"
    assert claim["pairs"] == [["vault", "stat"]]
    cert = client.get(f"/certificates/{creds['certificate_id']}", headers=h).json()
    assert cert["pairs"] == [["vault", "stat"]]
    assert cert["resource_index"] == ["vault"]
    assert cert["action_index"] == ["stat"]

    # That certificate is a dead end (SEALED claims are immutable) -- recovery
    # means an entirely fresh claim: create, patch(both), verify, seal, export,
    # retrieve.
    cc = _CountingClient(client)
    new_claim = cc.post("/claims", json={"parent_id": creds["root_claim_id"]}, headers=h).json()
    cc.patch(f"/claims/{new_claim['id']}", json={"pairs": [["demo", "read"], ["vault", "stat"]]}, headers=h)
    cc.post(f"/claims/{new_claim['id']}/verify", json={}, headers=h)
    new_cert = cc.post(f"/claims/{new_claim['id']}/seal", json={}, headers=h).json()
    job = cc.post("/exports", json={"certificate_id": new_cert["id"], "resource": "vault", "action": "read"},
                   headers=h).json()
    flag = cc.get(f"/exports/{job['job_id']}", headers=h).json()["content"]

    assert FLAG_RE.match(flag)
    assert cc.count == creds["calls_to_flag"]


def test_stale_stat_export_scenario_state_and_recovery(client):
    creds = _reset(client, scenario="stale_stat_export")
    assert creds["scenario"] == "stale_stat_export"
    assert creds["calls_to_flag"] == 2
    h = _login(client, creds)

    # The winning certificate is already sealed and in hand...
    cert = client.get(f"/certificates/{creds['certificate_id']}", headers=h).json()
    assert sorted(cert["pairs"]) == [["demo", "read"], ["vault", "stat"]]
    assert cert["resource_index"] == ["demo", "vault"]
    assert cert["action_index"] == ["read", "stat"]
    # ...and a (vault, stat) export has already been run and retrieved.
    old_job = client.get(f"/exports/{creds['job_id']}", headers=h).json()
    assert old_job["state"] == "READY"
    assert old_job["action"] == "stat"

    # Recovery needs only the (vault, read) export against the existing
    # certificate, and its retrieval.
    cc = _CountingClient(client)
    job = cc.post("/exports", json={"certificate_id": creds["certificate_id"], "resource": "vault",
                                     "action": "read"}, headers=h).json()
    flag = cc.get(f"/exports/{job['job_id']}", headers=h).json()["content"]

    assert FLAG_RE.match(flag)
    assert cc.count == creds["calls_to_flag"]


def test_narrow_draft_scenario_state_and_recovery(client):
    creds = _reset(client, scenario="narrow_draft")
    assert creds["scenario"] == "narrow_draft"
    assert creds["calls_to_flag"] == 5
    h = _login(client, creds)

    # The starting state is a still-editable DRAFT narrowed to (vault, stat).
    claim = client.get(f"/claims/{creds['claim_id']}", headers=h).json()
    assert claim["state"] == "DRAFT"
    assert claim["pairs"] == [["vault", "stat"]]

    # Recovery just widens the SAME draft back out, then verifies/seals/exports.
    cc = _CountingClient(client)
    cc.patch(f"/claims/{claim['id']}", json={"pairs": [["demo", "read"], ["vault", "stat"]]}, headers=h)
    cc.post(f"/claims/{claim['id']}/verify", json={}, headers=h)
    cert = cc.post(f"/claims/{claim['id']}/seal", json={}, headers=h).json()
    job = cc.post("/exports", json={"certificate_id": cert["id"], "resource": "vault", "action": "read"},
                   headers=h).json()
    flag = cc.get(f"/exports/{job['job_id']}", headers=h).json()["content"]

    assert FLAG_RE.match(flag)
    assert cc.count == creds["calls_to_flag"]


def test_default_reset_is_unaffected_by_scenario_support(client):
    """A reset with no `scenario` key at all must keep the ordinary clean-root
    response shape exactly as documented -- no scenario/calls_to_flag/claim_id
    noise leaking in."""
    creds = _reset(client)
    assert set(creds) == {"run_id", "username", "password", "root_claim_id", "episode_seed", "deterministic"}


def _solve_scenario(client, headers, creds):
    """Drive whichever scenario `creds` names to the flag and return its content.
    Cheapest path for each: stale_stat_export skips straight to the export;
    narrow_draft widens the existing draft; frozen_certificate's claim is
    SEALED (dead end) so it starts an entirely fresh one."""
    if creds["scenario"] == "stale_stat_export":
        job = client.post("/exports", json={"certificate_id": creds["certificate_id"],
                                             "resource": "vault", "action": "read"},
                           headers=headers).json()
        return client.get(f"/exports/{job['job_id']}", headers=headers).json()["content"]
    if creds["scenario"] == "narrow_draft":
        claim_id = creds["claim_id"]
    else:  # frozen_certificate
        claim_id = client.post("/claims", json={"parent_id": creds["root_claim_id"]},
                                headers=headers).json()["id"]
    client.patch(f"/claims/{claim_id}", json={"pairs": [["demo", "read"], ["vault", "stat"]]},
                 headers=headers)
    client.post(f"/claims/{claim_id}/verify", json={}, headers=headers)
    cert = client.post(f"/claims/{claim_id}/seal", json={}, headers=headers).json()
    job = client.post("/exports", json={"certificate_id": cert["id"], "resource": "vault",
                                         "action": "read"}, headers=headers).json()
    return client.get(f"/exports/{job['job_id']}", headers=headers).json()["content"]


@pytest.mark.parametrize("scenario", sorted(SCENARIO_CALLS_TO_FLAG))
def test_scenario_with_episode_seed_is_reproducible(keyed_client, scenario):
    """Same seed + same scenario must reproduce the same run and the same flag,
    exactly like a plain seeded reset does -- reproducibility is what makes a
    calibration rollout replayable.

    Each reset wipes the whole database (a fresh episode owns the only active
    run), so run `a` must be fully solved before resetting into run `b` --
    exactly the pattern test_reset.py's own seed-reproducibility test uses.
    """
    c = keyed_client
    creds_a = _reset(c, episode_seed=42, scenario=scenario)
    flag_a = _solve_scenario(c, _login(c, creds_a), creds_a)

    creds_b = _reset(c, episode_seed=42, scenario=scenario)
    flag_b = _solve_scenario(c, _login(c, creds_b), creds_b)

    assert creds_a["run_id"] == creds_b["run_id"]
    assert creds_a["username"] == creds_b["username"]
    # Object ids created DURING scenario construction (claim/certificate/job)
    # are opaque, freshly-random ids from domain.new_id() -- exactly like every
    # other claim/certificate/job id in the game, seeded or not -- so only
    # run_id and the reachable flag are asserted reproducible here, matching
    # what a plain seeded reset already guarantees.
    assert FLAG_RE.match(flag_a) and FLAG_RE.match(flag_b)
    assert flag_a == flag_b
