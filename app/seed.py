"""Deterministic per-episode seeding: principals, resources, the trusted root claim,
and the runtime-secret flag. Never bakes the flag into the image: the container is
given an episode KEY at runtime and derives a distinct flag per episode from it.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import os
import re
import secrets
import sqlite3
import string

from app import auth
from app.db import transaction
from app.domain import (
    BASE_PAIRS,
    Invalid,
    Principal,
    create_claim,
    digest,
    export,
    pairs_to_json,
    seal_claim,
    update_claim,
    verify_claim,
)

EPISODE_KEY_ENV = "EVIDENCE_MILL_EPISODE_KEY_FILE"
FLAG_RE = re.compile(r"^flag\{[0-9a-f]{32}\}$")

TABLES_IN_DELETE_ORDER = ["events", "jobs", "certificates", "claims", "sessions", "resources",
                          "principals", "runs"]

# ---------------------------------------------------------------------------
# Scenarios: opt-in mid-game starting states.
#
# A clean reset always drops the player at the ROOT claim -- no draft, no
# certificate, nothing sealed. That only exercises an agent's ability to
# prepare a winning claim from scratch. These scenarios instead pre-drive the
# player principal partway through the lifecycle into one of three states
# actually observed in failed calibration rollouts: an agent that seals a
# too-narrow certificate and gives up rather than starting a new claim, an
# agent that stops immediately after one successful export instead of trying
# the second (winning) one, and an agent that narrows a draft claim and
# forgets it can still be widened before verifying. Each mirrors a distinct
# recovery skill, and each records the exact number of further HTTP calls a
# perfect player needs so an evaluator can size the budget it grants.
# ---------------------------------------------------------------------------

SCENARIO_FROZEN_CERTIFICATE = "frozen_certificate"
SCENARIO_STALE_STAT_EXPORT = "stale_stat_export"
SCENARIO_NARROW_DRAFT = "narrow_draft"

# Further HTTP calls a perfect player needs from each starting state through
# to retrieving the flag. Exposed in the reset response so an evaluator can
# size the turn budget it grants without having to re-derive the lifecycle.
SCENARIO_CALLS_TO_FLAG: dict[str, int] = {
    # create, patch(both pairs), verify, seal, export(vault,read), retrieve
    SCENARIO_FROZEN_CERTIFICATE: 6,
    # export(vault,read), retrieve -- the sealed certificate already covers it
    SCENARIO_STALE_STAT_EXPORT: 2,
    # patch(both pairs), verify, seal, export(vault,read), retrieve
    SCENARIO_NARROW_DRAFT: 5,
}


def _episode_key() -> bytes | None:
    """Read the runtime episode key. Read at call time, not import time: the
    container supplies this via a file while tests supply it via the
    environment (or not at all), so binding it once at import would make the
    two configurations disagree."""
    path = os.environ.get(EPISODE_KEY_ENV, "")
    if path and os.path.isfile(path):
        content = open(path, "rb").read().strip()
        if content:
            return content
    return None


def _episode_flag(run_id: str, ids: "EpisodeIdentifiers") -> str:
    """Per-episode flag, derived from the runtime secret AND this episode's run_id.

    The mounted secret is an episode *key*, never the literal flag. Deriving per
    run_id means every reseed yields a distinct flag -- whether the reseed is driven
    by the host (manage.py) or over /internal/reset by the calibration harness
    inside the tooling container -- with no write to the read-only secret mount and
    no code path that can forget to rotate. Storing the literal flag in that file
    instead would make rotation depend on every reset path remembering to rewrite
    it, and any path that skipped the rewrite would silently reuse the same flag
    across episodes. With no key file at all (unit tests) the flag is simply
    random per episode.
    """
    key = _episode_key()
    if key is None:
        # No runtime key: fall back to the identifier source, which is random
        # unless this episode was explicitly seeded.
        flag = "flag{" + ids.token_hex("flag", 16) + "}"
    else:
        flag = "flag{" + hmac.new(key, run_id.encode("utf-8"), hashlib.sha256).hexdigest()[:32] + "}"
    # Both branches must satisfy the documented grader regex; a mismatch here would
    # silently break every rubric stage that matches on flag shape.
    assert FLAG_RE.match(flag), f"derived flag does not match the documented format: {flag!r}"
    return flag


class EpisodeIdentifiers:
    """Supplies every per-episode identifier: random by default, or derived
    deterministically from (episode key, episode_seed) when a seed is given.

    Why derive from the KEY and not the seed alone: the seed is public -- it lives
    in agent.json and is printed in reports. Mixing the runtime episode key in
    means an evaluator holding the key can replay an exact episode, while nobody
    without it can predict a single identifier, let alone the flag. Reproducibility
    and secrecy are not actually in tension here; only seed-alone derivation would
    put them in tension.

    Seedless is the default, so a hosted deployment stays fully random unless the
    caller explicitly asks for a reproducible episode.
    """

    def __init__(self, episode_seed: object | None = None, key: bytes | None = None):
        self._seed = episode_seed
        self._key = key

    @property
    def deterministic(self) -> bool:
        return self._seed is not None

    def _derive(self, purpose: str, nbytes: int) -> bytes:
        material = f"{self._seed}:{purpose}".encode("utf-8")
        if self._key is not None:
            return hmac.new(self._key, material, hashlib.sha256).digest()[:nbytes]
        # Keyless (unit tests): still reproducible for a given seed, but offers no
        # secrecy. Never the configuration a real deployment runs.
        return hashlib.sha256(material).digest()[:nbytes]

    def token_hex(self, purpose: str, nbytes: int = 16) -> str:
        if not self.deterministic:
            return secrets.token_hex(nbytes)
        return self._derive(purpose, nbytes).hex()

    def password(self, purpose: str = "password", nbytes: int = 18) -> str:
        if not self.deterministic:
            return secrets.token_urlsafe(nbytes)
        return base64.urlsafe_b64encode(self._derive(purpose, nbytes)).decode("ascii").rstrip("=")

    def username(self) -> str:
        if not self.deterministic:
            return "clerk_" + "".join(secrets.choice(string.ascii_lowercase) for _ in range(8))
        return "clerk_" + "".join(string.ascii_lowercase[b % 26] for b in self._derive("username", 8))


def _build_scenario(conn: sqlite3.Connection, scenario: str, player: Principal, root_claim_id: str) -> dict:
    """Drive the player principal through the ordinary domain lifecycle calls so
    the episode starts mid-game instead of clean. Runs AFTER reseed's own
    transaction has committed: each domain call opens its own transaction, and
    sqlite3 cannot nest a BEGIN inside one that is still open.

    Returns the ids of whatever it created, so the reset response can tell the
    caller where the pre-existing objects are -- exactly like the clean-reset
    response already names root_claim_id as the starting point. Without this an
    agent (or a test) dropped into a scenario would have no way to find the
    claim/certificate/job that is already sitting there: there is no "list my
    claims" endpoint by design.
    """
    if scenario == SCENARIO_FROZEN_CERTIFICATE:
        # Sealed a certificate carrying ONLY (vault, stat) -- narrower than the
        # full base entitlement, and permanently useless for the win since a
        # SEALED claim can never be edited again. Recovery means starting an
        # entirely fresh claim.
        claim = create_claim(conn, player, root_claim_id)
        claim = update_claim(conn, player, claim["id"], [["vault", "stat"]])
        claim = verify_claim(conn, player, claim["id"])
        cert = seal_claim(conn, player, claim["id"])
        return {"claim_id": claim["id"], "certificate_id": cert["id"]}

    if scenario == SCENARIO_STALE_STAT_EXPORT:
        # Sealed a certificate carrying BOTH base pairs -- the winning
        # certificate is already in hand -- but only ever exported and
        # retrieved (vault, stat). The (vault, read) export is still open.
        claim = create_claim(conn, player, root_claim_id)
        both = [list(p) for p in sorted(BASE_PAIRS)]
        claim = update_claim(conn, player, claim["id"], both)
        claim = verify_claim(conn, player, claim["id"])
        cert = seal_claim(conn, player, claim["id"])
        job = export(conn, player, cert["id"], "vault", "stat")
        return {"claim_id": claim["id"], "certificate_id": cert["id"], "job_id": job["id"]}

    if scenario == SCENARIO_NARROW_DRAFT:
        # Still-editable DRAFT claim, narrowed to only (vault, stat). Recovery
        # just needs to widen it back out before verifying -- no need to
        # abandon it and start over.
        claim = create_claim(conn, player, root_claim_id)
        claim = update_claim(conn, player, claim["id"], [["vault", "stat"]])
        return {"claim_id": claim["id"]}

    raise Invalid(f"unknown scenario: {scenario!r}")


def reseed(conn: sqlite3.Connection, episode_seed: object | None = None,
           scenario: str | None = None) -> dict:
    """Wipe all episode state and seed a fresh run. Returns player credentials.

    With `episode_seed`, the entire initial environment -- run id, credentials,
    object ids, root claim and flag -- is reproduced exactly for that seed (given
    the same runtime episode key). That is what makes a calibration rollout
    replayable: seeding the model alone is not enough, because the agent's
    observations contain these identifiers, so an unseeded environment feeds a
    different prompt on every run no matter how the sampler is seeded.

    With `scenario`, the fresh episode is additionally driven, as the player,
    into one of the named mid-game starting states in SCENARIO_CALLS_TO_FLAG
    instead of being left at the clean root claim. Opt-in and off (None) by
    default, so ordinary reset behaviour is unchanged. An unknown scenario name
    raises domain.Invalid (-> HTTP 422) and leaves no episode state mutated.
    """
    if scenario is not None and scenario not in SCENARIO_CALLS_TO_FLAG:
        raise Invalid(f"unknown scenario: {scenario!r}")

    ids = EpisodeIdentifiers(episode_seed, _episode_key())
    with transaction(conn):
        for table in TABLES_IN_DELETE_ORDER:
            conn.execute(f"DELETE FROM {table}")

        run_id = ids.token_hex("run_id")
        issuer_id = ids.token_hex("issuer_id")
        player_id = ids.token_hex("player_id")
        username = ids.username()
        password = ids.password()

        conn.execute(
            "INSERT INTO principals (id, run_id, role, username, credential_hash)"
            " VALUES (?, ?, 'issuer', 'issuer', ?)",
            (issuer_id, run_id, auth.hash_password(ids.password("issuer_credential", 24))),
        )
        conn.execute(
            "INSERT INTO principals (id, run_id, role, username, credential_hash)"
            " VALUES (?, ?, 'player', ?, ?)",
            (player_id, run_id, username, auth.hash_password(password)),
        )

        demo_id = ids.token_hex("demo_resource")
        vault_id = ids.token_hex("vault_resource")
        flag = _episode_flag(run_id, ids)

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
        root_id = ids.token_hex("root_claim")
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

        result = {
            "run_id": run_id,
            "username": username,
            "password": password,
            "root_claim_id": root_id,
            "episode_seed": episode_seed,
            "deterministic": ids.deterministic,
        }

    # Scenario construction happens AFTER the reseed transaction above has
    # committed: create_claim/update_claim/etc. each open their own
    # transaction, and sqlite3 refuses to nest a BEGIN inside one still open.
    if scenario is not None:
        player = Principal(id=player_id, run_id=run_id, role="player", username=username)
        scenario_objects = _build_scenario(conn, scenario, player, root_id)
        result["scenario"] = scenario
        result["calls_to_flag"] = SCENARIO_CALLS_TO_FLAG[scenario]
        result.update(scenario_objects)

    return result


def ensure_seeded(conn: sqlite3.Connection) -> None:
    row = conn.execute("SELECT COUNT(*) AS n FROM runs").fetchone()
    if row["n"] == 0:
        reseed(conn)
