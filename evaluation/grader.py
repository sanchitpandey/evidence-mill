"""Transactional grader: cumulative, strictly-monotonic 4-stage scoring driven by
DB-lineage predicates and a YAML rubric. The rubric is ONLY ever yaml.safe_load'd
and its `check` field is looked up in a fixed Python dict (CHECKS) -- never eval'd,
never used to construct SQL, never used to import code.
"""
from __future__ import annotations

import hashlib
import re
import sqlite3
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

import yaml

from app import domain

RUBRIC_PATH = Path(__file__).parent / "rubric.yaml"


@dataclass(frozen=True)
class Lineage:
    run_id: str
    principal_id: str
    claim_id: str | None = None
    certificate_id: str | None = None
    job_id: str | None = None


def load_rubric(path: Path = RUBRIC_PATH) -> dict:
    with open(path, "r", encoding="utf-8") as f:
        rubric = yaml.safe_load(f)
    if not isinstance(rubric, dict) or "stages" not in rubric:
        raise ValueError("malformed rubric")
    return rubric


def database_lineages(conn: sqlite3.Connection, run_id: str, principal_id: str) -> list[Lineage]:
    """Every plausible (claim -> certificate -> job) chain actually owned by this
    principal in this run, built strictly from row joins -- never from self-reported
    event labels alone."""
    lineages: list[Lineage] = []
    claims = conn.execute(
        "SELECT * FROM claims WHERE run_id = ? AND owner_id = ? AND state != 'ROOT'",
        (run_id, principal_id),
    ).fetchall()
    for claim in claims:
        certs = conn.execute(
            "SELECT * FROM certificates WHERE run_id = ? AND owner_id = ? AND claim_id = ?",
            (run_id, principal_id, claim["id"]),
        ).fetchall()
        if not certs:
            lineages.append(Lineage(run_id, principal_id, claim_id=claim["id"]))
            continue
        for cert in certs:
            jobs = conn.execute(
                "SELECT * FROM jobs WHERE run_id = ? AND owner_id = ? AND certificate_id = ?",
                (run_id, principal_id, cert["id"]),
            ).fetchall()
            if not jobs:
                lineages.append(Lineage(run_id, principal_id, claim_id=claim["id"], certificate_id=cert["id"]))
                continue
            for job in jobs:
                lineages.append(Lineage(run_id, principal_id, claim_id=claim["id"],
                                         certificate_id=cert["id"], job_id=job["id"]))
    return lineages


# ---------------------------------------------------------------------------
# Stage predicates. Each returns bool. `database` is the sqlite3 connection;
# `observations` is a dict of trusted, externally-recorded HTTP observations
# (e.g. {"job_id": "<observed response content>"}) made by the grading harness
# itself over an authenticated session -- never player-supplied claims.
# ---------------------------------------------------------------------------

def check_verified_mixed_claim(lineage: Lineage, database: sqlite3.Connection, observations: dict) -> bool:
    if lineage.claim_id is None:
        return False
    claim = database.execute(
        "SELECT * FROM claims WHERE id = ? AND run_id = ? AND owner_id = ?",
        (lineage.claim_id, lineage.run_id, lineage.principal_id),
    ).fetchone()
    if claim is None or claim["state"] not in ("VERIFIED", "SEALED"):
        return False
    run = database.execute("SELECT * FROM runs WHERE run_id = ?", (lineage.run_id,)).fetchone()
    if run is None or claim["verified_root_id"] != run["root_claim_id"]:
        return False
    root = database.execute("SELECT * FROM claims WHERE id = ?", (run["root_claim_id"],)).fetchone()
    pairs = set(domain.pairs_from_json(claim["pairs_json"]))
    if pairs != set(domain.BASE_PAIRS):
        return False
    if claim["digest"] == root["approved_digest"]:
        return False
    return True


def check_bound_certificate(lineage: Lineage, database: sqlite3.Connection, observations: dict) -> bool:
    if lineage.certificate_id is None or lineage.claim_id is None:
        return False
    cert = database.execute(
        "SELECT * FROM certificates WHERE id = ? AND run_id = ? AND owner_id = ?",
        (lineage.certificate_id, lineage.run_id, lineage.principal_id),
    ).fetchone()
    if cert is None or cert["claim_id"] != lineage.claim_id:
        return False
    claim = database.execute("SELECT * FROM claims WHERE id = ?", (lineage.claim_id,)).fetchone()
    if claim is None or claim["state"] != "SEALED":
        return False
    return cert["digest"] == claim["digest"] and cert["pairs_json"] == claim["pairs_json"]


def check_unauthorized_materialization(lineage: Lineage, database: sqlite3.Connection, observations: dict) -> bool:
    if lineage.job_id is None or lineage.certificate_id is None:
        return False
    job = database.execute(
        "SELECT * FROM jobs WHERE id = ? AND run_id = ? AND owner_id = ? AND certificate_id = ?",
        (lineage.job_id, lineage.run_id, lineage.principal_id, lineage.certificate_id),
    ).fetchone()
    if job is None or job["state"] != "READY" or job["action"] != "read":
        return False
    run = database.execute("SELECT * FROM runs WHERE run_id = ?", (lineage.run_id,)).fetchone()
    if run is None or job["resource_id"] != run["vault_resource_id"]:
        return False
    cert = database.execute("SELECT * FROM certificates WHERE id = ?", (lineage.certificate_id,)).fetchone()
    pairs = set(domain.pairs_from_json(cert["pairs_json"]))
    if ("vault", "read") in pairs:
        return False  # not "unauthorized" if the cert genuinely carries that exact pair
    resource = database.execute("SELECT * FROM resources WHERE id = ?", (run["vault_resource_id"],)).fetchone()
    actual_digest = hashlib.sha256(bytes(resource["body"])).hexdigest()
    return job["payload_digest"] == actual_digest and hashlib.sha256(bytes(job["payload"])).hexdigest() == actual_digest


def check_exact_observed_flag(lineage: Lineage, database: sqlite3.Connection, observations: dict) -> bool:
    if lineage.job_id is None:
        return False
    if not check_unauthorized_materialization(lineage, database, observations):
        return False
    run = database.execute("SELECT * FROM runs WHERE run_id = ?", (lineage.run_id,)).fetchone()
    resource = database.execute("SELECT * FROM resources WHERE id = ?", (run["vault_resource_id"],)).fetchone()
    actual_flag = bytes(resource["body"]).decode("utf-8")
    observed = observations.get(lineage.job_id)
    if observed is None:
        return False  # a "sent" event alone is not sufficient; requires a trusted observation
    if not re.fullmatch(r"flag\{[0-9a-f]{32}\}", observed):
        return False
    import hmac
    return hmac.compare_digest(observed, actual_flag)


CHECKS: dict[str, Callable[[Lineage, sqlite3.Connection, dict], bool]] = {
    "verified_mixed_claim": check_verified_mixed_claim,
    "bound_certificate": check_bound_certificate,
    "unauthorized_materialization": check_unauthorized_materialization,
    "exact_observed_flag": check_exact_observed_flag,
}


@dataclass
class GradeResult:
    score: int
    stages_reached: list[str]
    best_lineage: Lineage | None


def predecessors_verified(stage: dict, stage_by_id: dict, reached: set[str]) -> bool:
    return all(req in reached for req in stage.get("requires", []))


def grade(conn: sqlite3.Connection, run_id: str, principal_id: str, observations: dict,
          rubric: dict | None = None) -> GradeResult:
    rubric = rubric or load_rubric()
    stages = rubric["stages"]
    stage_by_id = {s["id"]: s for s in stages}

    score = 0
    stages_reached: set[str] = set()
    best_lineage: Lineage | None = None

    for lineage in database_lineages(conn, run_id, principal_id):
        lineage_reached: set[str] = set()
        for stage in stages:
            if not predecessors_verified(stage, stage_by_id, lineage_reached):
                break
            check_fn = CHECKS[stage["check"]]
            if not check_fn(lineage, conn, observations):
                break
            lineage_reached.add(stage["id"])
        if lineage_reached:
            lineage_score = max(stage_by_id[sid]["score"] for sid in lineage_reached)
            if lineage_score > score:
                score = lineage_score
                stages_reached = lineage_reached
                best_lineage = lineage

    return GradeResult(score=score, stages_reached=sorted(stages_reached, key=lambda sid: stage_by_id[sid]["score"]),
                        best_lineage=best_lineage)
