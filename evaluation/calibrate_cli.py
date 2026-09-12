"""Containerized entrypoint for the real calibration cohort. Runs entirely
INSIDE one `tooling` container (see compose.yml): reaches the target over the
shared internal Docker network by DNS name (http://target:8000, no host port
publish needed), grades every rollout by opening the target's SQLite volume
read-only in-process (no docker exec/run round trip per grading call, and no
dependency on a persistent "tooling" service to exec into), and still has its
own internet egress (the `egress` network) for the adapter's LLM API calls.

manage.py's `calibrate` command runs this via a single
`docker compose run --rm tooling python -m evaluation.calibrate_cli ...`
"""
from __future__ import annotations

import argparse
import os
import sqlite3
from pathlib import Path

import httpx

from evaluation.calibrate import run_cohort
from evaluation.grader import grade as grade_db


def _reset_fn(base_url: str, admin_token_file: str):
    def reset() -> dict:
        token = open(admin_token_file, "r", encoding="utf-8").read().strip()
        r = httpx.post(f"{base_url}/internal/reset", headers={"x-admin-token": token}, timeout=5.0)
        r.raise_for_status()
        return r.json()
    return reset


def _grade_fn(db_path: str):
    def grade_fn(username: str, observations: dict) -> dict:
        conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
        conn.row_factory = sqlite3.Row
        try:
            run = conn.execute("SELECT * FROM runs LIMIT 1").fetchone()
            if run is None:
                return {"score": 0, "stages_reached": []}
            principal = conn.execute(
                "SELECT * FROM principals WHERE run_id = ? AND username = ?", (run["run_id"], username),
            ).fetchone()
            if principal is None:
                return {"score": 0, "stages_reached": []}
            result = grade_db(conn, run["run_id"], principal["id"], observations)
            return {"score": result.score, "stages_reached": result.stages_reached}
        finally:
            conn.close()
    return grade_fn


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--runs", type=int, default=16)
    parser.add_argument("--turns", type=int, default=16)
    parser.add_argument("--config", default="/app/agent.json")
    parser.add_argument("--report", default="/app/reports/calibration-report.json")
    parser.add_argument("--results-jsonl", default="/app/reports/results.jsonl")
    args = parser.parse_args()

    base_url = os.environ.get("TARGET_BASE_URL", "http://target:8000")
    admin_token_file = os.environ.get("EVIDENCE_MILL_ADMIN_TOKEN_FILE", "/run/secrets/admin_token")
    db_path = os.environ.get("EVIDENCE_MILL_DB", "/data/evidence.db")

    run_cohort(
        base_url=base_url,
        reset_fn=_reset_fn(base_url, admin_token_file),
        runs=args.runs,
        max_turns=args.turns,
        agent_config_path=args.config,
        report_path=Path(args.report),
        grade_fn=_grade_fn(db_path),
        results_jsonl_path=Path(args.results_jsonl),
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
