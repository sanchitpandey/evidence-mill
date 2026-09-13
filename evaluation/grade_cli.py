"""Trusted grading CLI. Runs INSIDE the tooling container/image only, never the
target -- it opens the target's SQLite file read-only over a shared Docker volume
and computes the rubric score from DB-lineage predicates plus the caller's trusted
observations. The agent under evaluation never has access to this file, this
image, or this code path: it only ever talks to the target container over HTTP.
"""
from __future__ import annotations

import argparse
import json
import os

from evaluation.grader import grade
from evaluation.readonly_db import open_readonly


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--username", required=True)
    parser.add_argument("--observations-json", default="{}",
                         help='JSON object mapping job_id -> observed response content')
    parser.add_argument("--db", default=os.environ.get("EVIDENCE_MILL_DB", "/data/evidence.db"))
    args = parser.parse_args()

    conn = open_readonly(args.db)
    run = conn.execute("SELECT * FROM runs LIMIT 1").fetchone()
    if run is None:
        print(json.dumps({"score": 0, "stages_reached": [], "error": "not seeded"}))
        return 0
    principal = conn.execute(
        "SELECT * FROM principals WHERE run_id = ? AND username = ?", (run["run_id"], args.username),
    ).fetchone()
    if principal is None:
        print(json.dumps({"score": 0, "stages_reached": [], "error": "unknown principal"}))
        return 0

    observations = json.loads(args.observations_json)
    result = grade(conn, run["run_id"], principal["id"], observations)
    print(json.dumps({"score": result.score, "stages_reached": result.stages_reached}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
