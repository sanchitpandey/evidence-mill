"""Trusted per-episode reset CLI. Run inside the tooling container against the
target's /internal/reset over the shared internal Docker network -- no host
port publish required. manage.py invokes this via `docker compose exec tooling`.
"""
from __future__ import annotations

import argparse
import json
import os

import httpx


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--base-url", default=os.environ.get("TARGET_BASE_URL", "http://target:8000"))
    parser.add_argument("--admin-token-file",
                         default=os.environ.get("EVIDENCE_MILL_ADMIN_TOKEN_FILE", "/run/secrets/admin_token"))
    parser.add_argument("--episode-seed", default=None,
                         help="reproduce an exact initial environment (ids, credentials, flag) "
                              "for this seed; omit for a fresh random episode")
    parser.add_argument("--scenario", default=None,
                         help="drive the fresh episode into a named mid-game starting state "
                              "(see app.seed.SCENARIO_CALLS_TO_FLAG); omit for the clean root claim")
    args = parser.parse_args()

    token = open(args.admin_token_file, "r", encoding="utf-8").read().strip()
    payload: dict = {}
    if args.episode_seed is not None:
        payload["episode_seed"] = args.episode_seed
    if args.scenario is not None:
        payload["scenario"] = args.scenario
    r = httpx.post(f"{args.base_url}/internal/reset", headers={"x-admin-token": token},
                    json=payload, timeout=5.0)
    r.raise_for_status()
    print(json.dumps(r.json()))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
