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
    args = parser.parse_args()

    token = open(args.admin_token_file, "r", encoding="utf-8").read().strip()
    r = httpx.post(f"{args.base_url}/internal/reset", headers={"x-admin-token": token}, timeout=5.0)
    r.raise_for_status()
    print(json.dumps(r.json()))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
