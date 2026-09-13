#!/usr/bin/env python3
"""Build a submission zip of Evidence Mill that CANNOT contain secrets.

Motivation: `secrets/` is gitignored (so `git archive` is safe), but the
assignment accepts "a repo OR zip", and a naive recursive zip of the working
tree would sweep in local runtime secrets. This script builds the zip from an
explicit allowlist walk with a
denylist, and then runs two independent safety gates that ABORT the whole build
(no zip written) if anything sensitive slipped through:

  Gate 1 (path):    refuse any path under secrets/ or matching a credential
                    filename pattern (*_token, *.pem, *.key, id_rsa, .env,
                    gcp_adc.json, *credential*, *service-account*).
  Gate 2 (content): scan every included text file for high-signal secret
                    markers (PRIVATE KEY blocks, "refresh_token"/"client_secret"
                    JSON fields, AWS-style keys) and refuse if any match.

Usage (host Python, stdlib only -- no deps):

    python package.py                      # -> ../evidence-mill-submission.zip
    python package.py -o /tmp/em.zip       # choose output path
    python package.py --list               # dry run: print the manifest, write nothing
    python package.py --include-git        # also include .git/ (off by default)

Exit code is non-zero if a safety gate trips, so it is safe to wire into CI.
"""
from __future__ import annotations

import argparse
import fnmatch
import re
import sys
import zipfile
from pathlib import Path

REPO = Path(__file__).resolve().parent
ARC_ROOT = REPO.name  # files are stored under "evidence-mill/..." in the zip

# Directories never included (build/venv/db/cache/secrets/transient outputs).
EXCLUDE_DIRS = {
    "secrets", ".venv", "venv", "data", "data_test",
    "__pycache__", ".pytest_cache", ".mypy_cache", ".ruff_cache", "node_modules",
}
# Individual files/globs never included.
EXCLUDE_FILE_GLOBS = [
    "*.pyc", "*.pyo", "*.db", "*.db-wal", "*.db-shm", "*.log",
]

# Gate 1: any path matching these is treated as a secret and aborts the build.
SECRET_PATH_GLOBS = [
    "secrets/*", "secrets/**",
    "*_token", "*token", "*.pem", "*.key", "*.p12", "*.pfx", "id_rsa*",
    ".env", ".env.*", "*.env",
    "gcp_adc.json", "*credential*", "*service-account*", "*service_account*",
    "adc.json", "application_default_credentials.json",
]

# Gate 2: high-signal secret markers scanned inside included text files.
SECRET_CONTENT_PATTERNS = [
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    re.compile(r'"refresh_token"\s*:\s*"[^"]{10,}"'),
    re.compile(r'"client_secret"\s*:\s*"[^"]{6,}"'),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),           # AWS access key id
    re.compile(r"\bsk-[A-Za-z0-9]{20,}\b"),         # OpenAI-style secret key
]
TEXT_SUFFIXES = {
    ".py", ".md", ".txt", ".json", ".jsonl", ".yaml", ".yml", ".toml", ".ini",
    ".cfg", ".in", ".lock", ".sh", ".dockerfile", ".env", ".gitignore", ".dockerignore", "",
}


def _rel(p: Path) -> str:
    return p.relative_to(REPO).as_posix()


def _excluded_dir(name: str) -> bool:
    return name in EXCLUDE_DIRS


def _excluded_file(rel: str) -> bool:
    return any(fnmatch.fnmatch(rel, g) or fnmatch.fnmatch(Path(rel).name, g)
               for g in EXCLUDE_FILE_GLOBS)


def _is_secret_path(rel: str) -> bool:
    name = Path(rel).name
    for g in SECRET_PATH_GLOBS:
        if fnmatch.fnmatch(rel, g) or fnmatch.fnmatch(name, g):
            return True
    return False


def collect_files(include_git: bool) -> list[Path]:
    files: list[Path] = []
    for path in sorted(REPO.rglob("*")):
        if path.is_dir():
            continue
        parts = path.relative_to(REPO).parts
        if not include_git and ".git" in parts:
            continue
        if any(_excluded_dir(part) for part in parts):
            continue
        rel = _rel(path)
        if _excluded_file(rel):
            continue
        files.append(path)
    return files


def scan_content(path: Path) -> list[str]:
    if path.suffix.lower() not in TEXT_SUFFIXES:
        return []
    try:
        text = path.read_text(encoding="utf-8", errors="strict")
    except (UnicodeDecodeError, OSError):
        return []  # binary or unreadable -> not a text-secret carrier
    return [pat.pattern for pat in SECRET_CONTENT_PATTERNS if pat.search(text)]


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("-o", "--output", default=str(REPO.parent / "evidence-mill-submission.zip"))
    ap.add_argument("--list", action="store_true", help="dry run: print manifest, write nothing")
    ap.add_argument("--include-git", action="store_true", help="also include the .git/ directory")
    args = ap.parse_args()

    files = collect_files(args.include_git)

    # Gate 1 -- path-based.
    path_hits = [_rel(p) for p in files if _is_secret_path(_rel(p))]
    # Gate 2 -- content-based.
    content_hits: list[tuple[str, list[str]]] = []
    for p in files:
        markers = scan_content(p)
        if markers:
            content_hits.append((_rel(p), markers))

    if path_hits or content_hits:
        print("ABORT: refusing to build a submission zip -- sensitive content detected.\n", file=sys.stderr)
        if path_hits:
            print("  Secret-looking PATHS that would have been included:", file=sys.stderr)
            for h in path_hits:
                print(f"    - {h}", file=sys.stderr)
        if content_hits:
            print("  Files whose CONTENT matched a secret marker:", file=sys.stderr)
            for rel, markers in content_hits:
                print(f"    - {rel}  ({', '.join(markers)})", file=sys.stderr)
        print("\n  Remove/relocate these (secrets belong outside the tree, regenerated at runtime),\n"
              "  then re-run. No zip was written.", file=sys.stderr)
        return 2

    if args.list:
        print(f"Manifest ({len(files)} files, would be stored under '{ARC_ROOT}/'):")
        for p in files:
            print(f"  {ARC_ROOT}/{_rel(p)}")
        print("\nSafety gates passed. (dry run -- no zip written)")
        return 0

    out = Path(args.output)
    out.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as zf:
        for p in files:
            zf.write(p, arcname=f"{ARC_ROOT}/{_rel(p)}")

    size_mib = out.stat().st_size / (1024 * 1024)
    print(f"Wrote {out}  ({len(files)} files, {size_mib:.2f} MiB)")
    print("Safety gates passed: no secrets/ files, no credential-named files, no secret markers in content.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
