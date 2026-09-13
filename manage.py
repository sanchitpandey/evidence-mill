#!/usr/bin/env python
"""Host orchestration CLI for Evidence Mill.

    python manage.py up --build
    python manage.py acceptance cold-build --no-cache --max-seconds 600
    python manage.py acceptance offline
    python manage.py acceptance resources --max-total-mib 8192 --no-gpu
    python manage.py acceptance reset --episodes 2
    python manage.py reference --runs 16 --max-seconds 300
    python manage.py calibrate --runs 16 --turns 16 --config agent.json
    python manage.py test
    python manage.py acceptance submission
"""
from __future__ import annotations

import argparse
import json
import os
import secrets
import statistics
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).parent.resolve()
SECRETS_DIR = ROOT / "secrets"
EPISODE_KEY_FILE = SECRETS_DIR / "episode_key"
ADMIN_TOKEN_FILE = SECRETS_DIR / "admin_token"
DEFAULT_PORT = int(os.environ.get("TARGET_PORT", "8000"))
BASE_URL = f"http://127.0.0.1:{DEFAULT_PORT}"


def sh(cmd: list[str], **kwargs) -> subprocess.CompletedProcess:
    print("+ " + " ".join(cmd))
    return subprocess.run(cmd, cwd=ROOT, check=True, **kwargs)


def _utc_now() -> str:
    import datetime
    return datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0).isoformat()


def _git_commit() -> str | None:
    """Best-effort commit id so a results file can be tied back to the tree that
    produced it. Absent git is not an error -- the submission ships as a zip."""
    try:
        top = subprocess.run(["git", "rev-parse", "--show-toplevel"], cwd=ROOT,
                             capture_output=True, text=True, timeout=5).stdout.strip()
        if not top or Path(top).resolve() != ROOT.resolve():
            return None  # an unrelated parent repo's commit would be misleading
        out = subprocess.run(["git", "rev-parse", "--short", "HEAD"], cwd=ROOT,
                             capture_output=True, text=True, timeout=5)
        return out.stdout.strip() or None
    except Exception:  # noqa: BLE001
        return None


def ensure_secrets() -> None:
    """Create the runtime secrets if absent. The episode key is a long-lived
    secret, NOT the flag: app/seed.py derives a distinct flag per episode from
    (key, run_id), so no caller has to remember to rotate anything and every
    reset path -- host or harness -- rotates identically."""
    SECRETS_DIR.mkdir(exist_ok=True)
    if not EPISODE_KEY_FILE.exists():
        EPISODE_KEY_FILE.write_text(secrets.token_hex(32), encoding="utf-8")
    if not ADMIN_TOKEN_FILE.exists():
        ADMIN_TOKEN_FILE.write_text(secrets.token_hex(32), encoding="utf-8")


def compose(*args: str, **kwargs) -> subprocess.CompletedProcess:
    return sh(["docker", "compose", "-f", "compose.yml", *args], **kwargs)


# ---------------------------------------------------------------------------
# up / down
# ---------------------------------------------------------------------------

def cmd_up(args: argparse.Namespace) -> int:
    ensure_secrets()
    build_args = ["--build"] if args.build else []
    compose("up", "-d", *build_args, "target")
    _wait_healthy()
    print("target container is healthy (internal network only; see compose.yml "
          f"for the best-effort {BASE_URL} host binding on platforms where it works)")
    return 0


def cmd_down(_args: argparse.Namespace) -> int:
    compose("down", "-v")
    return 0


def _target_container_name() -> str:
    out = subprocess.run(
        ["docker", "compose", "-f", "compose.yml", "ps", "-q", "target"],
        cwd=ROOT, capture_output=True, text=True, check=True,
    )
    container_id = out.stdout.strip().splitlines()[0]
    return container_id


def _wait_healthy(timeout: float = 60.0) -> None:
    """Poll the target container's own Docker HEALTHCHECK status. We do not rely
    on host port publishing -- see compose.yml for why."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            container_id = _target_container_name()
            out = subprocess.run(
                ["docker", "inspect", "--format", "{{.State.Health.Status}}", container_id],
                capture_output=True, text=True, check=True,
            )
            if out.stdout.strip() == "healthy":
                return
        except (subprocess.CalledProcessError, IndexError):
            pass
        time.sleep(1)
    raise SystemExit("target did not become healthy in time")


def _run_in_tooling(*args: str) -> subprocess.CompletedProcess:
    """Run a one-shot command in a fresh tooling container on the same internal
    network as target (reachable at http://target:8000 via Docker DNS) -- this
    is how all trusted admin/reference/grading calls reach the target, since
    host port publishing on the internal network isn't reliable everywhere."""
    return subprocess.run(
        ["docker", "compose", "-f", "compose.yml", "run", "--rm", "-T", "tooling", *args],
        cwd=ROOT, capture_output=True, text=True,
    )


def _last_json_line(text: str) -> dict:
    lines = [l for l in text.strip().splitlines() if l.strip()]
    return json.loads(lines[-1])


def _reset_episode() -> dict:
    ensure_secrets()
    proc = _run_in_tooling("python", "-m", "evaluation.reset_cli")
    if proc.returncode != 0:
        raise SystemExit(f"reset failed: {proc.stdout}\n{proc.stderr}")
    return _last_json_line(proc.stdout)


def _reference_solve_via_tooling(username: str, password: str, timeout: float) -> dict:
    proc = _run_in_tooling(
        "python", "-m", "evaluation.reference", "--base-url", "http://target:8000",
        "--username", username, "--password", password, "--timeout", str(timeout), "--json",
    )
    return _last_json_line(proc.stdout)


# ---------------------------------------------------------------------------
# acceptance: cold-build
# ---------------------------------------------------------------------------

def cmd_acceptance_cold_build(args: argparse.Namespace) -> int:
    build_args = ["build"]
    if args.no_cache:
        build_args.append("--no-cache")
    build_args += ["target", "tooling"]
    sys.path.insert(0, str(ROOT))
    from evaluation.acceptance import check_cold_build

    start = time.monotonic()
    compose(*build_args)
    elapsed = time.monotonic() - start
    ok, msg = check_cold_build(elapsed, args.max_seconds)
    print(msg)
    return 0 if ok else 1


# ---------------------------------------------------------------------------
# acceptance: offline
# ---------------------------------------------------------------------------

def cmd_acceptance_offline(_args: argparse.Namespace) -> int:
    ensure_secrets()
    compose("up", "-d", "target")
    _wait_healthy()
    sys.path.insert(0, str(ROOT))
    from evaluation.acceptance import check_offline_isolation

    probe = subprocess.run(
        ["docker", "compose", "-f", "compose.yml", "exec", "-T", "target",
         "python", "-c",
         "import socket; socket.setdefaulttimeout(3); "
         "socket.create_connection(('8.8.8.8', 53))"],
        cwd=ROOT, capture_output=True, text=True,
    )
    ok, msg = check_offline_isolation(internet_reachable=(probe.returncode == 0))
    print(msg)
    if not ok:
        return 1

    creds = _reset_episode()
    result = _reference_solve_via_tooling(creds["username"], creds["password"], timeout=5.0)
    if not result.get("ok"):
        print(f"FAIL: offline reference solve failed: {result}", file=sys.stderr)
        return 1
    print(f"offline reference solve OK: flag={result['flag']} elapsed={result['elapsed_seconds']:.2f}s")
    print("PASS")
    return 0


# ---------------------------------------------------------------------------
# acceptance: resources
# ---------------------------------------------------------------------------

def cmd_acceptance_resources(args: argparse.Namespace) -> int:
    ensure_secrets()
    compose("up", "-d", "target")
    _wait_healthy()
    sys.path.insert(0, str(ROOT))
    from evaluation.acceptance import check_memory, parse_mem_usage

    out = subprocess.run(
        ["docker", "stats", "--no-stream", "--format", "{{json .}}"],
        cwd=ROOT, capture_output=True, text=True, check=True,
    )
    total_mib = 0.0
    for line in out.stdout.splitlines():
        if not line.strip():
            continue
        row = json.loads(line)
        name = (row.get("Name", "") + row.get("Container", "")).lower()
        if "evidence" not in name and "target" not in name:
            continue
        mem_usage = row.get("MemUsage", "0MiB / 0MiB").split("/")[0].strip()
        total_mib += parse_mem_usage(mem_usage)
    ok, msg = check_memory(total_mib, args.max_total_mib)
    print(msg)
    if args.no_gpu:
        gpu = subprocess.run(["docker", "info", "--format", "{{range $k, $v := .Runtimes}}{{$k}} {{end}}"],
                              capture_output=True, text=True)
        print(f"docker runtimes available: {gpu.stdout.strip()} (no --gpus used; target requests no GPU device)")
    return 0 if ok else 1


# ---------------------------------------------------------------------------
# acceptance: reset
# ---------------------------------------------------------------------------

def cmd_acceptance_reset(args: argparse.Namespace) -> int:
    ensure_secrets()
    compose("up", "-d", "target")
    _wait_healthy()
    sys.path.insert(0, str(ROOT))
    from evaluation.acceptance import check_reset_isolation

    run_ids, usernames = [], []
    for i in range(args.episodes):
        creds = _reset_episode()
        run_ids.append(creds["run_id"])
        usernames.append(creds["username"])
        print(f"episode {i + 1}: run_id={creds['run_id']} username={creds['username']}")
    ok, msg = check_reset_isolation(run_ids, usernames)
    print(msg)
    return 0 if ok else 1


# ---------------------------------------------------------------------------
# reference
# ---------------------------------------------------------------------------

def cmd_reference(args: argparse.Namespace) -> int:
    ensure_secrets()
    compose("up", "-d", "target")
    _wait_healthy()
    sys.path.insert(0, str(ROOT))
    from evaluation.acceptance import check_reference_reliability

    successes = 0
    times = []
    failures = []
    for i in range(args.runs):
        creds = _reset_episode()
        result = _reference_solve_via_tooling(creds["username"], creds["password"], timeout=args.timeout)
        if not result.get("ok"):
            failures.append({"run": i, "step": result.get("step"), "detail": result.get("detail")})
            print(f"run {i + 1}/{args.runs}: FAIL at {result.get('step')}")
            continue
        elapsed = result["elapsed_seconds"]
        ok = elapsed <= args.max_seconds
        successes += 1 if ok else 0
        times.append(elapsed)
        status = "OK" if ok else "SLOW"
        print(f"run {i + 1}/{args.runs}: {status} flag={result['flag']} elapsed={elapsed:.2f}s")

    print()
    _ok, msg = check_reference_reliability(successes, args.runs, args.min_successes)
    print(msg)
    if times:
        print(f"solve time: min={min(times):.2f}s median={statistics.median(times):.2f}s max={max(times):.2f}s")
    if failures:
        print(f"failures: {failures}")

    report = {
        "generated_at_utc": _utc_now(),
        "git_commit": _git_commit(),
        "runs": args.runs, "successes": successes, "times_seconds": times, "failures": failures,
    }
    (ROOT / "reports").mkdir(exist_ok=True)
    (ROOT / "reports" / "reference-run-report.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    return 0 if successes >= args.min_successes else 1


# ---------------------------------------------------------------------------
# calibrate / test / submission
# ---------------------------------------------------------------------------

def cmd_calibrate(args: argparse.Namespace) -> int:
    """Runs the entire cohort inside ONE tooling container (evaluation/calibrate_cli.py):
    it reaches target via Docker DNS (no host port dependency), grades every
    rollout by reading the target's SQLite volume directly (no exec/run
    round-trip per rollout), and has its own internet egress for the LLM call.
    Requires OPENAI_API_KEY in the host environment (forwarded via compose.yml)."""
    ensure_secrets()
    compose("up", "-d", "target")
    _wait_healthy()
    proc = subprocess.run(
        ["docker", "compose", "-f", "compose.yml", "run", "--rm", "-T", "tooling",
         "python", "-m", "evaluation.calibrate_cli",
         "--runs", str(args.runs), "--turns", str(args.turns),
         "--config", f"/app/{os.path.basename(args.config)}"],
        cwd=ROOT,
    )
    return proc.returncode


def cmd_test(_args: argparse.Namespace) -> int:
    compose("build", "tooling")
    result = compose("run", "--rm", "-T", "tooling", "python", "-m", "pytest", "tests/", "-q")
    return result.returncode


def cmd_acceptance_submission(_args: argparse.Namespace) -> int:
    """Packaging check ONLY: confirms required files exist. It does NOT confirm
    they contain correct content, that tests pass, or that calibration has
    actually been run -- those are separately covered by `manage.py test`,
    `manage.py reference`, and `manage.py calibrate` respectively. Treat a PASS
    here as "nothing is missing from the archive," not "the assignment is done."
    """
    required = [
        "Dockerfile", "compose.yml", "requirements.lock", "requirements-tooling.lock",
        "manage.py", "app/main.py", "app/domain.py", "app/db.py", "app/seed.py",
        "evaluation/rubric.yaml", "evaluation/grader.py", "evaluation/reference.py",
        "evaluation/calibrate.py", "evaluation/http_tool.py", "evaluation/openai_adapter.py",
        "evaluation/acceptance.py", "agent.json", "package.py",
        "tests/test_flow.py", "tests/test_rewards.py", "tests/test_shortcuts.py",
        "tests/test_repairs.py", "tests/test_reset.py", "PLAYER.md", "README.md",
        "reports/design-note.md", "reports/calibration-report.md",
        "reports/calibration-report.json", "reports/results.jsonl",
        "reports/reference-run-report.json",
    ]
    missing = [f for f in required if not (ROOT / f).exists()]
    if missing:
        print(f"FAIL: missing required files: {missing}", file=sys.stderr)
        return 1
    calibration_done = (ROOT / "reports" / "calibration-report.json").exists()
    print("PASS (packaging only): all required submission files present.")
    if not calibration_done:
        print("NOTE: reports/calibration-report.json is absent -- the real agent "
              "cohort has not been run yet. This command does not fail on that; "
              "run `manage.py calibrate` before treating the assignment as complete.")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description=__doc__)
    sub = p.add_subparsers(dest="command", required=True)

    up = sub.add_parser("up")
    up.add_argument("--build", action="store_true")
    up.set_defaults(func=cmd_up)

    down = sub.add_parser("down")
    down.set_defaults(func=cmd_down)

    acc = sub.add_parser("acceptance")
    acc_sub = acc.add_subparsers(dest="acceptance_command", required=True)

    cb = acc_sub.add_parser("cold-build")
    cb.add_argument("--no-cache", action="store_true")
    cb.add_argument("--max-seconds", type=float, default=600)
    cb.set_defaults(func=cmd_acceptance_cold_build)

    off = acc_sub.add_parser("offline")
    off.set_defaults(func=cmd_acceptance_offline)

    res = acc_sub.add_parser("resources")
    res.add_argument("--max-total-mib", type=float, default=8192)
    res.add_argument("--no-gpu", action="store_true")
    res.set_defaults(func=cmd_acceptance_resources)

    rst = acc_sub.add_parser("reset")
    rst.add_argument("--episodes", type=int, default=2)
    rst.set_defaults(func=cmd_acceptance_reset)

    sub_ = acc_sub.add_parser("submission")
    sub_.set_defaults(func=cmd_acceptance_submission)

    ref = sub.add_parser("reference")
    ref.add_argument("--runs", type=int, default=16)
    ref.add_argument("--max-seconds", type=float, default=300)
    ref.add_argument("--min-successes", type=int, default=14)
    ref.add_argument("--timeout", type=float, default=5.0)
    ref.set_defaults(func=cmd_reference)

    cal = sub.add_parser("calibrate")
    cal.add_argument("--runs", type=int, default=16)
    cal.add_argument("--turns", type=int, default=16)
    cal.add_argument("--config", type=str, default=str(ROOT / "agent.json"))
    cal.set_defaults(func=cmd_calibrate)

    tst = sub.add_parser("test")
    tst.set_defaults(func=cmd_test)

    return p


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
