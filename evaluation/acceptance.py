"""Pure acceptance predicates used by manage.py's `acceptance` subcommands.
Kept separate from manage.py's subprocess/docker orchestration so the pass/fail
logic itself is unit-testable without a running Docker daemon.
"""
from __future__ import annotations


def parse_mem_usage(value: str) -> float:
    """Parse a `docker stats` MemUsage field (e.g. '123.4MiB') into MiB."""
    value = value.strip()
    if value.endswith("GiB"):
        return float(value[:-3]) * 1024
    if value.endswith("MiB"):
        return float(value[:-3])
    if value.endswith("KiB"):
        return float(value[:-3]) / 1024
    if value.endswith("B"):
        return float(value[:-1]) / (1024 * 1024)
    return 0.0


def check_cold_build(elapsed_seconds: float, max_seconds: float) -> tuple[bool, str]:
    ok = elapsed_seconds <= max_seconds
    return ok, f"cold build {elapsed_seconds:.1f}s (limit {max_seconds:.0f}s): {'PASS' if ok else 'FAIL'}"


def check_memory(total_mib: float, max_total_mib: float) -> tuple[bool, str]:
    ok = total_mib <= max_total_mib
    return ok, f"memory {total_mib:.1f} MiB (limit {max_total_mib:.0f} MiB): {'PASS' if ok else 'FAIL'}"


def check_reset_isolation(run_ids: list[str], usernames: list[str]) -> tuple[bool, str]:
    ok = len(set(run_ids)) == len(run_ids) and len(set(usernames)) == len(usernames)
    return ok, f"{len(run_ids)} episodes, all identifiers unique: {'PASS' if ok else 'FAIL'}"


def check_reference_reliability(successes: int, runs: int, min_successes: int) -> tuple[bool, str]:
    ok = successes >= min_successes
    return ok, f"reference reliability {successes}/{runs} (need >= {min_successes}): {'PASS' if ok else 'FAIL'}"


def check_offline_isolation(internet_reachable: bool) -> tuple[bool, str]:
    ok = not internet_reachable
    return ok, f"target internet reachability: {internet_reachable} ({'FAIL' if internet_reachable else 'PASS'})"
