"""One shared way to open the target's SQLite file read-only, used by BOTH
grading entry points (evaluation/grade_cli.py and evaluation/calibrate_cli.py).

The problem this solves: the target runs in WAL mode and the tooling container
sees /data as a read-only bind mount. Opening a WAL database with `mode=ro` can
fail with "unable to open database file" because the shared-memory (-shm) file
is not creatable on that mount. The obvious workaround, `immutable=1`, makes
SQLite ignore the WAL and locking entirely -- which means it reads ONLY the main
database file and silently misses every committed transaction still sitting in
the WAL.

For a grader that is the worst possible failure mode: it does not raise, it
quietly returns a LOWER score than the agent earned. So the fallback here is
gated on the WAL being empty, and refuses rather than guesses when it is not.
"""
from __future__ import annotations

import os
import sqlite3
import sys
import time


class StaleReadRefused(RuntimeError):
    """Raised instead of returning a score derived from a possibly stale snapshot."""


def _wal_bytes(db_path: str) -> int:
    try:
        return os.path.getsize(db_path + "-wal")
    except OSError:
        return 0


def _try(uri: str) -> sqlite3.Connection:
    conn = sqlite3.connect(uri, uri=True)
    conn.row_factory = sqlite3.Row
    conn.execute("SELECT 1")  # force the open to actually happen now
    return conn


def open_readonly(db_path: str, attempts: int = 6, delay: float = 0.25) -> sqlite3.Connection:
    """Open `db_path` read-only without ever silently returning a stale view.

    Order of preference:
      1. `mode=ro` -- WAL-aware and always correct. Retried, because the -shm
         failure is often transient right after a write.
      2. `immutable=1` -- ONLY when the WAL is empty, so it cannot hide committed
         data. Warns on stderr so the fallback is never invisible in a log.
    Otherwise raises, because a grader that under-reports silently is worse than
    a grader that stops.
    """
    last_exc: Exception | None = None
    for _ in range(attempts):
        try:
            return _try(f"file:{db_path}?mode=ro")
        except sqlite3.OperationalError as exc:
            last_exc = exc
        time.sleep(delay)

    pending = _wal_bytes(db_path)
    if pending > 0:
        raise StaleReadRefused(
            f"cannot open {db_path!r} with mode=ro ({last_exc}), and its write-ahead log holds "
            f"{pending} bytes of committed data that an immutable=1 read would silently skip. "
            "Refusing to grade from a possibly stale snapshot. Checkpoint the database or grant "
            "the grader a writable -shm path, then retry."
        )
    print(
        f"[readonly_db] WARNING: mode=ro failed ({last_exc}); falling back to immutable=1. "
        f"The write-ahead log is empty, so no committed data can be hidden by this read.",
        file=sys.stderr, flush=True,
    )
    try:
        return _try(f"file:{db_path}?immutable=1")
    except sqlite3.OperationalError as exc:
        raise StaleReadRefused(f"cannot open {db_path!r} read-only: {exc}") from exc
