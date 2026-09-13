"""The read-only open used by BOTH grading entry points must never return a view
that silently omits committed data."""
import sqlite3

import pytest

from evaluation.readonly_db import StaleReadRefused, open_readonly


def _wal_db(path):
    conn = sqlite3.connect(str(path))
    conn.execute("PRAGMA journal_mode = WAL")
    conn.execute("CREATE TABLE t (v TEXT)")
    conn.execute("INSERT INTO t VALUES ('committed')")
    conn.commit()
    return conn


def test_open_readonly_handles_wal_database(tmp_path):
    db = tmp_path / "evidence.db"
    writer = _wal_db(db)
    try:
        conn = open_readonly(str(db))
        assert conn.execute("SELECT v FROM t").fetchone()[0] == "committed"
        conn.close()
    finally:
        writer.close()


def test_open_readonly_refuses_a_stale_snapshot_when_the_wal_is_non_empty(tmp_path, monkeypatch):
    """If mode=ro cannot open the file, falling back to immutable=1 while the WAL
    still holds committed rows would under-report the agent's score without any
    error. The opener must refuse instead -- a grader that stops is strictly better
    than one that quietly scores low."""
    db = tmp_path / "evidence.db"
    writer = _wal_db(db)
    try:
        assert (tmp_path / "evidence.db-wal").stat().st_size > 0

        import evaluation.readonly_db as mod

        def _always_fail(uri):
            raise sqlite3.OperationalError("unable to open database file")

        monkeypatch.setattr(mod, "_try", _always_fail)
        monkeypatch.setattr(mod.time, "sleep", lambda _s: None)

        with pytest.raises(StaleReadRefused) as exc:
            open_readonly(str(db), attempts=2, delay=0)
        assert "silently skip" in str(exc.value)
    finally:
        writer.close()


def test_immutable_fallback_is_allowed_only_once_the_wal_is_empty(tmp_path, monkeypatch, capsys):
    db = tmp_path / "evidence.db"
    writer = _wal_db(db)
    writer.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    writer.close()

    import evaluation.readonly_db as mod

    real_try = mod._try

    def _fail_ro_only(uri):
        if "mode=ro" in uri:
            raise sqlite3.OperationalError("unable to open database file")
        return real_try(uri)

    monkeypatch.setattr(mod, "_try", _fail_ro_only)
    monkeypatch.setattr(mod.time, "sleep", lambda _s: None)

    conn = open_readonly(str(db), attempts=2, delay=0)
    assert conn.execute("SELECT v FROM t").fetchone()[0] == "committed"
    conn.close()
    assert "WARNING" in capsys.readouterr().err, "the fallback must never be invisible"
