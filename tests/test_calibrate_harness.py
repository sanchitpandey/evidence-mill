"""Self-test for the calibration harness plumbing (turn accounting, grading via
DB truth, failure classification, reporting) using a deterministic ScriptedAdapter
in place of a live LLM. This does NOT exercise a real model -- see README.md for
why the actual 16-agent cohort must be run outside this evaluation environment."""
import json

import pytest

from app import db as db_module
from evaluation import calibrate
from evaluation.grader import grade as grade_db


def _in_process_grade_fn():
    conn = db_module.get_conn()

    def grade_fn(username: str, observations: dict) -> dict:
        run = conn.execute("SELECT * FROM runs LIMIT 1").fetchone()
        principal = conn.execute(
            "SELECT * FROM principals WHERE run_id = ? AND username = ?", (run["run_id"], username),
        ).fetchone()
        result = grade_db(conn, run["run_id"], principal["id"], observations)
        return {"score": result.score, "stages_reached": result.stages_reached}

    return grade_fn


def _reset_fn(client):
    def reset() -> dict:
        r = client.post("/internal/reset", headers={"x-admin-token": "test-admin-token"})
        return r.json()
    return reset


class _PerfectAdapter:
    """Replays the known exploit path, reading IDs out of prior tool results
    instead of a fixed action list (since IDs are randomised per episode).

    Deliberately never returns a "headers" key -- the real tool schema
    (evaluation/openai_adapter.py tool schema) has no such parameter, so a
    real LLM adapter could never supply one either. Authentication past
    /session must work purely from HttpTool's own auto-session-token handling
    (see evaluation/http_tool.py); if that regressed, every call from step 2
    onward would 401 and this adapter would still complete step 3 by asking
    for a `root_id` of None, which fails loudly rather than silently passing."""

    def __init__(self, username: str, password: str):
        self._username = username
        self._password = password
        self._step = 0
        self._root_id = None
        self._claim_id = None
        self._cert_id = None
        self._job_id = None

    def next_action(self, transcript: list[dict]) -> dict:
        if transcript and "result" in transcript[-1]:
            last_body = transcript[-1]["result"]["body"]
            if self._step == 2:
                self._root_id = last_body["root"]["id"]
            elif self._step == 3:
                self._claim_id = last_body["id"]
            elif self._step == 6:
                self._cert_id = last_body["id"]
            elif self._step == 7:
                self._job_id = last_body["job_id"]

        self._step += 1
        if self._step == 1:
            return {"method": "POST", "path": "/session",
                     "json": {"username": self._username, "password": self._password}}
        if self._step == 2:
            return {"method": "GET", "path": "/catalog", "json": None}
        if self._step == 3:
            return {"method": "POST", "path": "/claims", "json": {"parent_id": self._root_id}}
        if self._step == 4:
            return {"method": "PATCH", "path": f"/claims/{self._claim_id}",
                     "json": {"pairs": [["demo", "read"], ["vault", "stat"]]}}
        if self._step == 5:
            return {"method": "POST", "path": f"/claims/{self._claim_id}/verify", "json": {}}
        if self._step == 6:
            return {"method": "POST", "path": f"/claims/{self._claim_id}/seal", "json": {}}
        if self._step == 7:
            return {"method": "POST", "path": "/exports",
                     "json": {"certificate_id": self._cert_id, "resource": "vault", "action": "read"}}
        if self._step == 8:
            return {"method": "GET", "path": f"/exports/{self._job_id}", "json": None}
        return {"stop": True, "flag": None}


def test_harness_reports_full_success_for_a_perfect_agent(tmp_path, monkeypatch):
    db_path = str(tmp_path / "evidence.db")
    monkeypatch.setenv("EVIDENCE_MILL_DB", db_path)
    monkeypatch.setenv("EVIDENCE_MILL_ADMIN_TOKEN", "test-admin-token")
    # compose sets the *_FILE form for the tooling image; without clearing it the
    # real container secret wins and every /internal/reset in the suite 404s.
    monkeypatch.delenv("EVIDENCE_MILL_ADMIN_TOKEN_FILE", raising=False)
    monkeypatch.delenv("EVIDENCE_MILL_EPISODE_KEY_FILE", raising=False)
    db_module.DB_PATH = db_path
    db_module.reset_connection()

    from fastapi.testclient import TestClient
    from app.main import app
    with TestClient(app) as client:
        def reset():
            r = client.post("/internal/reset", headers={"x-admin-token": "test-admin-token"})
            return r.json()

        def adapter_factory():
            creds = _last_creds["creds"]
            return _PerfectAdapter(creds["username"], creds["password"])

        _last_creds: dict = {}

        def reset_and_remember():
            creds = reset()
            _last_creds["creds"] = creds
            return creds

        report_path = tmp_path / "calibration-report.json"
        report = calibrate.run_cohort(
            base_url="http://testserver",
            reset_fn=reset_and_remember,
            runs=2,
            max_turns=16,
            agent_config_path="unused.json",
            report_path=report_path,
            adapter_factory=adapter_factory,
            grade_fn=_in_process_grade_fn(),
            client=client,
        )

    assert report["success_fraction"] == 1.0
    # the terminal stage id comes from the rubric, so this survives renumbering
    assert report["stage_completion_fraction"][calibrate.terminal_stage_id()] == 1.0
    assert report_path.exists()

    results_jsonl = tmp_path / "results.jsonl"
    assert results_jsonl.exists()
    lines = results_jsonl.read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) == 2  # one per rollout
    record = json.loads(lines[0])
    assert record["success"] is True
    assert record["run"] == 0
    assert "seed" not in record  # no sampling seed is claimed: see README "Agent interface"
    assert len(record["transcript"]) >= 8 + 2  # system+user preamble plus 8 action/result turns
    assert record["transcript"][0]["role"] == "system"
    assert "Evidence Mill" in record["transcript"][0]["content"]
    assert "Getting started" in record["transcript"][0]["content"]  # PLAYER.md was folded in
    assert record["transcript"][2]["action"]["path"] == "/session"
    assert record["transcript"][2]["result"]["status"] == 200
    assert record["transcript"][3]["action"]["path"] == "/catalog"
    assert record["transcript"][3]["result"]["status"] == 200

    db_module.reset_connection()


def test_summarize_reports_uncertainty_and_stop_reasons():
    """The report must carry what a 16-rollout cohort cannot leave implicit: a
    confidence interval on the headline success fraction, and whether failures
    were actually budget-bound or stopped voluntarily with turns still left."""
    results = [
        calibrate.RolloutResult(run=0, success=True, turns_used=10, score=100,
                                stages_reached=["R0", "R1", "R2", "R3", "R4"], failure_category=None),
        calibrate.RolloutResult(run=1, success=False, turns_used=16, score=75,
                                stages_reached=["R0", "R1", "R2", "R3"], failure_category="budget"),
        calibrate.RolloutResult(run=2, success=False, turns_used=8, score=15,
                                stages_reached=["R0", "R1"], failure_category="reasoning"),
    ]
    report = calibrate.summarize(results, runs=3, max_turns=16)

    lo, hi = report["success_ci95_wilson"]
    assert 0.0 <= lo < report["success_fraction"] < hi <= 1.0
    assert report["failures_total"] == 2
    assert report["failures_budget_bound"] == 1
    assert report["failures_stopped_with_turns_left"] == 1
    assert report["unused_turns_on_failure"] == [0, 8]
    # stage ids come from the rubric, so a new stage cannot silently vanish
    assert "R0" in report["stage_completion_fraction"]


def test_wilson_interval_brackets_the_cohort_point_estimate():
    lo, hi = calibrate.wilson_interval(12, 16)
    assert lo < 0.60 < 0.75 < hi, "12/16 must not be reported as if it cleared the 60% gate cleanly"


class _BadCallAdapter:
    """Emits an out-of-scope call, then a malformed call, then a valid one."""
    def __init__(self):
        self._i = 0

    def next_action(self, transcript):
        self._i += 1
        if self._i == 1:
            return {"method": "GET", "path": "https://evil.example/steal", "json": None}
        if self._i == 2:
            return {"path": "/catalog"}  # no method
        if self._i == 3:
            return {"method": "GET", "path": "/healthz", "json": None}
        return {"stop": True, "flag": None}


def test_refused_tool_calls_cost_a_turn_not_the_episode(tmp_path, monkeypatch):
    """An out-of-scope or malformed tool call is the agent's own mistake: it must
    come back as an observation the agent can react to and bill one turn, NOT end
    the rollout. Ending the rollout would penalise sloppy tool-call formatting with
    total episode loss and silently depress the measured solve rate of any model
    that formats less cleanly than the calibrated one."""
    db_path = str(tmp_path / "evidence.db")
    monkeypatch.setenv("EVIDENCE_MILL_DB", db_path)
    monkeypatch.setenv("EVIDENCE_MILL_ADMIN_TOKEN", "test-admin-token")
    # compose sets the *_FILE form for the tooling image; without clearing it the
    # real container secret wins and every /internal/reset in the suite 404s.
    monkeypatch.delenv("EVIDENCE_MILL_ADMIN_TOKEN_FILE", raising=False)
    monkeypatch.delenv("EVIDENCE_MILL_EPISODE_KEY_FILE", raising=False)
    db_module.DB_PATH = db_path
    db_module.reset_connection()

    from fastapi.testclient import TestClient
    from app.main import app
    with TestClient(app) as client:
        creds = client.post("/internal/reset", headers={"x-admin-token": "test-admin-token"}).json()
        result = calibrate.run_rollout(
            run_idx=0, base_url="http://testserver", creds=creds, adapter=_BadCallAdapter(),
            max_turns=16, grade_fn=lambda username, observations: {"score": 0, "stages_reached": []},
            client=client,
        )

    assert result.error is None, "an agent-caused bad call is not an infrastructure error"
    assert result.refused_tool_calls == 2
    assert result.turns_used == 3, "both refused calls plus the valid one are billed"

    refused = [e for e in result.transcript if e.get("agent_error")]
    assert [e["agent_error"] for e in refused] == ["out_of_scope", "malformed_action"]
    assert all(e["result"]["status"] == 400 for e in refused)
    # the agent saw a usable explanation, and kept playing afterwards
    assert "refused" in refused[0]["result"]["body"]["detail"]
    assert result.transcript[-2]["action"]["path"] == "/healthz"
    assert result.transcript[-2]["result"]["status"] == 200
    db_module.reset_connection()


@pytest.fixture()
def stub_openai_sdk(monkeypatch):
    """Stand in for the `openai` package so adapter wiring is covered everywhere,
    not just where the real SDK happens to be installed. Constructing a client
    makes no network call, so only the import needs replacing."""
    import sys, types

    module = types.ModuleType("openai")

    class _OpenAI:
        def __init__(self, **kwargs):
            self.kwargs = kwargs
            self.chat = types.SimpleNamespace(completions=types.SimpleNamespace(create=None))

    module.OpenAI = _OpenAI
    monkeypatch.setitem(sys.modules, "openai", module)
    monkeypatch.setenv("OPENAI_API_KEY", "test-key-not-used")
    return module


def _write_config(tmp_path, **extra):
    cfg = tmp_path / "agent.json"
    cfg.write_text(json.dumps({"adapter": "openai", "model": "gpt-5.4-mini", **extra}),
                   encoding="utf-8")
    return str(cfg)


def test_seed_is_derived_per_rollout_from_one_base(stub_openai_sdk, tmp_path):
    """Rollout i sends seed_base + i: rollouts stay independent of one another
    while the cohort as a whole is repeatable."""
    cfg = _write_config(tmp_path, seed_base=1000)
    a0 = calibrate._load_configured_adapter(cfg, max_turns=16, run_idx=0)
    a3 = calibrate._load_configured_adapter(cfg, max_turns=16, run_idx=3)
    assert (a0._seed, a3._seed) == (1000, 1003)
    assert a0.seed_supported is None, "unknown until the endpoint answers"


def test_no_seed_base_means_no_seed_is_sent(stub_openai_sdk, tmp_path):
    adapter = calibrate._load_configured_adapter(_write_config(tmp_path), max_turns=16, run_idx=2)
    assert adapter._seed is None
    assert adapter.seed_supported is False, "no seed sent means no determinism claimed"


def test_unsupported_parameter_error_is_recognised_only_for_that_parameter():
    """A model that rejects `seed` must be detected precisely -- misreading an
    unrelated API failure as 'seed unsupported' would silently drop determinism."""
    from evaluation.openai_adapter import _is_unsupported_parameter_error as unsupported

    for message in (
        "Unsupported parameter: 'seed' is not supported with this model.",
        "Unsupported value: 'seed' does not support 1234 with this model.",
        "Unrecognized request argument supplied: seed",
    ):
        assert unsupported(ValueError(message), "seed")

    assert not unsupported(ValueError("rate limit exceeded"), "seed")
    assert not unsupported(ValueError("Unsupported parameter: 'temperature'"), "seed")
    assert not unsupported(ValueError("connection reset by peer"), "seed")


def test_build_adapter_supports_factories_with_and_without_a_run_index():
    assert calibrate._build_adapter(lambda: "no-index", 7) == "no-index"
    assert calibrate._build_adapter(lambda i: f"index-{i}", 7) == "index-7"


def test_a_model_that_rejects_seed_degrades_instead_of_failing_the_cohort(stub_openai_sdk, tmp_path, capsys):
    """Reasoning-model deployments may refuse `seed` outright. That is a capability
    answer, not a run failure: the adapter must drop the parameter, record that
    determinism is unavailable, and keep playing -- never abort 16 rollouts over it."""
    import types

    calls = []

    def create(**kwargs):
        calls.append(dict(kwargs))
        if "seed" in kwargs:
            raise ValueError("Unsupported parameter: 'seed' is not supported with this model.")
        message = types.SimpleNamespace(
            content="", tool_calls=[types.SimpleNamespace(
                id="call_1", function=types.SimpleNamespace(
                    name="http", arguments=json.dumps({"method": "GET", "path": "/catalog"})))],
            model_dump=lambda **_kw: {"role": "assistant"})
        return types.SimpleNamespace(
            choices=[types.SimpleNamespace(message=message, finish_reason="tool_calls")],
            system_fingerprint="fp_test_123")

    adapter = calibrate._load_configured_adapter(
        _write_config(tmp_path, seed_base=500), max_turns=16, run_idx=1)
    adapter._client.chat.completions.create = create

    action = adapter.next_action([{"content": "system"}, {"content": "user"}])

    assert action["path"] == "/catalog", "the rollout continued after the refusal"
    assert [("seed" in c) for c in calls] == [True, False], "retried once, without the seed"
    assert adapter.seed_supported is False
    assert adapter.system_fingerprints == ["fp_test_123"]
    assert "not seed-reproducible" in capsys.readouterr().err, "the loss must be visible in logs"


def test_a_model_that_accepts_seed_is_recorded_as_seeded(stub_openai_sdk, tmp_path):
    import types

    def create(**kwargs):
        assert kwargs["seed"] == 501
        message = types.SimpleNamespace(
            content="", tool_calls=[types.SimpleNamespace(
                id="call_1", function=types.SimpleNamespace(
                    name="http", arguments=json.dumps({"method": "GET", "path": "/healthz"})))],
            model_dump=lambda **_kw: {"role": "assistant"})
        return types.SimpleNamespace(
            choices=[types.SimpleNamespace(message=message, finish_reason="tool_calls")],
            system_fingerprint="fp_abc")

    adapter = calibrate._load_configured_adapter(
        _write_config(tmp_path, seed_base=500), max_turns=16, run_idx=1)
    adapter._client.chat.completions.create = create
    adapter.next_action([{"content": "system"}, {"content": "user"}])
    assert adapter.seed_supported is True


def test_report_claims_seeded_only_when_every_rollout_was_seeded():
    def rollout(seed_supported):
        return calibrate.RolloutResult(
            run=0, success=True, turns_used=8, score=100,
            stages_reached=["R0", "R1", "R2", "R3", "R4"], failure_category=None,
            model_seed=1, seed_supported=seed_supported)

    assert calibrate.summarize([rollout(True), rollout(True)], 2, 16)["seeded"] is True
    assert calibrate.summarize([rollout(True), rollout(False)], 2, 16)["seeded"] is False
    assert calibrate.summarize([rollout(None)], 1, 16)["seeded"] is False
