"""Regression coverage for the agent-facing HttpTool's target confinement.
httpx treats an absolute URL passed to Client.request as an override of
base_url rather than a path relative to it -- HttpTool must reject that
itself, since the whole "target-only" safety claim for the agent interface
depends on it."""
import pytest

from evaluation.http_tool import HttpTool, OutOfScopeRequest


def test_absolute_url_is_rejected():
    tool = HttpTool("http://127.0.0.1:9", timeout=1.0)
    with pytest.raises(OutOfScopeRequest):
        tool("GET", "http://example.com/")
    tool.close()


def test_scheme_relative_url_is_rejected():
    tool = HttpTool("http://127.0.0.1:9", timeout=1.0)
    with pytest.raises(OutOfScopeRequest):
        tool("GET", "//example.com/")
    tool.close()


def test_ordinary_relative_path_is_not_rejected_by_confinement_check():
    # We only assert the confinement check itself doesn't fire; connecting to
    # a real target is covered elsewhere (test_calibrate_harness.py, reference.py).
    from evaluation.http_tool import _confine_to_target
    _confine_to_target("/catalog")
    _confine_to_target("/claims/abc123/verify")


def test_session_token_is_captured_and_auto_attached(episode):
    """The agent-facing tool schema has no `headers` parameter -- HttpTool must
    manage the bearer token itself once a login response hands one back,
    exactly like a browser carries a cookie forward. This is what makes a real
    LLM agent (which never sees a headers field to fill in) able to reach any
    endpoint past /session."""
    ep = episode
    tool = HttpTool(client=ep["client"])

    r = tool("POST", "/session", json={"username": ep["creds"]["username"], "password": ep["creds"]["password"]})
    assert r["status"] == 200
    assert tool._session_token == r["body"]["token"]

    # No headers passed here at all -- must still be authenticated.
    r2 = tool("GET", "/catalog")
    assert r2["status"] == 200
    assert "root" in r2["body"]
    tool.close()
