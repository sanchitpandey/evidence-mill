"""The single agent-facing tool: http(method, path, json). One HTTP request per
call, no redirects, no batching, no automatic retries, target-only base_url.
N calls to this tool == N turns for calibration purposes.

The tool's own schema (see evaluation/anthropic_adapter.py TOOL_SCHEMA and the
design doc's `http(method, path, json)` contract) has no `headers` parameter --
the agent is never asked to track or forward a bearer token itself. HttpTool
therefore manages session continuity transparently: it watches every response
body for a top-level "token" field (POST /session's shape) and auto-attaches
`Authorization: Bearer <token>` to every later call, the same way a browser
would carry a cookie forward. An explicit `headers=` argument (used by
evaluation/reference.py, which manages its own token) always takes precedence.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import httpx


class OutOfScopeRequest(ValueError):
    """Raised when a tool call tries to escape the target base_url. httpx's
    Client.request treats an absolute URL passed as `path` as an override of
    base_url, not a relative path against it -- so without this check, an
    agent (or a bug) could point the "target-only" tool at an arbitrary host."""


def _confine_to_target(path: str) -> None:
    if "://" in path or path.startswith("//"):
        raise OutOfScopeRequest(
            f"path must be relative to the target base_url; got an absolute-looking path: {path!r}"
        )


@dataclass
class Call:
    method: str
    path: str
    status: int
    body: Any


class HttpTool:
    """Wraps a single httpx.Client bound to the target base_url.

    Usage: tool = HttpTool("http://127.0.0.1:8000"); tool("GET", "/catalog")
    """

    def __init__(self, base_url: str | None = None, timeout: float = 5.0, client=None):
        if client is not None:
            # Testing-only hook: reuse an already-working client object (e.g. a
            # fastapi.testclient.TestClient, which IS an httpx.Client subclass
            # wired to its own in-process ASGI transport) instead of trying to
            # rebuild a new httpx.Client around a borrowed transport -- that
            # construction path has version-sensitive internals (observed to
            # break between some httpx/starlette version pairings) that have
            # nothing to do with real network calls, which is the only thing
            # HttpTool does in production.
            self._client = client
            self._owns_client = False
        else:
            self._client = httpx.Client(base_url=base_url, timeout=timeout, follow_redirects=False,
                                         trust_env=False)
            self._owns_client = True
        self.history: list[Call] = []
        self._session_token: str | None = None

    @property
    def turns_used(self) -> int:
        return len(self.history)

    def __call__(self, method: str, path: str, json: dict | None = None,
                 headers: dict | None = None) -> dict:
        _confine_to_target(path)
        effective_headers = dict(headers) if headers else {}
        if self._session_token and not any(k.lower() == "authorization" for k in effective_headers):
            effective_headers["Authorization"] = f"Bearer {self._session_token}"
        resp = self._client.request(method.upper(), path, json=json, headers=effective_headers or None)
        try:
            body: Any = resp.json()
        except ValueError:
            body = resp.text
        if isinstance(body, dict) and isinstance(body.get("token"), str):
            self._session_token = body["token"]
        self.history.append(Call(method=method.upper(), path=path, status=resp.status_code, body=body))
        return {"status": resp.status_code, "body": body}

    def close(self) -> None:
        if not self._owns_client:
            return  # a borrowed test client's lifecycle belongs to its caller
        self._client.close()

    def __enter__(self) -> "HttpTool":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()
