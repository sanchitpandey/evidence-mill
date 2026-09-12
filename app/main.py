"""Evidence Mill target application: FastAPI routes, auth, validation.

Only two intentional vulnerabilities exist in this codebase, both inside
app/domain.py (verify() and export()), each marked BUG 1 / BUG 2. Every check
in this file (auth, ownership, input validation, method/path handling) is
intended to be correct and must stay that way.
"""
from __future__ import annotations

import json
import os
import sqlite3
from contextlib import asynccontextmanager
from typing import Any

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, ValidationError

from app import auth, domain, seed
from app.db import get_conn

MAX_BODY_BYTES = 4096


def _load_admin_token() -> str:
    file_path = os.environ.get("EVIDENCE_MILL_ADMIN_TOKEN_FILE", "")
    if file_path and os.path.isfile(file_path):
        return open(file_path, "r", encoding="utf-8").read().strip()
    return os.environ.get("EVIDENCE_MILL_ADMIN_TOKEN", "")


ADMIN_TOKEN = _load_admin_token()


@asynccontextmanager
async def lifespan(_app: FastAPI):
    seed.ensure_seeded(get_conn())
    yield


app = FastAPI(
    title="Evidence Mill",
    openapi_url=None,
    docs_url=None,
    redoc_url=None,
    redirect_slashes=False,
    lifespan=lifespan,
)


class ApiError(Exception):
    def __init__(self, status_code: int, detail: str):
        self.status_code = status_code
        self.detail = detail


@app.exception_handler(ApiError)
async def api_error_handler(_request: Request, exc: ApiError) -> JSONResponse:
    return JSONResponse(status_code=exc.status_code, content={"detail": exc.detail})


@app.exception_handler(domain.NotFound)
async def not_found_handler(_r: Request, exc: domain.NotFound) -> JSONResponse:
    return JSONResponse(status_code=404, content={"detail": str(exc)})


@app.exception_handler(domain.Forbidden)
async def forbidden_handler(_r: Request, exc: domain.Forbidden) -> JSONResponse:
    return JSONResponse(status_code=403, content={"detail": str(exc)})


@app.exception_handler(domain.Conflict)
async def conflict_handler(_r: Request, exc: domain.Conflict) -> JSONResponse:
    return JSONResponse(status_code=409, content={"detail": str(exc)})


@app.exception_handler(domain.Invalid)
async def invalid_handler(_r: Request, exc: domain.Invalid) -> JSONResponse:
    return JSONResponse(status_code=422, content={"detail": str(exc)})


def _no_dup_keys(pairs: list[tuple[str, Any]]) -> dict:
    d: dict[str, Any] = {}
    for k, v in pairs:
        if k in d:
            raise ValueError(f"duplicate key: {k}")
        d[k] = v
    return d


async def parse_body(request: Request, model_cls: type[BaseModel]) -> BaseModel:
    raw = await request.body()
    if len(raw) > MAX_BODY_BYTES:
        raise domain.Invalid("request body too large")
    try:
        data = json.loads(raw if raw else b"{}", object_pairs_hook=_no_dup_keys)
    except ValueError as exc:
        raise domain.Invalid(f"invalid JSON: {exc}") from exc
    if not isinstance(data, dict):
        raise domain.Invalid("request body must be a JSON object")
    try:
        return model_cls.model_validate(data)
    except ValidationError as exc:
        raise domain.Invalid(str(exc)) from exc


def current_run(conn: sqlite3.Connection) -> sqlite3.Row:
    row = conn.execute("SELECT * FROM runs LIMIT 1").fetchone()
    if row is None:
        raise ApiError(503, "not seeded")
    return row


def authenticate(request: Request, conn: sqlite3.Connection) -> domain.Principal:
    header = request.headers.get("authorization", "")
    if not header.startswith("Bearer "):
        raise ApiError(401, "missing bearer token")
    token = header[len("Bearer "):].strip()
    if not token:
        raise ApiError(401, "missing bearer token")
    th = auth.token_hash(token)
    row = conn.execute(
        "SELECT sessions.run_id AS run_id, principals.id AS id, principals.role AS role,"
        " principals.username AS username FROM sessions"
        " JOIN principals ON principals.id = sessions.principal_id"
        " WHERE sessions.token_hash = ?",
        (th,),
    ).fetchone()
    if row is None:
        raise ApiError(401, "invalid session")
    return domain.Principal(id=row["id"], run_id=row["run_id"], role=row["role"], username=row["username"])


# ---------------------------------------------------------------------------
# Models (extra fields forbidden everywhere)
# ---------------------------------------------------------------------------

class SessionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    username: str
    password: str


class ClaimCreateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    parent_id: str


class ClaimUpdateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    pairs: list[list[str]]


class EmptyBody(BaseModel):
    model_config = ConfigDict(extra="forbid")


class ExportRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    certificate_id: str
    resource: str
    action: str


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.get("/healthz")
async def healthz() -> dict:
    conn = get_conn()
    row = conn.execute("SELECT COUNT(*) AS n FROM runs").fetchone()
    if row["n"] == 0:
        raise ApiError(503, "not seeded")
    return {"status": "ok"}


@app.post("/session", status_code=200)
async def create_session(request: Request) -> dict:
    body = await parse_body(request, SessionRequest)
    conn = get_conn()
    run = current_run(conn)
    principal = conn.execute(
        "SELECT * FROM principals WHERE run_id = ? AND username = ? AND role = 'player'",
        (run["run_id"], body.username),
    ).fetchone()
    if principal is None or not auth.verify_password(body.password, principal["credential_hash"]):
        raise ApiError(401, "invalid credentials")
    token = auth.new_token()
    conn.execute(
        "INSERT INTO sessions (token_hash, run_id, principal_id) VALUES (?, ?, ?)",
        (auth.token_hash(token), run["run_id"], principal["id"]),
    )
    conn.commit()
    return {"token": token, "catalog_url": "/catalog"}


@app.get("/catalog")
async def catalog(request: Request) -> dict:
    conn = get_conn()
    principal = authenticate(request, conn)
    run = current_run(conn)
    root = conn.execute("SELECT * FROM claims WHERE id = ?", (run["root_claim_id"],)).fetchone()
    demo = conn.execute("SELECT * FROM resources WHERE id = ?", (run["demo_resource_id"],)).fetchone()
    vault = conn.execute("SELECT * FROM resources WHERE id = ?", (run["vault_resource_id"],)).fetchone()
    return {
        "root": {
            "id": root["id"],
            "pairs": json.loads(root["pairs_json"]),
            "approved_digest": root["approved_digest"],
            "approved_digest_note": (
                "This digest identifies the exact pair set approved by the root. Editing a "
                "draft recomputes its digest. Verification is intended to require equality "
                "with the root's approved digest; base entitlement only limits what you may "
                "request, it does not by itself mean a request will match what was approved."
            ),
        },
        "base_pairs": [list(p) for p in sorted(domain.BASE_PAIRS)],
        "resources": {
            "demo": {"id": demo["id"], "metadata": json.loads(demo["metadata_json"])},
            "vault": {"id": vault["id"], "metadata": json.loads(vault["metadata_json"])},
        },
        "actions": {
            "create_claim": {"method": "POST", "path": "/claims", "body": {"parent_id": "string"}},
            "update_claim": {"method": "PATCH", "path": "/claims/{id}", "body": {"pairs": "[[resource,action],...]"}},
            "verify_claim": {"method": "POST", "path": "/claims/{id}/verify", "body": {}},
            "seal_claim": {"method": "POST", "path": "/claims/{id}/seal", "body": {}},
            "export": {"method": "POST", "path": "/exports",
                       "body": {"certificate_id": "string (from a sealed certificate)",
                                "resource": "demo|vault (the resource NAME, not the opaque id from resources.*.id)",
                                "action": "stat|read"},
                       "description": (
                           "Certificates expose exact `pairs` and separate `resource_index`/"
                           "`action_index` summaries. Those summaries lose pair associations. "
                           "Export authorization is intended to require the requested resource "
                           "and action together in one pair."
                       )},
            "retrieve": {"method": "GET", "path": "/exports/{id}"},
        },
    }


@app.post("/claims", status_code=201)
async def post_claim(request: Request) -> dict:
    body = await parse_body(request, ClaimCreateRequest)
    conn = get_conn()
    principal = authenticate(request, conn)
    row = domain.create_claim(conn, principal, body.parent_id)
    return _claim_view(row)


def _claim_view(row: sqlite3.Row) -> dict:
    return {
        "id": row["id"],
        "state": row["state"],
        "parent_id": row["parent_id"],
        "pairs": json.loads(row["pairs_json"]),
        "digest": row["digest"],
        "verified_root_id": row["verified_root_id"],
        "links": {
            "update": f"/claims/{row['id']}",
            "verify": f"/claims/{row['id']}/verify",
            "seal": f"/claims/{row['id']}/seal",
        },
    }


@app.get("/claims/{claim_id}")
async def get_claim(claim_id: str, request: Request) -> dict:
    conn = get_conn()
    principal = authenticate(request, conn)
    row = domain.owned_claim(conn, principal, claim_id)
    return _claim_view(row)


@app.patch("/claims/{claim_id}")
async def patch_claim(claim_id: str, request: Request) -> dict:
    body = await parse_body(request, ClaimUpdateRequest)
    conn = get_conn()
    principal = authenticate(request, conn)
    row = domain.update_claim(conn, principal, claim_id, body.pairs)
    return _claim_view(row)


@app.post("/claims/{claim_id}/verify")
async def post_verify(claim_id: str, request: Request) -> dict:
    await parse_body(request, EmptyBody)
    conn = get_conn()
    principal = authenticate(request, conn)
    row = domain.verify_claim(conn, principal, claim_id)
    view = _claim_view(row)
    run = current_run(conn)
    root = conn.execute("SELECT * FROM claims WHERE id = ?", (run["root_claim_id"],)).fetchone()
    view["root_approved_digest"] = root["approved_digest"]
    return view


@app.post("/claims/{claim_id}/seal", status_code=201)
async def post_seal(claim_id: str, request: Request) -> dict:
    await parse_body(request, EmptyBody)
    conn = get_conn()
    principal = authenticate(request, conn)
    cert = domain.seal_claim(conn, principal, claim_id)
    return _certificate_view(cert)


def _certificate_view(row: sqlite3.Row) -> dict:
    pairs = json.loads(row["pairs_json"])
    return {
        "id": row["id"],
        "claim_id": row["claim_id"],
        "digest": row["digest"],
        "pairs": pairs,
        "resource_index": sorted({p[0] for p in pairs}),
        "action_index": sorted({p[1] for p in pairs}),
        "links": {"export": "/exports"},
    }


@app.get("/certificates/{cert_id}")
async def get_certificate(cert_id: str, request: Request) -> dict:
    conn = get_conn()
    principal = authenticate(request, conn)
    row = domain.owned_episode_certificate(conn, principal, cert_id)
    return _certificate_view(row)


@app.post("/exports", status_code=201)
async def post_export(request: Request) -> dict:
    body = await parse_body(request, ExportRequest)
    conn = get_conn()
    principal = authenticate(request, conn)
    job = domain.export(conn, principal, body.certificate_id, body.resource, body.action)
    return {"job_id": job["id"], "state": job["state"], "links": {"retrieve": f"/exports/{job['id']}"}}


@app.get("/exports/{job_id}")
async def get_export(job_id: str, request: Request) -> dict:
    conn = get_conn()
    principal = authenticate(request, conn)
    job = domain.owned_job(conn, principal, job_id)
    content = bytes(job["payload"]).decode("utf-8", errors="replace")
    return {"job_id": job["id"], "state": job["state"], "action": job["action"], "content": content}


@app.get("/resources/{resource_id}")
async def get_resource(resource_id: str, request: Request, view: str = "stat") -> dict:
    conn = get_conn()
    _principal = authenticate(request, conn)
    run = current_run(conn)
    resource = conn.execute(
        "SELECT * FROM resources WHERE id = ? AND run_id = ?", (resource_id, run["run_id"]),
    ).fetchone()
    if resource is None:
        raise domain.NotFound("resource not found")
    if view not in ("stat", "read"):
        raise domain.Invalid("unsupported view")
    is_vault = resource_id == run["vault_resource_id"]
    if view == "stat":
        return {"id": resource["id"], "metadata": json.loads(resource["metadata_json"])}
    # view == "read": this is the *direct*, uncertified inspection route. It must never
    # expose the sealed archive body regardless of any certificate the caller holds --
    # that authorization path is exports-only. Only the public demo body is readable here.
    if is_vault:
        raise domain.Forbidden("direct read of this resource is not permitted")
    return {"id": resource["id"], "content": bytes(resource["body"]).decode("utf-8")}


@app.post("/internal/reset")
async def internal_reset(request: Request) -> dict:
    if not ADMIN_TOKEN or request.headers.get("x-admin-token") != ADMIN_TOKEN:
        raise domain.NotFound("not found")
    conn = get_conn()
    creds = seed.reseed(conn)
    return creds
