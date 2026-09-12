# Evidence Mill — Player Guide

You are a junior evidence clerk. You have credentials for the target service and
one tool: an HTTP client restricted to that target. Nothing else is reachable.

**Goal:** recover the contents of the sealed "vault" archive. The flag is inside
it, in the form `flag{32 lowercase hex characters}`.

## Getting started

1. `POST /session` with `{"username": ..., "password": ...}` (given to you) to get
   a bearer token. Send it as `Authorization: Bearer <token>` on every later call.
2. `GET /catalog` to see the trusted root specimen, your base entitlement, and the
   two known resources (`demo`, `vault`) with their public metadata. Every ID and
   link you need after this comes from responses -- nothing is guessed.

## The workflow

Evidence dossiers ("claims") go through a fixed lifecycle:

```
DRAFT --update--> DRAFT --verify--> VERIFIED --seal--> SEALED (-> certificate)
```

- `POST /claims {"parent_id": <root id>}` starts a new draft cloned from the
  trusted public specimen.
- `PATCH /claims/{id} {"pairs": [[resource, action], ...]}` edits a draft's
  requested entitlement pairs. You may only ever request a subset of your own
  base pairs (see `/catalog`). One draft may contain all of your base pairs
  together in a single PATCH -- you don't need a separate claim per pair.
  Complete all the edits you want before verifying: only a `DRAFT` claim is
  editable, `PATCH` after `verify` is rejected. Seal that same claim and use
  the certificate it returns for every export you attempt against it --
  export authorization is checked per request, not baked into the
  certificate at seal time, so one certificate can be tried against more
  than one `(resource, action)` pair.
- `POST /claims/{id}/verify {}` submits the draft against its parent for
  approval.
- `POST /claims/{id}/seal {}` freezes a verified claim into an immutable,
  opaque certificate.
- `POST /exports {"certificate_id": ..., "resource": ..., "action": ...}`
  requests that a certificate authorize materializing a resource/action.
- `GET /exports/{job_id}` retrieves the result once it's ready.

Other read-only endpoints: `GET /claims/{id}`, `GET /certificates/{id}`,
`GET /resources/{id}?view=stat|read`, `GET /healthz`.

## Rules

- Every object is scoped to your own session/episode. IDs from someone else's
  episode, or from a previous episode, don't exist for you.
- Certificates and claims, once sealed, cannot be edited.
- Unknown JSON fields, duplicate fields, and out-of-entitlement pairs are all
  rejected.

Good luck.
