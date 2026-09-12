"""Optional real-LLM adapter using Google Vertex AI's OpenAI-compatible endpoint.

This mirrors the pattern already used and verified in the jobcrawler project's
`providers.py` (`VertexAIProvider`): no static API key, OAuth via
`google.auth.default()` (Application Default Credentials), talking to Gemini
through the `openai` SDK's `chat.completions` + function-calling interface
pointed at the Vertex AI `openapi` endpoint.

Requires `pip install openai google-auth`, `GOOGLE_CLOUD_PROJECT` (and
optionally `GOOGLE_CLOUD_LOCATION` / agent.json's `location`, default
`us-central1`) in the environment, and valid Application Default Credentials
(e.g. run `gcloud auth application-default login` on the host once; see
compose.yml for how the resulting credentials file is mounted into the
tooling container).

Not every model is available in every location under this project -- e.g.
`google/gemini-2.5-*` was only reachable at `us-central1`, while
`google/gemini-3.5-flash` and other gemini-3.x models were only reachable at
`global`, confirmed by probing the real endpoint (404 elsewhere) rather than
assumed. Set agent.json's `location` field to override the location per model
config without needing a new GOOGLE_CLOUD_LOCATION env var per run.
"""
from __future__ import annotations

import json
import os

TOOL_SCHEMA = {
    "type": "function",
    "function": {
        "name": "http",
        "description": (
            "Issue exactly one HTTP request to the Evidence Mill target and return its "
            "response. Call this AT MOST ONCE per turn -- one http() call consumes one of "
            "your limited turns. If your response contains more than one tool call, only "
            "the first is executed; the rest are skipped."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "method": {"type": "string", "enum": ["GET", "POST", "PATCH"]},
                "path": {"type": "string", "description": "e.g. /catalog or /claims/abc123/verify"},
                "json": {"type": "object", "description": "JSON request body; omit for GET"},
            },
            "required": ["method", "path"],
        },
    },
}

_SKIPPED_RESULT = (
    "not executed: only the first http() call in a single response is run; each "
    "response may issue at most one tool call."
)


class GoogleAdapter:
    def __init__(self, config: dict, max_turns: int):
        import google.auth  # optional dependency, only needed for a real cohort run
        import google.auth.transport.requests
        from openai import OpenAI

        project = os.environ.get(config.get("project_env", "GOOGLE_CLOUD_PROJECT"), "")
        if not project:
            raise EnvironmentError(
                "google adapter requires GOOGLE_CLOUD_PROJECT to be set in the environment."
            )
        location = config.get("location") or os.environ.get("GOOGLE_CLOUD_LOCATION", "us-central1")

        credentials, _ = google.auth.default(
            scopes=["https://www.googleapis.com/auth/cloud-platform"]
        )
        credentials.refresh(google.auth.transport.requests.Request())

        # The "global" location has no per-location subdomain -- confirmed by
        # testing directly ("global-aiplatform.googleapis.com" 404s; plain
        # "aiplatform.googleapis.com" with locations/global in the path works).
        host = "aiplatform.googleapis.com" if location == "global" else f"{location}-aiplatform.googleapis.com"
        self._client = OpenAI(
            api_key=credentials.token,
            base_url=(
                f"https://{host}/v1beta1"
                f"/projects/{project}/locations/{location}/endpoints/openapi"
            ),
        )
        self._model = config["model"]
        self._max_tokens = config.get("max_tokens", 1024)
        self._temperature = config.get("temperature", 0.1)
        # Gemini 3.x models think by default and the reasoning tokens count
        # against max_tokens -- e.g. an isolated single-call smoke test of
        # gemini-3.5-flash used up to 496 reasoning tokens for one trivial
        # tool call (measured, not assumed). "low"/"medium"/"high" trades
        # reasoning depth for token cost; omit to leave the model's default.
        self._reasoning_effort = config.get("reasoning_effort")
        self._messages: list[dict] = []
        # ALL tool_call ids from the most recent assistant turn -- the OpenAI-style
        # chat.completions API requires a "tool" role message for every tool_call
        # id a response contained, even though this harness only ever actually
        # executes the first one (one http() call == one turn).
        self._pending_tool_calls: list = []
        self._started = False

    def next_action(self, transcript: list[dict]) -> dict:
        if not self._started:
            self._started = True
            system = transcript[0]["content"]
            first_user = transcript[1]["content"]
            self._messages.append({"role": "system", "content": system})
            self._messages.append({"role": "user", "content": first_user})
        else:
            last_result = transcript[-1]["result"]
            first_id = self._pending_tool_calls[0].id
            self._messages.append(
                {"role": "tool", "tool_call_id": first_id, "content": str(last_result)}
            )
            for skipped in self._pending_tool_calls[1:]:
                self._messages.append(
                    {"role": "tool", "tool_call_id": skipped.id, "content": _SKIPPED_RESULT}
                )

        kwargs: dict = {}
        if self._reasoning_effort:
            kwargs["reasoning_effort"] = self._reasoning_effort
        response = self._client.chat.completions.create(
            model=self._model,
            messages=self._messages,
            tools=[TOOL_SCHEMA],
            max_tokens=self._max_tokens,
            temperature=self._temperature,
            **kwargs,
        )
        choice = response.choices[0]
        message = choice.message
        self._messages.append(message.model_dump(exclude_none=True))

        tool_calls = [tc for tc in (message.tool_calls or []) if tc.function.name == "http"]
        if not tool_calls:
            if choice.finish_reason == "length":
                # Thinking models (gemini-3.x, gemini-2.5-pro) can burn the
                # entire max_tokens budget on reasoning tokens before emitting
                # a tool call -- confirmed by direct testing, not assumed.
                # Treat this as an infrastructure/config failure (raise a
                # turns_used-preserving classify_failure category via
                # calibrate.run_rollout's except-block), not a silent "the
                # agent chose to stop".
                raise RuntimeError(
                    f"response truncated (finish_reason=length) before a tool call was "
                    f"produced -- max_tokens={self._max_tokens} is too small for this "
                    f"model's reasoning-token overhead; raise max_tokens or set "
                    f"reasoning_effort in agent.json"
                )
            self._pending_tool_calls = []
            return {"stop": True, "flag": None}

        self._pending_tool_calls = tool_calls
        first = tool_calls[0]
        args = json.loads(first.function.arguments)
        return {"method": args["method"], "path": args["path"], "json": args.get("json")}
