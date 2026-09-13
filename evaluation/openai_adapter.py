"""Native OpenAI adapter using the OpenAI Chat Completions tool-use API.

Talks directly to `api.openai.com` (or an OpenAI-compatible endpoint, via
`base_url`/`OPENAI_BASE_URL`) using the `openai` SDK's `chat.completions` and
function-calling interface. It is the sole model adapter shipped with the
frozen submission.

Requires `pip install openai` (already listed in requirements-tooling) and
`OPENAI_API_KEY` in the environment (or `api_key_env` in agent config pointing
at a different environment variable name).
"""
from __future__ import annotations

import json
import os
import sys

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


def _is_unsupported_parameter_error(exc: Exception, param: str) -> bool:
    """True when the endpoint refused a request specifically because `param` is
    not supported by this model, as opposed to any other API failure."""
    text = str(exc).lower()
    return param in text and any(
        marker in text for marker in
        ("unsupported parameter", "unsupported value", "unrecognized request argument",
         "not supported with this model", "does not support")
    )


class OpenAIAdapter:
    def __init__(self, config: dict, max_turns: int, seed: int | None = None):
        from openai import OpenAI

        api_key = os.environ.get(config.get("api_key_env", "OPENAI_API_KEY"), "")
        if not api_key:
            raise EnvironmentError(
                "openai adapter requires OPENAI_API_KEY in the environment "
                "(or set api_key_env in the agent config)."
            )
        # The OpenAI SDK also reads OPENAI_BASE_URL directly from the environment.
        # compose.yml sets it to an empty string when the user hasn't provided one,
        # and the SDK turns that blank value into a protocol-less base URL -- every
        # request then fails with APIConnectionError (UnsupportedProtocol). Normalize
        # an empty value to unset and ALWAYS pass an explicit base_url so the SDK
        # never falls back to the blank env var. A real OPENAI_BASE_URL (e.g. Azure
        # or an OpenAI-compatible endpoint) is still honored when non-empty.
        env_base = (os.environ.get("OPENAI_BASE_URL") or "").strip()
        base_url = config.get("base_url") or env_base or "https://api.openai.com/v1"
        self._client = OpenAI(api_key=api_key, base_url=base_url)

        self._model = config["model"]
        self._max_tokens = config.get("max_tokens", 4096)
        # Which token-budget parameter this model expects. Reasoning models
        # (gpt-5*, o-series) reject "max_tokens" and require "max_completion_tokens";
        # 4.1/4o-class models use "max_tokens". Set token_param in the agent config.
        self._token_param = config.get("token_param", "max_tokens")
        self._temperature = config.get("temperature")
        self._reasoning_effort = config.get("reasoning_effort")
        self._max_empty_retries = int(config.get("max_empty_retries", 4))
        # Best-effort determinism. OpenAI documents `seed` as Beta and explicitly
        # does NOT guarantee it ("refer to the system_fingerprint response
        # parameter to monitor changes in the backend"). Sending it is still
        # strictly better than not sending it: it removes one source of variance
        # for free. What it must never do is fail the cohort if this model class
        # rejects the parameter -- hence seed_supported below.
        self._seed = seed
        self.seed_supported: bool | None = None if seed is not None else False
        self._messages: list[dict] = []
        # ALL tool_call ids from the most recent assistant turn -- the OpenAI-style
        # chat.completions API requires a "tool" role message for every tool_call
        # id a response contained, even though this harness only ever actually
        # executes the first one (one http() call == one turn).
        self._pending_tool_calls: list = []
        self._started = False
        # Backend configuration ids seen during this rollout. OpenAI documents
        # system_fingerprint as the way to "monitor changes in the backend" that
        # affect determinism; it changes when OpenAI updates the serving stack.
        # Recording it does not make anything reproducible -- it makes a LATER
        # comparison between two cohorts interpretable, by showing whether they
        # ran against the same backend at all. Free to collect, so collect it.
        self.system_fingerprints: list[str] = []

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
        if self._temperature is not None:
            kwargs["temperature"] = self._temperature
        kwargs[self._token_param] = self._max_tokens
        if self._seed is not None and self.seed_supported is not False:
            kwargs["seed"] = self._seed

        # An empty/malformed completion -- no usable http() tool call AND no
        # natural-language text -- is a transient model/endpoint failure, NOT the
        # agent deciding to stop. Silently returning stop here scores the rollout
        # as a premature "reasoning" failure when nothing about the agent's
        # reasoning caused it. A retried model call issues no http() request, so
        # it does not consume one of the agent's turns; retry a bounded number of
        # times (logging finish_reason each time so the cause is in the logs), and
        # only surface a classified infrastructure error if the endpoint keeps
        # returning nothing usable. A genuine final text answer with no tool call
        # is still a real stop and is returned as one.
        last_finish_reason = None
        for attempt in range(self._max_empty_retries + 1):
            try:
                response = self._client.chat.completions.create(
                    model=self._model,
                    messages=self._messages,
                    tools=[TOOL_SCHEMA],
                    **kwargs,
                )
                if "seed" in kwargs:
                    self.seed_supported = True
            except Exception as exc:  # noqa: BLE001 -- narrowed immediately below
                # Reasoning-model deployments may reject `seed` outright. That is a
                # capability answer, not a run failure: drop the parameter, record
                # that determinism is unavailable here, and carry on unseeded.
                if "seed" in kwargs and _is_unsupported_parameter_error(exc, "seed"):
                    print(f"[openai_adapter] model {self._model!r} rejected `seed` "
                          f"({str(exc)[:120]}); continuing WITHOUT it. This cohort is "
                          f"not seed-reproducible.", file=sys.stderr, flush=True)
                    self.seed_supported = False
                    kwargs.pop("seed")
                    response = self._client.chat.completions.create(
                        model=self._model,
                        messages=self._messages,
                        tools=[TOOL_SCHEMA],
                        **kwargs,
                    )
                else:
                    raise
            fingerprint = getattr(response, "system_fingerprint", None)
            if fingerprint and fingerprint not in self.system_fingerprints:
                self.system_fingerprints.append(fingerprint)
            choice = response.choices[0]
            message = choice.message
            last_finish_reason = choice.finish_reason
            text = message.content or ""

            tool_calls = [tc for tc in (message.tool_calls or []) if tc.function.name == "http"]
            parsed = None
            if tool_calls:
                try:
                    parsed = json.loads(tool_calls[0].function.arguments)
                except (ValueError, TypeError):
                    parsed = None  # malformed arguments -> unusable, retry

            if isinstance(parsed, dict) and "method" in parsed and "path" in parsed:
                self._messages.append(message.model_dump(exclude_none=True))
                self._pending_tool_calls = tool_calls
                return {"method": parsed["method"], "path": parsed["path"],
                        "json": parsed.get("json"), "text": text,
                        "finish_reason": last_finish_reason}

            if last_finish_reason == "length":
                raise RuntimeError(
                    f"response truncated (finish_reason=length) before a tool call was "
                    f"produced -- max_tokens={self._max_tokens} is too small for this "
                    f"model's reasoning-token overhead; raise max_tokens or set "
                    f"reasoning_effort in agent.json"
                )

            if text.strip():
                # A genuine final answer with no tool call: the model chose to stop.
                self._messages.append(message.model_dump(exclude_none=True))
                self._pending_tool_calls = []
                return {"stop": True, "flag": None, "text": text,
                        "finish_reason": last_finish_reason}

            # Empty/malformed completion: log the finish_reason and retry WITHOUT
            # appending the empty assistant message (that would corrupt history).
            print(
                f"[openai_adapter] empty/uncallable completion "
                f"(finish_reason={last_finish_reason!r}, tool_calls={len(tool_calls)}, "
                f"text={len(text)} chars); retry {attempt + 1}/{self._max_empty_retries}",
                file=sys.stderr, flush=True,
            )

        raise RuntimeError(
            f"model returned {self._max_empty_retries + 1} consecutive empty/uncallable "
            f"completions (last finish_reason={last_finish_reason!r}) -- no usable tool call "
            f"and no text; an endpoint/model-layer failure, not an agent stop"
        )
