"""Optional real-LLM adapter using the Anthropic Messages API tool-use loop.

Requires `pip install anthropic` and an API key in the environment variable
named by agent.json's `api_key_env` (default ANTHROPIC_API_KEY). This is the
adapter the requester runs AFTER this build session to execute the real
16-rollout cohort -- it was not exercised against a live model inside the
session that authored it (no model credentials available there). See README.md.
"""
from __future__ import annotations

import os

TOOL_SCHEMA = {
    "name": "http",
    "description": (
        "Issue exactly one HTTP request to the Evidence Mill target and return its "
        "response. Call this AT MOST ONCE per turn -- one http() call consumes one of "
        "your limited turns. If your response contains more than one tool call, only "
        "the first is executed; the rest are skipped."
    ),
    "input_schema": {
        "type": "object",
        "properties": {
            "method": {"type": "string", "enum": ["GET", "POST", "PATCH"]},
            "path": {"type": "string", "description": "e.g. /catalog or /claims/abc123/verify"},
            "json": {"type": "object", "description": "JSON request body; omit for GET"},
        },
        "required": ["method", "path"],
    },
}

_SKIPPED_RESULT = (
    "not executed: only the first http() call in a single response is run; each "
    "response may issue at most one tool call."
)


class AnthropicAdapter:
    def __init__(self, config: dict, max_turns: int):
        import anthropic  # optional dependency, only needed for a real cohort run

        api_key = os.environ.get(config.get("api_key_env", "ANTHROPIC_API_KEY"))
        self._client = anthropic.Anthropic(api_key=api_key)
        self._model = config["model"]
        self._max_tokens = config.get("max_tokens", 1024)
        # The installed anthropic SDK's Messages.create() has no `temperature`
        # parameter at all in this API generation (sampling control moved to
        # `output_config.effort`, a reasoning-effort level, not a temperature
        # knob) -- confirmed by inspecting the actual installed signature, not
        # assumed. agent.json's `temperature` field is therefore NOT forwarded;
        # `effort` (optional) is, if present.
        self._effort = config.get("effort")
        self._messages: list[dict] = []
        self._system = ""
        # ALL tool_use ids from the most recent assistant turn. The Anthropic API
        # requires a tool_result for every tool_use block a response contained, or
        # the next messages.create call is rejected -- even though this harness
        # only ever actually executes the first one (one http() call == one turn).
        self._pending_tool_ids: list[str] = []
        self._started = False

    def next_action(self, transcript: list[dict]) -> dict:
        if not self._started:
            self._started = True
            self._system = transcript[0]["content"]
            first_user = transcript[1]["content"]
            self._messages.append({"role": "user", "content": first_user})
        else:
            last_result = transcript[-1]["result"]
            tool_results = [{"type": "tool_result", "tool_use_id": self._pending_tool_ids[0],
                              "content": str(last_result)}]
            for skipped_id in self._pending_tool_ids[1:]:
                tool_results.append({"type": "tool_result", "tool_use_id": skipped_id,
                                      "content": _SKIPPED_RESULT, "is_error": True})
            self._messages.append({"role": "user", "content": tool_results})

        kwargs: dict = {}
        if self._effort:
            kwargs["output_config"] = {"effort": self._effort}
        response = self._client.messages.create(
            model=self._model,
            max_tokens=self._max_tokens,
            system=self._system,
            tools=[TOOL_SCHEMA],
            messages=self._messages,
            **kwargs,
        )
        self._messages.append({"role": "assistant", "content": response.content})

        tool_use_blocks = [b for b in response.content if b.type == "tool_use" and b.name == "http"]
        if not tool_use_blocks:
            self._pending_tool_ids = []
            return {"stop": True, "flag": None}

        self._pending_tool_ids = [b.id for b in tool_use_blocks]
        first = tool_use_blocks[0]
        return {"method": first.input["method"], "path": first.input["path"], "json": first.input.get("json")}
