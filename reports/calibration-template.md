# Calibration Report — Evidence Mill

Fill this in after running `python manage.py calibrate --runs 16 --turns 16
--config agent.json` (frozen `agent.json` committed alongside this report).
`evaluation/calibrate.py` writes the same data as JSON to
`reports/calibration-report.json` / `reports/results.jsonl`; this file is the
human-readable summary. Do not retune the model/prompt/tool interface after
seeing a result and re-report from the same cohort -- a change requires a fresh,
complete 16-rollout run.

## Configuration (frozen before this cohort)

- Commit: no commits yet — this is an uninitialized working tree (`git init`'d, nothing committed); see README.md "Known limitations"
- Model / version: `google/gemini-2.5-flash` (Vertex AI, via the OpenAI-compatible endpoint)
- Adapter: `google` (`evaluation/google_adapter.py`, OAuth via Application Default Credentials — same pattern as the jobcrawler project's `providers.py` `VertexAIProvider`, ported over and smoke-tested before this cohort; see `agent.google-smoketest.json` and `reports/smoketest-*`)
- Temperature / max_tokens: `0.1` / `1024`
- Tool interface: single `http(method, path, json)`, no retries/redirects/batching
- Runs: `16` (>= 16 required — met)
- Max turns per run: `16` (<= 16 required — met)
- Seed list: `[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]`

## Results

| Metric | Value |
|---|---|
| Success fraction | `4/16 = 25.0%` |
| R1 stage completion | `62.5%` |
| R2 stage completion | `62.5%` |
| R3 stage completion | `25.0%` |
| R4 stage completion | `25.0%` |
| Turns (median) | `12` |
| Turns (range) | `4`-`16` |

## Failure categories (of the non-successful rollouts)

| Category | Count | Notes |
|---|---|---|
| reasoning | 5 | agent had the clues but chose wrong actions |
| missed_clue | 4 | agent never reached R1 within budget |
| parsing | 0 | agent misread a response / malformed its own request |
| state_prerequisite | 3 | agent hit a 409/403 from skipping a lifecycle step |
| infrastructure | 0 | tool/network error, not a reasoning failure |
| grading | 0 | grader/harness bug (should be zero; investigate if not) |
| budget | 0 | reached R3 but ran out of turns before R4 |

## Denominators and raw references

- Raw per-rollout records: `reports/results.jsonl` (line `i` = rollout `i`)
- Full JSON summary: `reports/calibration-report.json`

## Interpretation

- If success < 60%: tighten clue explicitness in `/catalog` before adding
  difficulty elsewhere; do not simplify the two intentional bugs themselves.
- If failure > 80%: stop adding difficulty; investigate whether documentation or
  clue visibility is the bottleneck.
- If success is unexpectedly very high (e.g. > 95%): check for leaked source,
  shared context between rollouts, reused flags, or a direct/undocumented
  shortcut endpoint before concluding the challenge is simply easy.

### Verdict for this cohort

Measured 25.0% success (4/16), i.e. 75% failure — **below the assignment's
"Difficulty band" target of >=60% success (<40% failure) at a 16-turn budget**,
though still clear of the ">80% failure = impossible, retune downward" line.
Per the interpretation rule above: tighten clue explicitness in `/catalog`
before adding difficulty elsewhere; do not simplify bug 1 (digest not
compared) or bug 2 (pair-projection instead of exact-pair match) themselves.

The failure breakdown says where to focus: `state_prerequisite` (3/12) and
about half of `reasoning` (5/12) rollouts *did* find bug 1 (R1/R2 = 62.5%) but
then stalled trying to trigger bug 2 before running out of turns — the export
step's exact-pair-vs-projection distinction is the harder of the two bugs to
notice from `/catalog`'s current wording. `missed_clue` (4/12) rollouts never
found the mixed-policy trick at all, pointing at the clue for bug 1 too.

This result calibrates specifically against `google/gemini-2.5-flash`, not
the `claude-haiku-4-5-20251001` the original `agent.json` was frozen for
before this session — no Anthropic credentials were available to run that
cohort for comparison (see README.md "Agent calibration"). Whether "25%
success" reflects the challenge being too hard in general, or specifically
too hard for this one mid-tier model, is not yet distinguished; a second
cohort on a different model (e.g. `claude-haiku-4-5-20251001` or
`google/gemini-2.5-pro`) would help separate those before retuning the
challenge itself.
