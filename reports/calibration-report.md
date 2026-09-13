# Calibration Report — Evidence Mill

Two independent 16-rollout cohorts were run against this environment, with the
same model, the same system prompt and the same 16-turn budget. Both returned
12/16. The primary cohort is seeded; the second was run without seeding and is
kept as a genuine replication rather than discarded.

## Configuration

- Environment: the environment in this repository, unchanged between cohorts
- Agent: `gpt-5.4-mini` through the OpenAI adapter, configured by `agent.json`
- Rollouts: 16 per cohort, each against a freshly reset episode
- Budget: at most 16 HTTP tool calls per rollout
- Interface: one confined `http(method, path, json)` call per turn
- Grading: SQLite lineage plus HTTP responses observed by the trusted harness
- Reproducibility (primary cohort): `seed_base = 20260913`; rollout *i* ran at
  `episode_seed = model_seed = seed_base + i`
- Raw trajectories: `results.jsonl`; aggregate: `calibration-report.json`
- Replication cohort, verbatim: `cohort-2026-09-13-unseeded/`

Each rollout's recorded system prompt contains the shipped `PLAYER.md` verbatim,
and the recorded `/catalog` responses match the shipped response shape, so both
cohorts demonstrably ran against the environment as submitted.

## Results

| Metric | Primary | Replication | Pooled |
|---|---:|---:|---:|
| Successful rollouts | 12/16 = 75.0% | 12/16 = 75.0% | **24/32 = 75.0%** |
| 95% CI (Wilson) | [50.5%, 89.8%] | [50.5%, 89.8%] | **[57.9%, 86.8%]** |
| R0 — unapproved policy verified | 16/16 | 16/16 | 32/32 = 100% |
| R1 — productive certificate issued | 12/16 | 15/16 | 27/32 = 84.4% |
| R2 — unauthorized bytes materialized | 12/16 | 13/16 | 25/32 = 78.1% |
| R3 — exact flag observed | 12/16 | 12/16 | 24/32 = 75.0% |
| Turns | median 10, range 8–14 | median 10, range 8–16 | median 10 |
| Infrastructure errors | 0 | 0 | 0 |
| Refused tool calls | 0 | 0 | 0 |

No rollout solved in two or fewer turns; the minimum observed is 8, the reference
path length. The 25% failure rate is far from the 80% ceiling.

### What 32 rollouts can and cannot establish

At n=16 the interval reaches down to 50.5%, which cannot exclude a true rate below
the 60% gate. Pooling the two cohorts lifts the lower bound to 57.9%, and
P(X ≥ 24 | true rate = 0.60) = 0.057. That still does not put the bound strictly
above the gate — roughly 48 rollouts would — but the point estimate has now been
reproduced exactly on an independent cohort, which is stronger evidence than a
single interval of any width.

The cohorts are poolable: identical environment, model, system prompt and turn
budget, with nothing player-visible differing between them. Seeding selects which
samples are drawn, not the distribution they are drawn from.

## The two cohorts fail in different places

This is the most informative result, and the reason the earlier cohort was kept.

| Cohort | Where its four failures stalled |
|---|---|
| Primary | all four at **R0** — verified an unapproved claim, but never composed the productive `{(demo,read),(vault,stat)}` pair set |
| Replication | one at R0, two at **R1** (mixed certificate built, cross-pair export never attempted), one at **R2** (bytes materialized on the final turn, no call left to read them) |

Both discovery steps are genuine hurdles, and which one bites varies between
cohorts of the same model:

- **R0 → R1** — realising the claim must carry *both* base pairs, not only the
  interesting-looking one. The primary cohort's four failures all patched to
  `{(vault, stat)}` alone, verified it — defeating the trust-propagation defect —
  and were then holding a certificate that could never authorize a read.
- **R1 → R2** — realising that a certificate holding `(demo, read)` and
  `(vault, stat)` will authorize `(vault, read)`. The replication cohort's
  failures stalled here.

A single cohort would have attributed the task's difficulty to whichever step
happened to bite that day.

## Where R0 earns its place

R0 credits any unapproved claim accepted as verified, without requiring the pair
set that can actually reach the flag. Five of the thirty-two rollouts stopped
exactly there: they defeated the trust-propagation defect and then chose a payload
that leads nowhere. Collapsing R0 into R1 would score all five identically to an
agent that achieved nothing, erasing the distinction between a real partial result
and no result.

R0 is nonetheless a floor rather than a gradient. All 32 rollouts reached it, so
it separates nothing among genuine attempts and contributes no signal beyond that
fairness property. The report states this rather than presenting a 100%-completion
stage as evidence of anything.

## Preparation decides the outcome; recovery is barely exercised

| First verified claim | Rollouts | Succeeded |
|---|---:|---:|
| Carries both `(demo, read)` and `(vault, stat)` | 26 | 24 |
| Carries a singleton, or the unchanged root pairs | 6 | 0 |

Every success held the productive certificate by turn 6. Of the eight failures,
seven stopped voluntarily with turns remaining — but only three of those had
enough turns left to still reach the flag, so the budget does create real dead
ends even though the service always permits a fresh claim. The clearest case of
simple persistence failure is replication run 14: it retrieved metadata, stopped
at eight calls, and left the winning two-call continuation on the table.

This is a property of the task worth naming: it measures clean preparation well
and recovery hardly at all. The `scenario` support on `POST /internal/reset`
exists to close that gap, starting an agent in one of three states drawn from
these observed failures so recovery can be measured directly.

## Honest limits

- **Reward granularity is bimodal in the primary cohort.** Every rollout that
  reached R1 went on to the flag, so its observed scores were only 10 or 100. The
  stages remain individually observable and correctly ordered, and the replication
  cohort did produce intermediate scores — but one cohort of this model does not
  exercise the middle of the ladder. Whether that is a defect depends on the
  objective: if the goal is reliable flag recovery, equally successful strategies
  arguably should receive equal credit.
- **The turn budget binds almost nothing.** Seven of eight failures stopped with
  turns in hand. The failure rate reflects early abandonment at least as much as
  capability at 16 turns.
- **One model.** Both cohorts are `gpt-5.4-mini`. A variant of this environment
  carrying additional in-response hints was tried and discarded — Gemini-family
  models fell far below the band without them, OpenAI-family models solved above
  90% with them. The band is strongly model-dependent, and a second competent
  model is the highest-value experiment remaining.
- **These are graded inference rollouts, not a training experiment.** The harness
  scores each episode after the fact. Rollout data of this kind can expose a
  reward that points the wrong way, and was used for exactly that. It cannot show
  how a learner responds to the reward, and no claim of that sort is made here.

## Environment reliability

The scripted reference solution succeeded **16/16**, with 16 distinct flags,
taking 0.21 s minimum, 0.23 s median and 0.42 s maximum — far inside the
five-minute limit. A cold `--no-cache` build of both images took 29.9 s. The
target had no internet route and used 35.3 MiB. Reset isolation produced 3/3
unique episodes. The full test suite passes inside the tooling image: **90
passed**. Exact commands are in `README.md`; raw timings in
`reference-run-report.json`.

## Interpretation

The result sits in the intended intermediate band for this model: a competent
agent usually solves the task within the budget, and the unsuccessful trajectories
retain useful partial-reward signal spread across both discovery steps. The limits
above — interval width at n=32, early abandonment rather than budget exhaustion,
single-model coverage, and the absence of any training evidence — bound how far
that conclusion generalizes.
