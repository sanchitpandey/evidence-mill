"""Read reports/results.jsonl into something you can actually inspect.

    python view_trajectory.py <results.jsonl>              # summary of all rollouts
    python view_trajectory.py <results.jsonl> 6            # full trace of rollout 6
    python view_trajectory.py <results.jsonl> 6 --say      # + the model's own reasoning text
    python view_trajectory.py <results.jsonl> --failures   # every unsuccessful rollout
"""
import argparse, json, sys

OK, BAD = "ok", "--"  # ASCII only: the default Windows console codepage cannot encode check marks.


def load(path):
    with open(path, encoding="utf-8") as f:
        return [json.loads(line) for line in f if line.strip()]


def summary(rows):
    n = len(rows)
    wins = sum(r["success"] for r in rows)
    print(f"{wins}/{n} solved ({wins / n:.0%})\n")
    stages = sorted({s for r in rows for s in r["stages_reached"]})
    for s in stages:
        hit = sum(s in r["stages_reached"] for r in rows)
        print(f"  {s}: {hit}/{n} ({hit / n:.0%})")
    print(f"\n{'run':>4} {'ok':>3} {'score':>6} {'turns':>6} {'left':>5}  {'stages':<18} failure mode")
    print("  " + "-" * 86)
    for r in sorted(rows, key=lambda r: r["run"]):
        left = 16 - r["turns_used"]
        print(f"{r['run']:>4} {OK if r['success'] else BAD:>3} {r['score']:>6} "
              f"{r['turns_used']:>6} {left:>5}  {','.join(r['stages_reached']) or '-':<18} "
              f"{r.get('failure_mode') or ''}")
    print("\nInspect one with:  python view_trajectory.py <file> <run>")


def trace(r, show_text):
    print(f"=== rollout {r['run']} | {'SOLVED' if r['success'] else 'FAILED'} | score={r['score']} "
          f"| turns={r['turns_used']}/16 | stages={','.join(r['stages_reached']) or 'none'}")
    if r.get("failure_mode"):
        print(f"    failure mode : {r['failure_mode']}")
    if r.get("behavior_tags"):
        print(f"    behavior tags: {', '.join(r['behavior_tags'])}")
    print(f"    furthest bug : {r.get('furthest_bug')}")
    for k in ("episode_seed", "model_seed", "seed_supported", "system_fingerprints"):
        if r.get(k) not in (None, [], False):
            print(f"    {k:<13}: {r[k]}")
    print()
    turn = 0
    for e in r["transcript"]:
        if e.get("stop"):
            print(f"  [STOP] final answer: {(e.get('assistant_text') or '').strip()[:300]!r}")
            continue
        if "action" not in e:
            if e.get("error"):
                print(f"  [ERROR] {e['error']}")
            continue
        turn += 1
        a, res = e["action"], e["result"]
        body = res["body"]
        body_s = json.dumps(body) if not isinstance(body, str) else body
        flag = "  <-- REFUSED" if e.get("agent_error") else ""
        req = f" {json.dumps(a['json'])}" if a.get("json") else ""
        print(f"  {turn:>2}. {a['method']:<5} {a['path']}{req}")
        print(f"      -> {res['status']} {body_s[:220]}{flag}")
        if show_text and (e.get("assistant_text") or "").strip():
            print(f"      model: {e['assistant_text'].strip()[:400]}")
    print()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("path")
    ap.add_argument("run", nargs="?", type=int)
    ap.add_argument("--say", action="store_true", help="show the model's own text each turn")
    ap.add_argument("--failures", action="store_true", help="trace every unsuccessful rollout")
    args = ap.parse_args()

    rows = load(args.path)
    if args.failures:
        for r in rows:
            if not r["success"]:
                trace(r, args.say)
    elif args.run is not None:
        match = [r for r in rows if r["run"] == args.run]
        if not match:
            sys.exit(f"no rollout {args.run}; have {[r['run'] for r in rows]}")
        trace(match[0], args.say)
    else:
        summary(rows)


if __name__ == "__main__":
    main()
