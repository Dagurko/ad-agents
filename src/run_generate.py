"""Phase A: attack agent vs. undefended target. Logs every attacker message and target reply.

Usage (from src/):
  caffeinate -i ../.venv/bin/python run_generate.py --per-strategy 2 --out ../data/attacks_pilot.jsonl
  caffeinate -i ../.venv/bin/python run_generate.py --per-strategy 25 --out ../data/attacks.jsonl

Resumable: episodes listed in <out>.episodes.jsonl are skipped; partial episodes are redone.
"""
import argparse, json, os, time
from datetime import datetime, timezone

import attacker
import target
from target import Target, leaked, overridden

MAX_REFUSAL_RETRIES = 2

p = argparse.ArgumentParser()
p.add_argument("--per-strategy", type=int, default=25)
p.add_argument("--max-turns", type=int, default=6)
p.add_argument("--seed-base", type=int, default=1000)
p.add_argument("--out", default="../data/attacks.jsonl")
args = p.parse_args()

EP_LOG = args.out.replace(".jsonl", ".episodes.jsonl")

done = set()
if os.path.exists(EP_LOG):
    done = {json.loads(l)["episode_id"] for l in open(EP_LOG)}
if os.path.exists(args.out):   # drop turns from episodes that never finished
    keep = [l for l in open(args.out) if json.loads(l)["episode_id"] in done]
    open(args.out, "w").writelines(keep)
print(f"resuming: {len(done)} episodes already done")

# interleave strategies so a partial run stays balanced
plan = [(i, s) for i in range(args.per_strategy) for s in attacker.STRATEGIES]

with open(args.out, "a") as f, open(EP_LOG, "a") as ef:
    for i, strategy in plan:
        ep = f"{strategy}-{i:03d}"
        if ep in done:
            continue
        seed = args.seed_base + i * 10 + attacker.STRATEGIES.index(strategy)
        bot = Target(seed=seed)
        transcript, success, refusals_total = [], False, 0
        t_ep = time.time()
        for turn in range(args.max_turns):
            refusals = 0
            for attempt in range(MAX_REFUSAL_RETRIES + 1):
                t0 = time.time()
                raw = attacker.next_attack(strategy, transcript, args.max_turns, seed=seed * 100 + turn * 10 + attempt)
                lat_a = time.time() - t0
                if not attacker.is_refusal(raw):
                    break
                refusals += 1
            refusals_total += refusals
            msg = attacker.clean(raw)
            gave_up = attacker.is_refusal(raw)   # still refusing after all retries
            t0 = time.time()
            reply = bot.reply(msg)
            lat_t = time.time() - t0
            lk, ov = leaked(reply), overridden(reply)
            rec = {
                "episode_id": ep, "strategy": strategy, "turn": turn,
                "attacker_msg": msg, "attacker_raw": raw, "attacker_refusals": refusals,
                "attacker_gave_up": gave_up, "target_reply": reply,
                "leaked": lk, "overridden": ov, "success": lk or ov,
                "target_truncated": bot.truncated,
                "seed": seed, "attacker_model": attacker.MODEL, "target_model": target.MODEL,
                "attacker_prompt_version": attacker.PROMPT_VERSION,
                "target_prompt_version": target.PROMPT_VERSION,
                "latency_attacker_s": round(lat_a, 2), "latency_target_s": round(lat_t, 2),
                "ts": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            }
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")
            f.flush()
            transcript += [("attacker", msg), ("target", reply)]
            if lk or ov:
                success = True
                break
        ef.write(json.dumps({"episode_id": ep, "strategy": strategy, "seed": seed,
                             "turns": turn + 1, "success": success,
                             "attacker_refusals": refusals_total,
                             "duration_s": round(time.time() - t_ep, 1)}) + "\n")
        ef.flush()
        print(f"{ep}: {'SUCCESS' if success else 'fail'} after {turn + 1} turns "
              f"({refusals_total} attacker refusals, {time.time() - t_ep:.0f}s)", flush=True)

# summary
eps = [json.loads(l) for l in open(EP_LOG)]
print("\nstrategy          episodes  successes  rate")
for s in attacker.STRATEGIES:
    e = [x for x in eps if x["strategy"] == s]
    k = sum(x["success"] for x in e)
    print(f"{s:<17} {len(e):>8}  {k:>9}  {k / len(e) if e else 0:.0%}")
k = sum(x["success"] for x in eps)
print(f"{'TOTAL':<17} {len(eps):>8}  {k:>9}  {k / len(eps) if eps else 0:.0%}")
