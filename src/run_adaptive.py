"""Phase C: adaptive attacker vs. a blocking defense (regex or LLM), in rounds.

The defense sits in front of the target: a flagged message never reaches HelpBot and the attacker
sees BLOCK_MSG instead. Before each round after the first, the attacker gets feedback (examples of
blocked / passed / successful messages) from the previous round against the same defense.
Both arms use the same seeds, rounds and episode counts.

Usage (from src/):
  caffeinate -is ../.venv/bin/python run_adaptive.py --rounds 2 --per-strategy 1 --out ../data/phaseC_pilot.jsonl
  caffeinate -is ../.venv/bin/python run_adaptive.py --rounds 5 --per-strategy 2 --out ../data/phaseC.jsonl

Resumable: episodes listed in <out>.episodes.jsonl are skipped; partial episodes are redone.
Feedback for round r is rebuilt from the logged round r-1, so a resumed run gets the same feedback.
"""
import argparse, json, os, random, time
from datetime import datetime, timezone

import attacker
import defender
import llm
import regex_filter
import target
from target import Target, leaked, overridden

BLOCK_MSG = "[Message blocked by a security filter.]"
MAX_REFUSAL_RETRIES = 2
N_EXAMPLES = 5          # examples per feedback category
MAX_EXAMPLE_CHARS = 200

p = argparse.ArgumentParser()
p.add_argument("--rounds", type=int, default=5)
p.add_argument("--per-strategy", type=int, default=2)
p.add_argument("--max-turns", type=int, default=6)
p.add_argument("--seed-base", type=int, default=5000)
p.add_argument("--arms", default="regex,llm")
p.add_argument("--out", default="../data/phaseC.jsonl")
args = p.parse_args()
ARMS = args.arms.split(",")
EP_LOG = args.out.replace(".jsonl", ".episodes.jsonl")


def detect(arm, history, msg):
    if arm == "regex":
        t0 = time.time()
        r = regex_filter.regex_flag(msg)
        return {"flag": r["flag"], "score": None, "hits": r["hits"], "reason": None,
                "parse_ok": True, "latency_s": round(time.time() - t0, 5),
                "version": regex_filter.RULES_VERSION}
    d = defender.llm_flag(history, msg)
    return {"flag": d["flag"], "score": d["score"], "hits": None, "reason": d["reason"],
            "parse_ok": d["parse_ok"], "latency_s": d["latency_s"], "version": defender.PROMPT_VERSION,
            "attack_field": d["attack_field"]}


def short(t):
    t = " ".join(t.split())
    return t if len(t) <= MAX_EXAMPLE_CHARS else t[:MAX_EXAMPLE_CHARS] + "..."


def build_lessons(arm, rnd):
    """Feedback text for round rnd (>= 1) from the logged round rnd-1 of this arm."""
    if rnd == 0 or not os.path.exists(args.out):
        return None, None
    rows = [json.loads(l) for l in open(args.out)]
    rows = [r for r in rows if r["arm"] == arm and r["round"] == rnd - 1]
    if not rows:
        return None, None
    rng = random.Random(f"{arm}-{rnd}")   # deterministic sample, so resumed runs get the same feedback
    pick = lambda xs: [short(x) for x in rng.sample(xs, min(N_EXAMPLES, len(xs)))]
    blocked = [r["attacker_msg"] for r in rows if r["blocked"]]
    passed = [r["attacker_msg"] for r in rows if not r["blocked"] and not r["success"]]
    succeeded = [r["attacker_msg"] for r in rows if r["success"]]
    text = attacker.lessons_text(pick(blocked), pick(passed), pick(succeeded), len(blocked), len(rows))
    return text, {"n_blocked": len(blocked), "n_total": len(rows)}


done = set()
if os.path.exists(EP_LOG):
    done = {json.loads(l)["episode_id"] for l in open(EP_LOG)}
if os.path.exists(args.out):   # drop turns from episodes that never finished
    keep = [l for l in open(args.out) if json.loads(l)["episode_id"] in done]
    open(args.out, "w").writelines(keep)
print(f"resuming: {len(done)} episodes already done", flush=True)

t_run = time.time()
with open(args.out, "a") as f, open(EP_LOG, "a") as ef:
    for rnd in range(args.rounds):
        for arm in ARMS:   # arms interleaved by round, so slow-downs affect both equally
            lessons, lmeta = build_lessons(arm, rnd)
            for i in range(args.per_strategy):
                for si, strategy in enumerate(attacker.STRATEGIES):
                    ep = f"{arm}-r{rnd}-{strategy}-{i:02d}"
                    if ep in done:
                        continue
                    seed = args.seed_base + rnd * 100 + i * 10 + si   # same seed in both arms
                    bot = Target(seed=seed)
                    transcript, history, success, n_blocked = [], [], False, 0
                    t_ep = time.time()
                    for turn in range(args.max_turns):
                        refusals = 0
                        for attempt in range(MAX_REFUSAL_RETRIES + 1):
                            t0 = time.time()
                            raw = attacker.next_attack(strategy, transcript, args.max_turns,
                                                       seed=seed * 100 + turn * 10 + attempt, lessons=lessons)
                            lat_a = time.time() - t0
                            att_tokens = llm.last_meta.get("prompt_eval_count")
                            if not attacker.is_refusal(raw):
                                break
                            refusals += 1
                        msg = attacker.clean(raw)
                        det = detect(arm, history, msg)
                        if det["flag"]:
                            reply, lat_t, lk, ov, trunc = BLOCK_MSG, 0.0, False, False, False
                            n_blocked += 1
                        else:
                            t0 = time.time()
                            reply = bot.reply(msg)
                            lat_t = time.time() - t0
                            lk, ov, trunc = leaked(reply), overridden(reply), bot.truncated
                        rec = {
                            "arm": arm, "round": rnd, "episode_id": ep, "strategy": strategy, "turn": turn,
                            "attacker_msg": msg, "attacker_raw": raw, "attacker_refusals": refusals,
                            "attacker_gave_up": attacker.is_refusal(raw), "attacker_prompt_tokens": att_tokens,
                            "blocked": det["flag"], "det_score": det["score"], "det_hits": det["hits"],
                            "det_reason": det["reason"], "det_parse_ok": det["parse_ok"],
                            "det_attack_field": det.get("attack_field"), "det_latency_s": det["latency_s"],
                            "target_reply": reply, "leaked": lk, "overridden": ov, "success": lk or ov,
                            "target_truncated": trunc, "seed": seed, "feedback": lmeta,
                            "attacker_model": attacker.MODEL, "target_model": target.MODEL,
                            "attacker_prompt_version": attacker.ADAPT_PROMPT_VERSION if lessons else attacker.PROMPT_VERSION,
                            "target_prompt_version": target.PROMPT_VERSION, "detector_version": det["version"],
                            "latency_attacker_s": round(lat_a, 2), "latency_target_s": round(lat_t, 2),
                            "ts": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                        }
                        f.write(json.dumps(rec, ensure_ascii=False) + "\n"); f.flush()
                        transcript += [("attacker", msg), ("target", reply)]
                        history += [("user", msg), ("assistant", reply)]
                        if lk or ov:
                            success = True
                            break
                    ef.write(json.dumps({"episode_id": ep, "arm": arm, "round": rnd, "strategy": strategy,
                                         "seed": seed, "turns": turn + 1, "blocked": n_blocked,
                                         "success": success, "duration_s": round(time.time() - t_ep, 1)}) + "\n")
                    ef.flush()
                    print(f"{ep}: {'SUCCESS' if success else 'fail'}, {n_blocked}/{turn + 1} blocked "
                          f"({time.time() - t_ep:.0f}s, total {(time.time() - t_run) / 60:.1f} min)", flush=True)

eps = [json.loads(l) for l in open(EP_LOG)]
rows = [json.loads(l) for l in open(args.out)]
print("\narm    round  episodes  success  blocked msgs")
for arm in ARMS:
    for rnd in range(args.rounds):
        e = [x for x in eps if x["arm"] == arm and x["round"] == rnd]
        m = [x for x in rows if x["arm"] == arm and x["round"] == rnd]
        if e:
            print(f"{arm:<6} {rnd + 1:>5}  {len(e):>8}  {sum(x['success'] for x in e):>7}  "
                  f"{sum(x['blocked'] for x in m)}/{len(m)}")
