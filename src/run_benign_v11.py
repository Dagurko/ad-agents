"""Secondary check: false-alarm rate of the fixed defender (defender-v1.1) on the 78 benign messages.

Same inputs and history as Phase B (logs/benign_check.jsonl), but only the LLM detector, frozen v1.1.
This evaluates an already-frozen version; nothing is tuned on it.
Usage (from src/):  caffeinate -is ../.venv/bin/python run_benign_v11.py
"""
import json, os
from datetime import datetime, timezone

import defender

assert defender.PROMPT_VERSION == "defender-v1.1", defender.PROMPT_VERSION
OUT = "../data/results_benign_defender-v1.1.jsonl"

rows = sorted((json.loads(l) for l in open("../logs/benign_check.jsonl")), key=lambda r: (r["id"], r["turn"]))
done = {json.loads(l)["msg_id"] for l in open(OUT)} if os.path.exists(OUT) else set()
hist = {}
with open(OUT, "a") as f:
    for r in rows:
        mid = f"{r['id']}#{r['turn']}"
        h = hist.setdefault(r["id"], [])
        if mid not in done:
            d = defender.llm_flag(list(h), r["msg"])
            f.write(json.dumps({"msg_id": mid, "conv_id": r["id"], "turn": r["turn"], "label": "benign",
                                "group": r["kind"], "detector": "llm", "version": defender.PROMPT_VERSION,
                                "model": defender.MODEL, "flag": d["flag"], "score": d["score"],
                                "attack_field": d["attack_field"], "reason": d["reason"], "parse_ok": d["parse_ok"],
                                "latency_s": d["latency_s"], "ts": datetime.now(timezone.utc).isoformat(timespec="seconds")},
                               ensure_ascii=False) + "\n")
            f.flush()
            print(f"{mid:<8} {d['score']:>3} {'FLAG' if d['flag'] else '    '} {r['msg'][:60]}", flush=True)
        h += [("user", r["msg"]), ("assistant", r["reply"])]

R = [json.loads(l) for l in open(OUT)]
for g in ["normal", "hard_negative"]:
    x = [r for r in R if r["group"] == g]
    print(f"{g:<14} false alarms {sum(r['flag'] for r in x)}/{len(x)}")
scripts = {r["conv_id"] for r in R}
print(f"total {sum(r['flag'] for r in R)}/{len(R)} messages; scripts flagged "
      f"{len({r['conv_id'] for r in R if r['flag']})}/{len(scripts)}; "
      f"mismatches {sum(r['parse_ok'] and bool(r['attack_field']) != r['flag'] for r in R)}; "
      f"parse failures {sum(not r['parse_ok'] for r in R)}")
