"""Week 3 sanity check: run both detectors over the hand-written dev set (not the test data).

Usage (from src/):  ../.venv/bin/python run_dev_check.py [--no-llm]
"""
import json, sys
from datetime import datetime, timezone

import importlib.util
import regex_filter

use_llm = "--no-llm" not in sys.argv
if "--defender" in sys.argv:   # e.g. --defender ../logs/defender-v1_frozen_20261025.py
    spec = importlib.util.spec_from_file_location("defender", sys.argv[sys.argv.index("--defender") + 1])
    defender = importlib.util.module_from_spec(spec); spec.loader.exec_module(defender)
else:
    import defender
items = json.load(open("../data/dev_set.json"))
out = open(f"../logs/dev_check_{defender.PROMPT_VERSION}_{regex_filter.RULES_VERSION}_n{len(items)}.jsonl", "w")

rows = []
for it in items:
    r = regex_filter.regex_flag(it["msg"])
    rec = {"id": it["id"], "label": it["label"], "group": it.get("strategy") or it.get("kind"),
           "msg": it["msg"], "regex_flag": r["flag"], "regex_hits": r["hits"],
           "regex_version": regex_filter.RULES_VERSION,
           "ts": datetime.now(timezone.utc).isoformat(timespec="seconds")}
    if use_llm:
        d = defender.llm_flag([tuple(h) for h in it["history"]], it["msg"])
        rec.update({f"llm_{k}": v for k, v in d.items()},
                   llm_model=defender.MODEL, llm_version=defender.PROMPT_VERSION)
    out.write(json.dumps(rec, ensure_ascii=False) + "\n"); out.flush()
    rows.append(rec)
    llm_s = f" llm={rec['llm_score']:>3} {'FLAG' if rec['llm_flag'] else '    '}" if use_llm else ""
    print(f"{it['id']} {it['label']:<6} regex={'FLAG' if r['flag'] else '    '}{llm_s}  {it['msg'][:60]}", flush=True)


def summary(det):
    att = [r for r in rows if r["label"] == "attack"]
    ben = [r for r in rows if r["label"] == "benign"]
    tp = sum(r[f"{det}_flag"] for r in att); fp = sum(r[f"{det}_flag"] for r in ben)
    print(f"{det:<5} recall {tp}/{len(att)}  false alarms {fp}/{len(ben)}", end="")
    for g in sorted({r["group"] for r in rows}):
        x = [r for r in rows if r["group"] == g]
        print(f" | {g} {sum(r[f'{det}_flag'] for r in x)}/{len(x)}", end="")
    print()


print()
summary("regex")
if use_llm:
    summary("llm")
    bad = sum(not r["llm_parse_ok"] for r in rows)
    mis = sum(r["llm_parse_ok"] and bool(r["llm_attack_field"]) != r["llm_flag"] for r in rows)
    print(f"verdict/score mismatches: {mis}")
    print(f"parse failures: {bad}; mean latency {sum(r['llm_latency_s'] for r in rows) / len(rows):.1f}s")
