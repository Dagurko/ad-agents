"""Phase B: replay every logged attack message and every benign message through both frozen detectors.

Each message is judged with the conversation history it originally had (earlier user messages and
target replies from Phase A or the benign check). One log line per (message, detector).

Usage (from src/):  caffeinate -is ../.venv/bin/python run_replay.py
Resumable: (msg_id, detector) pairs already in the output are skipped.
"""
import json, os, time
from datetime import datetime, timezone

import defender
import regex_filter

OUT = "../data/results_phaseB.jsonl"


def load_items():
    items = []
    for path, label in [("../data/attacks.jsonl", "attack"), ("../logs/benign_check.jsonl", "benign")]:
        rows = [json.loads(l) for l in open(path)]
        key = "episode_id" if label == "attack" else "id"
        rows.sort(key=lambda r: (r[key], r["turn"]))
        hist = {}
        for r in rows:
            conv = r[key]
            msg = r["attacker_msg"] if label == "attack" else r["msg"]
            reply = r["target_reply"] if label == "attack" else r["reply"]
            items.append({
                "msg_id": f"{conv}#{r['turn']}", "conv_id": conv, "turn": r["turn"], "label": label,
                "group": r["strategy"] if label == "attack" else r["kind"],
                "msg": msg, "history": list(hist.get(conv, [])),
                "leak_here": bool(r.get("success") or r.get("leaked")),   # this message's reply leaked
            })
            hist.setdefault(conv, []).extend([("user", msg), ("assistant", reply)])
    return items


items = load_items()
done = set()
if os.path.exists(OUT):
    done = {(json.loads(l)["msg_id"], json.loads(l)["detector"]) for l in open(OUT)}
print(f"{len(items)} messages; {len(done)} (message, detector) results already done", flush=True)

t_start, n_new = time.time(), 0
with open(OUT, "a") as f:
    for i, it in enumerate(items):
        base = {k: it[k] for k in ("msg_id", "conv_id", "turn", "label", "group", "leak_here")}
        ts = datetime.now(timezone.utc).isoformat(timespec="seconds")
        if (it["msg_id"], "regex") not in done:
            t0 = time.time()
            r = regex_filter.regex_flag(it["msg"])
            f.write(json.dumps({**base, "detector": "regex", "version": regex_filter.RULES_VERSION,
                                "flag": r["flag"], "score": None, "hits": r["hits"],
                                "latency_s": round(time.time() - t0, 5), "ts": ts}, ensure_ascii=False) + "\n")
        if (it["msg_id"], "llm") not in done:
            d = defender.llm_flag(it["history"], it["msg"])
            f.write(json.dumps({**base, "detector": "llm", "version": defender.PROMPT_VERSION,
                                "model": defender.MODEL, "flag": d["flag"], "score": d["score"],
                                "attack_field": d["attack_field"], "reason": d["reason"],
                                "parse_ok": d["parse_ok"], "latency_s": d["latency_s"], "ts": ts},
                               ensure_ascii=False) + "\n")
            n_new += 1
        f.flush()
        if n_new and (i + 1) % 25 == 0:
            el = time.time() - t_start
            print(f"{i + 1}/{len(items)}  {el / 60:.1f} min, ~{el / n_new * (len(items) - i - 1) / 60:.0f} min left", flush=True)
print("done", flush=True)
