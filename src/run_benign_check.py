"""Sanity check: run every benign script through the undefended target and confirm no reply trips leaked()/overridden().
Resumable: scripts already fully logged in ../logs/benign_check.jsonl are skipped."""
import json, os, time
from target import Target, leaked, overridden, MODEL, PROMPT_VERSION

scripts = json.load(open("../data/benign_scripts.json"))
kinds = {}
for s in scripts:
    kinds[s["kind"]] = kinds.get(s["kind"], 0) + 1
n_msgs = sum(len(s["turns"]) for s in scripts)
print(f"{len(scripts)} scripts {kinds}, {n_msgs} messages")

LOG = "../logs/benign_check.jsonl"
done = {}
if os.path.exists(LOG):
    for line in open(LOG):
        r = json.loads(line)
        done[r["id"]] = done.get(r["id"], 0) + 1
complete = {s["id"] for s in scripts if done.get(s["id"]) == len(s["turns"])}
if done.keys() - complete:   # drop partially logged scripts so they rerun cleanly
    keep = [l for l in open(LOG) if json.loads(l)["id"] in complete]
    open(LOG, "w").writelines(keep)
print(f"resuming: {len(complete)} scripts already done")

bad = 0
with open(LOG, "a") as f:
    for s in scripts:
        if s["id"] in complete:
            continue
        bot = Target(seed=0)
        for turn, msg in enumerate(s["turns"]):
            t0 = time.time()
            out = bot.reply(msg)
            rec = {"id": s["id"], "kind": s["kind"], "turn": turn, "msg": msg, "reply": out,
                   "leaked": leaked(out), "overridden": overridden(out), "model": MODEL,
                   "prompt_version": PROMPT_VERSION, "latency_s": round(time.time() - t0, 2)}
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")
            f.flush()
            if rec["leaked"] or rec["overridden"]:
                bad += 1
                print(f"[!] {s['id']} turn {turn}: {out[:150]!r}")
        print(f"{s['id']} done", flush=True)
recs = [json.loads(l) for l in open(LOG)]
total_bad = sum(r["leaked"] or r["overridden"] for r in recs)
print(f"logged {len(recs)}/{n_msgs} messages; replies tripping a success check: {total_bad}")
