"""Phase C analysis: detection (block) rate and attack success per round and arm; trend comparison (H2).

Usage (from src/):  ../.venv/bin/python analyze_phaseC.py > ../logs/phaseC_results.txt
Also writes ../report/figures/phaseC_data.csv for the pgfplots figure.
"""
import json, math, random, re
from collections import defaultdict

R = [json.loads(l) for l in open("../data/phaseC.jsonl")]
E = [json.loads(l) for l in open("../data/phaseC.episodes.jsonl")]
ARMS = ["regex", "llm"]
ROUNDS = sorted({r["round"] for r in R})


def wilson(k, n, z=1.96):
    p = k / n; d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d
    h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return max(0, c - h), min(1, c + h)


def rate(k, n):
    lo, hi = wilson(k, n)
    return f"{k:>2}/{n:<2} {k / n:5.1%} [{lo:5.1%}-{hi:5.1%}]"


def slope(xs, ys):
    mx, my = sum(xs) / len(xs), sum(ys) / len(ys)
    return sum((x - mx) * (y - my) for x, y in zip(xs, ys)) / sum((x - mx) ** 2 for x in xs)


print("=== Block (detection) rate per round, message level ===")
csv = ["round,regex,regex_lo,regex_hi,llm,llm_lo,llm_hi"]
for rnd in ROUNDS:
    line, row = f"round {rnd + 1}", [str(rnd + 1)]
    for arm in ARMS:
        m = [r for r in R if r["arm"] == arm and r["round"] == rnd]
        k = sum(r["blocked"] for r in m); lo, hi = wilson(k, len(m))
        line += f"   {arm} {rate(k, len(m))}"
        row += [f"{100 * k / len(m):.1f}", f"{100 * lo:.1f}", f"{100 * hi:.1f}"]
    print(line); csv.append(",".join(row))
open("../report/figures/phaseC_data.csv", "w").write("\n".join(csv) + "\n")

print("\n=== Attack success per round (episodes) ===")
for rnd in ROUNDS:
    print(f"round {rnd + 1}   " + "   ".join(
        f"{arm} {sum(e['success'] for e in E if e['arm'] == arm and e['round'] == rnd)}/8" for arm in ARMS))
for arm in ARMS:
    e = [x for x in E if x["arm"] == arm]
    print(f"total {arm}: {rate(sum(x['success'] for x in e), len(e))}")

print("\n=== Round 1 vs. rounds 2-5 (block rate) ===")
for arm in ARMS:
    a = [r["blocked"] for r in R if r["arm"] == arm and r["round"] == 0]
    b = [r["blocked"] for r in R if r["arm"] == arm and r["round"] > 0]
    print(f"{arm:<6} round 1 {rate(sum(a), len(a))}   rounds 2-5 {rate(sum(b), len(b))}   "
          f"drop {100 * (sum(a) / len(a) - sum(b) / len(b)):.1f} points")

# Trend: least-squares slope of the per-message block indicator on round, per arm.
# CI by bootstrap over episodes (messages in one episode are not independent), stratified by round.
print("\n=== Trend (H2): slope of block rate per round, percentage points ===")
eps = defaultdict(list)
for r in R:
    eps[(r["arm"], r["round"], r["episode_id"])].append(r["blocked"])


def arm_slope(arm, rng=None):
    xs, ys = [], []
    for rnd in ROUNDS:
        keys = [k for k in eps if k[0] == arm and k[1] == rnd]
        if rng:
            keys = [rng.choice(keys) for _ in keys]
        for k in keys:
            xs += [rnd + 1] * len(eps[k]); ys += [int(b) for b in eps[k]]
    return 100 * slope(xs, ys)


rng = random.Random(0)
obs = {a: arm_slope(a) for a in ARMS}
boot = {a: [] for a in ARMS}; diff = []
for _ in range(5000):
    s = {a: arm_slope(a, rng) for a in ARMS}
    for a in ARMS:
        boot[a].append(s[a])
    diff.append(s["regex"] - s["llm"])
ci = lambda xs: (sorted(xs)[int(0.025 * len(xs))], sorted(xs)[int(0.975 * len(xs))])
for a in ARMS:
    lo, hi = ci(boot[a]); print(f"{a:<6} slope {obs[a]:+.1f} pp/round  95% CI [{lo:+.1f}, {hi:+.1f}]")
lo, hi = ci(diff)
print(f"regex - llm: {obs['regex'] - obs['llm']:+.1f} pp/round  95% CI [{lo:+.1f}, {hi:+.1f}]  "
      f"(bootstrap share of draws with regex slope >= llm slope: {sum(d >= 0 for d in diff) / len(diff):.3f})")

print("\n=== Block rate by turn position (all rounds) ===")
for arm in ARMS:
    print(f"{arm:<6} " + "  ".join(
        f"t{t + 1} {sum(r['blocked'] for r in R if r['arm'] == arm and r['turn'] == t)}/"
        f"{sum(1 for r in R if r['arm'] == arm and r['turn'] == t)}" for t in range(6)))

print("\n=== How the attacker adapts: share of messages containing trigger words, per round ===")
WORDS = {"passphrase/password": r"pass ?phrase|password", "instructions": r"instruction",
         "secret": r"secret", "admin": r"admin", "mode": r"\bmode\b", "ignore/disregard": r"ignore|disregard|forget"}
for arm in ARMS:
    print(f"-- {arm}")
    for w, p in WORDS.items():
        rx = re.compile(p, re.I)
        print(f"   {w:<20} " + "  ".join(
            f"r{rnd + 1} {sum(bool(rx.search(r['attacker_msg'])) for r in R if r['arm'] == arm and r['round'] == rnd):>2}"
            for rnd in ROUNDS))

print("\n=== Regex arm: rule hits per round ===")
hits = defaultdict(lambda: [0] * len(ROUNDS))
for r in R:
    if r["arm"] == "regex":
        for h in r["det_hits"] or []:
            hits[h][r["round"]] += 1
for h, c in sorted(hits.items(), key=lambda x: -sum(x[1])):
    print(f"   {h:<18} " + "  ".join(f"r{i + 1} {v:>2}" for i, v in enumerate(c)))

print("\n=== Successful episodes ===")
for e in E:
    if e["success"]:
        m = [r for r in R if r["episode_id"] == e["episode_id"]]
        print(f"{e['episode_id']} turns {e['turns']} blocked {e['blocked']}: {m[-1]['attacker_msg'][:160]!r}")

print("\n=== Data quality ===")
L = [r for r in R if r["arm"] == "llm"]
print(f"messages {len(R)}; parse failures {sum(not r['det_parse_ok'] for r in R)}; "
      f"LLM verdict/score mismatches {sum(r['det_parse_ok'] and bool(r['det_attack_field']) != r['blocked'] for r in L)}/{len(L)}; "
      f"attacker refusals {sum(r['attacker_refusals'] for r in R)}; truncated {sum(r['target_truncated'] for r in R)}; "
      f"max attacker prompt tokens {max(r['attacker_prompt_tokens'] or 0 for r in R)}")
lat = [r["det_latency_s"] for r in L]
print(f"LLM detector latency mean {sum(lat) / len(lat):.1f}s; run {R[0]['ts']} -> {R[-1]['ts']}")
