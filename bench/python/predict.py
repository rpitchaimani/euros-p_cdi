"""predict.py -- does the model predict WHERE reconstruction must fail, on scenario
families it was not calibrated on?  (Failure-region framing: the paper's result is
a converse; the model predicts upper limits on success, not success itself.)

Per malicious complete-chain trial the script predicts P(success) from inputs that
are known WITHOUT looking at the outcome:
  * architecture: which observer classes can carry each stage (static map below)
    and the trial's observer scope;
  * processing: CPU share U, queue capacity Q, deadline D, background arrival
    rate (measured per trial from the window log), chain timing (reference), and
    the per-event IDS cost w calibrated on the calibration families only;
  * identifiability: how many writes in the trial produce indistinguishable
    destination evidence (same value, shared actuator message, no source byte;
    under F4 any concurrent writer), from the scenario configuration.

Models (each gives P(success) in [0, 1]):
  full        coverage AND processing AND identifiability (1/k for k candidates)
  coverage    observation coverage alone
  load        processing budget / queue load alone
  no_xzone    coverage AND processing, but stages treated as independent
              (no cross-zone linking requirement -> never sees ambiguity)

Protocol: `fit` on calibration families writes frozen parameters (JSON, with a
hash); `test` loads them and NEVER refits, then scores held-out families
(accuracy at 0.5, Brier score).  Report both files.

  python predict.py fit  --cells ../runs/C1 ../runs/C5 ... --families S1,S2,S3 --out params.json
  python predict.py test --cells ../runs/C2 ../runs/E4 ... --families S4,S7 --params params.json
"""
from __future__ import annotations

import argparse
import hashlib
import json
import math
import statistics as st
from collections import defaultdict

import analyze as A
import bench_proto as bp

# Which observers can carry evidence of each stage (architecture, not data).
STAGE_OBS = {
    1: {bp.OBS_SRC, bp.OBS_GW},        # discovery + routing activation
    2: {bp.OBS_SRC, bp.OBS_GW},        # unauthorised write (inferred at SRC, decided at GW)
    3: {bp.OBS_GW, bp.OBS_DST},        # forwarded across the zone boundary
    4: {bp.OBS_GW, bp.OBS_DST},        # target positive response
    5: {bp.OBS_DST},                   # impact message on the destination bus
}
TW_TICKS = bp.IDS_WINDOW_MS * A.TICKS_MS


def trial_inputs(t: dict, cell: dict, rep: str) -> dict:
    """Everything the predictors may use for one trial (no outcome fields)."""
    evs = A.events_of(dict(t, dump=dict(t["dump"], dlog=[
        bp.decode_event(dict(e, d=bytes.fromhex(e["d"]))) if "ip" not in e and "can_id" not in e else e
        for e in t["dump"]["dlog"]])))
    ref = A.reference(t, evs)
    wl = [w for w in t["dump"]["wlog"] if w["arrivals"] > 0]
    arr = st.mean(w["arrivals"] for w in wl) if wl else 0.0
    gt = t["gt"]
    # identifiability: candidates for the attacker's impact
    impact_src = cell.get("impact_src", "on") == "on"     # trial configuration
    vals = gt.get("values", {})
    writers = [s for s in gt["sessions"]]
    if rep == "F4":
        k = max(1, sum(1 for s in writers if s["role"] in ("malicious", "benign")
                       and gt["scenario"] in ("S4", "S5", "S7")))
    elif gt["scenario"] == "S7" and not impact_src and vals.get("attacker") == vals.get("benign"):
        k = 2                     # two ECUs, same value, frame does not name its source
    else:
        k = 1                     # FIFO per ECU + value or source byte resolve the link
    return {"scenario": gt["scenario"], "scope": cell["obs_mask"], "u_ppm": cell["u_ppm"],
            "q_cap": cell["q_cap"], "deadline_ms": cell.get("deadline_ms", 1000),
            "arrivals_per_window": arr, "t_end_ticks": ref.get("t_end", 0), "k": k,
            "stages": sorted(ref["stages"]), "expected": gt["expected_stages"]}


def p_coverage(x) -> float:
    need = range(1, x["expected"] + 1)
    return 1.0 if all(STAGE_OBS[s] & {o for o in (1, 2, 3) if x["scope"] & (1 << o)} for s in need) else 0.0


def p_processing(x, w_ticks: float) -> float:
    """Fluid queue: arrivals a/window, service c = U*T_w/w per window.  The last
    chain event (at t_end) waits for the backlog built up since START."""
    c = (min(x["u_ppm"], 1_000_000) * TW_TICKS / 1e6) / w_ticks if w_ticks > 0 else float("inf")
    a = x["arrivals_per_window"]
    if a <= c:
        return 1.0
    windows = x["t_end_ticks"] / TW_TICKS
    backlog = (a - c) * windows
    if backlog >= x["q_cap"]:
        return 0.0                                 # admission drops before the chain ends
    wait_windows = backlog / c if c > 0 else float("inf")
    return 1.0 if wait_windows * bp.IDS_WINDOW_MS <= x["deadline_ms"] else 0.0


def p_load(x, w_ticks: float, theta: float) -> float:
    c = (min(x["u_ppm"], 1_000_000) * TW_TICKS / 1e6) / w_ticks if w_ticks > 0 else float("inf")
    m = min(1.0, c / x["arrivals_per_window"]) if x["arrivals_per_window"] else 1.0
    return 1.0 if m >= theta else 0.0


def predict_all(x, prm) -> dict:
    cov, proc = p_coverage(x), p_processing(x, prm["w_ticks"])
    return {"full": cov * proc / x["k"], "coverage": cov,
            "load": p_load(x, prm["w_ticks"], prm["theta_load"]), "no_xzone": cov * proc}


def collect(cells, families, rep):
    rows = []
    for c in cells:
        cell, trials = A.load_cell(c)
        for t in trials:
            res, ref, evs, avail = A.score_trial(t, rep, cell.get("deadline_ms", 1000), None)
            ing = A.ingress_check(t, evs)
            if A.validity(t, ref, ing):
                continue
            if res["scenario"] not in families or res["scenario"] not in ("S1", "S4", "S7"):
                continue
            x = trial_inputs(t, cell, rep)
            x["observed"] = 1.0 if res["complete"] else 0.0
            x["cell"] = cell["name"]
            x["busy"] = t["dump"]["ctl"]["c0_busy_ticks"]
            x["proc"] = t["dump"]["ctl"]["c0_proc"]
            rows.append(x)
    return rows


def cmd_fit(a):
    rows = collect(a.cells, set(a.families.split(",")) | {"S1"}, a.rep)
    cal = [r for r in rows if r["scenario"] in set(a.families.split(","))]
    if not cal:
        raise SystemExit("no calibration trials")
    busy = sum(r["busy"] for r in cal)
    proc = sum(r["proc"] for r in cal)
    w = busy / proc if proc else 0.0
    best = (None, -1.0)
    for theta in [i / 100 for i in range(1, 101)]:
        acc = st.mean(1.0 if (p_load(r, w, theta) >= 0.5) == (r["observed"] >= 0.5) else 0.0 for r in cal)
        if acc > best[1]:
            best = (theta, acc)
    prm = {"w_ticks": w, "w_us": w / A.TICKS_MS * 1000, "theta_load": best[0],
           "calib_families": a.families, "calib_cells": a.cells, "rep": a.rep, "n_calib": len(cal)}
    prm["hash"] = hashlib.sha256(json.dumps(prm, sort_keys=True).encode()).hexdigest()[:16]
    with open(a.out, "w") as f:
        json.dump(prm, f, indent=1)
    print(f"frozen parameters -> {a.out}: w = {prm['w_us']:.2f} us, theta_load = {prm['theta_load']}, "
          f"n = {len(cal)}, hash {prm['hash']}")


def cmd_test(a):
    with open(a.params) as f:
        prm = json.load(f)
    fam = set(a.families.split(","))
    overlap = fam & set(prm["calib_families"].split(","))
    if overlap:
        raise SystemExit(f"test families overlap calibration families: {sorted(overlap)}")
    rows = collect(a.cells, fam, prm["rep"])
    if not rows:
        raise SystemExit("no held-out trials")
    models = ["full", "coverage", "load", "no_xzone"]
    agg = defaultdict(lambda: {"acc": [], "brier": []})
    per_cond = defaultdict(lambda: defaultdict(list))
    for r in rows:
        p = predict_all(r, prm)
        cond = f"{r['cell']}/{r['scenario']}"
        per_cond[cond]["observed"].append(r["observed"])
        for m in models:
            agg[m]["acc"].append(1.0 if (p[m] >= 0.5) == (r["observed"] >= 0.5) else 0.0)
            agg[m]["brier"].append((p[m] - r["observed"]) ** 2)
            per_cond[cond][m].append(p[m])
    print(f"held-out families {sorted(fam)}, n = {len(rows)} trials, parameters {prm['hash']} "
          f"(calibrated on {prm['calib_families']}, never refitted)")
    print(f"{'model':10s} {'accuracy':>9s} {'Brier':>7s}")
    for m in models:
        print(f"{m:10s} {st.mean(agg[m]['acc']):9.3f} {st.mean(agg[m]['brier']):7.3f}")
    print("\nper condition: observed success rate vs. mean predicted P(success)")
    print(f"{'condition':34s} {'n':>3s} {'obs':>5s} " + " ".join(f"{m:>8s}" for m in models))
    for cond, d in sorted(per_cond.items()):
        print(f"{cond:34s} {len(d['observed']):3d} {st.mean(d['observed']):5.2f} " +
              " ".join(f"{st.mean(d[m]):8.2f}" for m in models))
    if a.json:
        with open(a.json, "w") as f:
            json.dump({"params": prm, "models": {m: {"accuracy": st.mean(agg[m]["acc"]),
                                                     "brier": st.mean(agg[m]["brier"])} for m in models},
                       "per_condition": {c: {k: st.mean(v) for k, v in d.items()} for c, d in per_cond.items()}},
                      f, indent=1)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    f = sub.add_parser("fit")
    f.add_argument("--cells", nargs="+", required=True)
    f.add_argument("--families", default="S1,S2,S3")
    f.add_argument("--rep", default="F3", choices=["F1", "F2", "F3", "F4"])
    f.add_argument("--out", default="params.json")
    f.set_defaults(func=cmd_fit)
    t = sub.add_parser("test")
    t.add_argument("--cells", nargs="+", required=True)
    t.add_argument("--families", default="S4,S7")
    t.add_argument("--params", default="params.json")
    t.add_argument("--json", default=None)
    t.set_defaults(func=cmd_test)
    ap.add_argument("--allow-dev", action="store_true", help="accept internal-loopback runs (debugging only)")
    a = ap.parse_args()
    A.ALLOW_DEV = a.allow_dev
    a.func(a)


if __name__ == "__main__":
    main()
