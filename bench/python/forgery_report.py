"""forgery_report.py -- summary of the forgery cells (FX* exogenous alpha sweep, FA attack-triggered).

For each cell and scope/format it reports P_chain with a Wilson interval and the miss causes.
For the exogenous cells it also checks the necessary condition that the model gives
under the gw+dst scope: the steps before the CAN request are seen only by gw, so a
trial can succeed only if none of the attacker's gw reports was replaced by a forgery.
A success in a trial that violates this condition would contradict the model.

  python forgery_report.py ../runs [--json out.json]
"""
from __future__ import annotations

import argparse
import glob
import json
import os
from collections import Counter

import analyze as A
import bench_proto as bp

EXO = [("FX100", 1.00), ("FX075", 0.75), ("FX050", 0.50), ("FX025", 0.25), ("FX000", 0.00)]


def trials(cell_dir):
    return [json.load(open(f)) for f in sorted(glob.glob(os.path.join(cell_dir, "trial_*.json")))]


def score(cell_dir, rep, scope):
    mask = bp.SCOPES[scope]
    rows = []
    for t in trials(cell_dir):
        res, ref, evs, _ = A.score_trial(t, rep, t["dump"]["ctl"]["deadline_ms"], mask)
        if not ref["malicious"]:
            continue
        gw_ref = [e for e in evs if e["obs"] == bp.OBS_GW and not e.get("forged")
                  and any(e["seq"] in v for v in ref["stages"].values())]
        rows.append({"ok": res["complete"], "mech": (res.get("mechanism") or "").split(":")[0],
                     "gw_all_genuine": all(e["dlv"] != "forged_out" for e in gw_ref)})
    return rows


def summarize(rows):
    n, k = len(rows), sum(r["ok"] for r in rows)
    _, lo, hi = A.wilson(k, n)
    return {"n": n, "k": k, "p": k / n if n else None, "ci": [lo, hi],
            "mech": dict(Counter(r["mech"] for r in rows if not r["ok"])),
            "cond_holds": sum(r["gw_all_genuine"] for r in rows),
            "success_despite_forged_gw": sum(r["ok"] and not r["gw_all_genuine"] for r in rows)}


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("runs")
    ap.add_argument("--json", default=None)
    a = ap.parse_args()
    out = {"exo": {}, "attack": {}}
    print("Exogenous forgery of the gw observer (alpha = probability a window is genuine)")
    print(f"{'cell':6s} {'alpha':>5s}  {'scope':7s} {'P_chain (F3)':>22s}  gw genuine  violations  misses")
    for cell, alpha in EXO:
        d = os.path.join(a.runs, cell)
        if not os.path.isdir(d):
            continue
        out["exo"][cell] = {"alpha": alpha}
        for scope in ("gw+dst", "all", "src+dst"):
            s = summarize(score(d, "F3", scope))
            out["exo"][cell][scope] = s
            print(f"{cell:6s} {alpha:5.2f}  {scope:7s} {s['k']:2d}/{s['n']:2d} = {s['p']:.2f} [{s['ci'][0]:.2f}, {s['ci'][1]:.2f}]"
                  f"  {s['cond_holds']:2d}/{s['n']:2d}      {s['success_despite_forged_gw']}           {s['mech']}")
    d = os.path.join(a.runs, "FA")
    if os.path.isdir(d):
        print("\nAttack-triggered forgery of the gw observer (the write is reported as allowed)")
        print(f"{'scope':7s} " + "  ".join(f"{r:>16s}" for r in ("F1", "F2", "F3", "F4")))
        for scope in ("all", "gw+dst", "src+dst"):
            cells = []
            for rep in ("F1", "F2", "F3", "F4"):
                s = summarize(score(d, rep, scope))
                out["attack"].setdefault(scope, {})[rep] = s
                cells.append(f"{s['k']:2d}/{s['n']:2d} {list(s['mech'])[:1] or ['-']}")
            print(f"{scope:7s} " + "  ".join(f"{c:>16s}" for c in cells))
    if a.json:
        json.dump(out, open(a.json, "w"), indent=1)


if __name__ == "__main__":
    main()
