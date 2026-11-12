#!/usr/bin/env python3
"""hv_atm.py: narrative entropy H(V) from the Auto-ISAC ATM STIX bundle.

Usage:
    python hv_atm.py <path/to/atm_bundle.json>          # from the STIX bundle
    python hv_atm.py data/atm_v4.02_techniques.csv      # from the exported list
    python hv_atm.py --export <bundle.json> <out.csv>   # write the list

The running example is the Leaf chain of the paper's Figure 2:
    IA -> PES -> C2 -> LM -> IMP
mapped to ATM tactics. The tactic order is fixed, so tactic entropy is zero and
H(V) is the sum of log2 |A(tau)| over the chain. The uniform prior on this fixed
support is the highest entropy for these technique sets. Fixing the tactic order
(the DAG) lowers the entropy against a prior without the DAG, which favors the
detector. The zero-error bar of the paper is H itself (zero error forces
I(phi; W) = H(phi)), not H - 1.

Two technique sets are reported:
  full   : every active ATM technique listed under the tactic
  scoped : techniques that need physical access, a supply-chain implant, or sensor
           spoofing are removed, matching the paper's threat model (Section 3)
"""
import json
import math
import sys

CHAIN = [  # (paper tactic, ATM kill-chain phase)
    ("IA",  "initial_access"),
    ("PES", "privilege_escalation"),
    ("C2",  "command_and_control"),
    ("LM",  "lateral_movement"),
    ("IMP", "affect_vehicle_function"),
]
POC_CHAIN = ["IA", "EX", "LM"]  # the stages run on the bench
PHASE = dict(CHAIN, EX="execution")

# Excluded by the threat model, with the reason. T0010 is a judgment call:
# compromised aftermarket or dealer equipment can be reached remotely, so it stays in.
EXCLUDED = {
    "ATM-T0013": "removable media needs physical access",
    "ATM-T0016": "physical modification",
    "ATM-T0017": "supply-chain compromise",
    "ATM-T0028": "hardware fault injection needs physical access",
    "ATM-T0004": "analog sensor attack (sensor spoofing)",
    "ATM-T0005": "adversarial ML on sensor inputs (sensor spoofing)",
}


def load_csv(path):
    """Technique list exported by --export (one row per technique and phase)."""
    import csv
    by_phase, ids = {}, set()
    for r in csv.DictReader(open(path, encoding="utf-8", newline="")):
        by_phase.setdefault(r["phase"], set()).add(r["technique_id"])
        ids.add(r["technique_id"])
    return by_phase, len(ids)


def export_csv(path_json, path_csv):
    """Write the active techniques per kill-chain phase (IDs, names, phases only)."""
    import csv
    objs = json.load(open(path_json, encoding="utf-8"))["objects"]
    rows = []
    for o in objs:
        if o.get("type") != "attack-pattern" or o.get("revoked") or o.get("x_mitre_deprecated"):
            continue
        tid = next((r["external_id"] for r in o.get("external_references", []) if r.get("external_id")), "?")
        phases = [k["phase_name"] for k in o.get("kill_chain_phases") or []] or ["(none)"]
        for ph in phases:  # techniques with no phase still count in the no-DAG baseline
            rows.append({"technique_id": tid, "name": o.get("name", ""), "phase": ph,
                         "excluded_by_threat_model": EXCLUDED.get(tid, "")})
    rows.sort(key=lambda r: (r["phase"], r["technique_id"]))
    with open(path_csv, "w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0]))
        w.writeheader(); w.writerows(rows)
    print(f"wrote {len(rows)} rows to {path_csv}")


def load(path):
    if path.lower().endswith(".csv"):
        return load_csv(path)
    objs = json.load(open(path, encoding="utf-8"))["objects"]
    by_phase = {}
    n_active = 0
    for o in objs:
        if o.get("type") != "attack-pattern" or o.get("revoked") or o.get("x_mitre_deprecated"):
            continue
        n_active += 1
        tid = next((r["external_id"] for r in o.get("external_references", []) if r.get("external_id")), "?")
        for k in o.get("kill_chain_phases", []):
            by_phase.setdefault(k["phase_name"], set()).add(tid)
    return by_phase, n_active


def entropy(stages, by_phase, scoped):
    bits, rows = 0.0, []
    for st in stages:
        techs = by_phase[PHASE[st]]
        if scoped:
            techs = {t for t in techs if t not in EXCLUDED}
        bits += math.log2(len(techs))
        rows.append((st, PHASE[st], len(techs)))
    return bits, rows


def main():
    if len(sys.argv) == 4 and sys.argv[1] == "--export":
        export_csv(sys.argv[2], sys.argv[3])
        return
    by_phase, n_active = load(sys.argv[1])
    print(f"active ATM techniques: {n_active}")
    for scoped in (False, True):
        label = "scoped to threat model" if scoped else "full ATM"
        h, rows = entropy([c for c, _ in CHAIN], by_phase, scoped)
        h_pre, _ = entropy([c for c, _ in CHAIN[:-1]], by_phase, scoped)
        h_imp = math.log2(rows[-1][2])
        h_poc, _ = entropy(POC_CHAIN, by_phase, scoped)
        print(f"\n== {label}")
        for st, ph, n in rows:
            print(f"  {st:<4} {ph:<25} |A| = {n}  ({math.log2(n):.2f} b)")
        print(f"  H(V), full narrative          = {h:.2f} b   (zero-error bar = H)")
        print(f"  H, prefix before impact       = {h_pre:.2f} b   (zero-error bar = H)")
        print(f"  H, single stage (impact)      = {h_imp:.2f} b   (zero-error bar = H)")
        print(f"  H, bench chain IA-EX-LM       = {h_poc:.2f} b   (zero-error bar = H)")
    print(f"\nno-DAG baseline: uniform over all {n_active} techniques at each of "
          f"{len(CHAIN)} steps = {len(CHAIN)*math.log2(n_active):.2f} b")
    print("\nexcluded techniques:")
    for t, why in EXCLUDED.items():
        print(f"  {t}: {why}")


if __name__ == "__main__":
    main()
