"""analyze.py -- score a ChainRecon cell: was the chain reconstructed before the
deadline, and if not, where was the evidence lost?

Reference evidence = the complete delivery log (every event every observer
produced, delivered or not) cross-checked against the independent PEAK CAN
capture.  The IDS's available evidence = events delivered to core 0 AND
processed (t_proc) before the deadline.  The correlator (offline, same code
for every condition) links stages over the available evidence under one of
four representations:

  F1 packet-level   raw frame fields + payload; gateway events reduced to the
                    forwarded/answered frame (no decision, auth, route seq)
  F2 protocol-aware F1 parsed: endpoints, SA/TA, SID/DID, session
                    (for this protocol F1 and F2 carry the same information;
                    reported separately so the claim is checked, not assumed)
  F3 semantic       F2 + gateway decision, reason, auth state, route sequence
  F4 aggregated     per-observer alerts: category + 100 ms window only,
                    no endpoints, session ids or payload

Primary outcome (per cell, at the cell's benign alarm rate):
  P_chain = malicious complete-chain trials (S1, S4) whose chain was
            reconstructed with correct stages, links and attribution before
            the deadline / those trials.
Failure mechanism of a missed chain (first stage that failed):
  insufficiency  reference event never delivered (out of scope / ring full)
  processing     delivered but dropped at admission, unprocessed, or late
  ambiguity      all evidence available in time, wrong/undecidable link

  python analyze.py ../runs/E3_all_U100 [--rep F3] [--scope gw] [--json out.json]
"""
from __future__ import annotations

import argparse
import glob
import json
import math
import os
import statistics as st
from collections import Counter, defaultdict

import bench_proto as bp

TICKS_MS = bp.STM_HZ // 1000


def wilson(k: int, n: int, z: float = 1.96):
    if n == 0:
        return (float("nan"), float("nan"), float("nan"))
    p = k / n
    d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d
    h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return (p, max(0.0, c - h), min(1.0, c + h))


def dt(a: int, b: int) -> int:
    """b - a in STM ticks, wrap-safe (b later than a)."""
    return (b - a) & 0xFFFFFFFF


# ---------------------------------------------------------------- #
# loading                                                           #
# ---------------------------------------------------------------- #
def load_cell(path: str):
    with open(os.path.join(path, "cell.json")) as f:
        cell = json.load(f)
    trials = []
    for p in sorted(glob.glob(os.path.join(path, "trial_*.json"))):
        with open(p) as f:
            trials.append(json.load(f))
    return cell, trials


def events_of(trial: dict) -> list[dict]:
    """Delivery-log events joined with the IDS log, times relative to START."""
    dump = trial["dump"]
    t0 = dump["ctl"]["t_start"]
    ids = {r["seq"]: r for r in dump["idslog"]}
    out = []
    for e in dump["dlog"]:
        e = dict(e)
        e["t"] = dt(t0, e["t_obs"])
        r = ids.get(e["seq"])
        e["ids_status"] = bp.IDS_ST.get(r["status"], "?") if r else None
        e["t_proc"] = dt(t0, r["t_proc"]) if (r and r["status"] == 1) else None
        e["t_ing"] = dt(t0, r["t_ing"]) if r else None
        e["dlv"] = bp.DLV.get(e["status"], "?")
        e["forged"] = bool(e.get("flags", 0) & bp.EVF_FORGED)   # written by a compromised observer
        out.append(e)
    out.sort(key=lambda e: e["seq"])
    return out


def sess_key(e) -> tuple | None:
    if e["obs"] in (bp.OBS_SRC, bp.OBS_GW) and e.get("port"):
        return (e["ip"], e["port"])
    return None


def uds_of_src(e) -> bytes:
    return bytes.fromhex(e.get("uds", "")) if e.get("uds") else b""


def can_data(e) -> bytes:
    return bytes.fromhex(e["data"])


# ---------------------------------------------------------------- #
# reference chain (ground truth)                                    #
# ---------------------------------------------------------------- #
def reference(trial: dict, evs: list[dict]) -> dict:
    gt = trial["gt"]
    # Ground truth is built from genuine observations only: a forged report
    # (written by a compromised observer) is never part of the reference.
    evs = [e for e in evs if not e.get("forged")]
    ports = {s["port"]: s for s in gt["sessions"]}
    mal = [s for s in gt["sessions"] if s["role"] == "malicious"]
    ref = {"malicious": bool(mal), "scenario": gt["scenario"], "stages": {}, "key": None}

    # Ground truth from the complete record (all observers, delivered or not):
    #  * per target ECU, the k-th forwarded route <-> k-th request frame <-> k-th
    #    response frame (each ECU answers its own requests in order);
    #  * impacts: core 2's private impact log says which ECU and value produced
    #    which impact counter; older runs without it fall back to FIFO order.
    can = [e for e in evs if e["obs"] == bp.OBS_DST]
    impacts = [e for e in can if e["can_id"] == bp.CANID_IMPACT]
    route_to_req, req_to_resp, req_ecu = {}, {}, {}
    for req_id in bp.DIAG_REQ_IDS:
        reqs_i = [e for e in can if e["can_id"] == req_id]
        resps_i = [e for e in can if e["can_id"] == bp.RESP_OF_REQ[req_id]]
        ta = 0x0010 if req_id == bp.CANID_DIAG_REQ else 0x0011
        routes_i = sorted([e for e in evs if e["obs"] == bp.OBS_GW and e["kind"] == bp.EK_GW_ROUTE
                           and e["decision"] in ("ALLOW", "AUDIT") and e["ta"] == ta],
                          key=lambda e: e["route_seq"])
        for i, r in enumerate(routes_i):
            route_to_req[r["route_seq"]] = reqs_i[i] if i < len(reqs_i) else None
        for i, q in enumerate(reqs_i):
            req_to_resp[q["seq"]] = resps_i[i] if i < len(resps_i) else None
            req_ecu[q["seq"]] = bp.ECU_OF_REQ[req_id]
    implog = [dict(x) for x in (trial["dump"].get("implog") or [])]
    imp_by_counter = {can_data(i)[1]: i for i in impacts}

    def impact_of(q, r):
        """True impact frame produced by the write q (answered by r)."""
        if implog:
            # Entries with the same (ECU, value) are indistinguishable in the
            # impact log.  Resolve them in write order: the k-th write of this
            # value to this ECU produced the k-th such impact.  Exact when the
            # impact delay is constant (jitter 0); with jitter > 0 and two equal
            # writes to ONE ECU the true pairing is not recorded (fix 10 Nov 2026:
            # the old code always took the first entry, i.e. gave the attacker the
            # first impact even when it wrote second).
            ecu, val = req_ecu[q["seq"]], can_data(q)[4]
            same = [x for x in can if x["can_id"] == q["can_id"]
                    and can_data(x)[1:4] == bytes([0x2E, 0xF1, 0xA0]) and can_data(x)[4] == val]
            k = next((i for i, x in enumerate(same) if x["seq"] == q["seq"]), 0)
            ents = [ent for ent in implog if ent["ecu"] == ecu and ent["value"] == val]
            if k < len(ents):
                return imp_by_counter.get(ents[k]["counter"])
            return None
        write_ok = [x for x in can if x["can_id"] in bp.DIAG_RESP_IDS
                    and can_data(x)[1:4] == bytes([0x6E, 0xF1, 0xA0])]
        k = next((i for i, x in enumerate(write_ok) if x["seq"] == r["seq"]), None)
        return impacts[k] if (k is not None and k < len(impacts)) else None
    ref["fifo"] = {"route_to_req": {k: (v["seq"] if v else None) for k, v in route_to_req.items()},
                   "req_to_resp": {k: (v["seq"] if v else None) for k, v in req_to_resp.items()}}

    if not mal:
        ref["t_end"] = max((e["t"] for e in evs if not (e["obs"] == bp.OBS_DST and e["can_id"] == bp.CANID_SYNC)),
                           default=0)
        return ref

    m = mal[0]
    gw_m = [e for e in evs if e["obs"] == bp.OBS_GW and e.get("port") == m["port"]]
    src_m = [e for e in evs if e["obs"] == bp.OBS_SRC and e.get("port") == m["port"]]
    ref["key"] = (gw_m[0]["ip"], m["port"]) if gw_m else (src_m[0]["ip"] if src_m else None, m["port"])
    S = ref["stages"]

    vir = [e for e in gw_m if e["kind"] == bp.EK_GW_VIR]
    ra = [e for e in gw_m if e["kind"] == bp.EK_GW_RA and e["decision"] == "ALLOW"]
    if vir and ra and ra[0]["t"] > vir[0]["t"]:
        S[1] = [vir[0]["seq"], ra[0]["seq"]] + [e["seq"] for e in src_m if e["doip_type"] in (bp.DOIP_VIR, bp.DOIP_RA_REQ)][:2]
    aud = [e for e in gw_m if e["kind"] == bp.EK_GW_ROUTE and e["decision"] == "AUDIT"]
    den = [e for e in gw_m if e["kind"] == bp.EK_GW_ROUTE and e["decision"] == "DENY" and e["reason"] == "ROUTE_CLOSED"]
    if aud:
        w_src = [e for e in src_m if e["doip_type"] == bp.DOIP_DIAG and uds_of_src(e)[:1] == b"\x2e"]
        S[2] = [aud[0]["seq"]] + [e["seq"] for e in w_src[:1]]
        q = route_to_req.get(aud[0]["route_seq"])
        if q is not None:
            S[3] = [aud[0]["seq"], q["seq"]]
            r = req_to_resp.get(q["seq"])
            if r is not None and can_data(r)[1:4] == bytes([0x6E, 0xF1, 0xA0]):
                gr = [e for e in gw_m if e["kind"] == bp.EK_GW_RESP and e["route_seq"] == aud[0]["route_seq"]]
                S[4] = [r["seq"]] + [e["seq"] for e in gr]
                im = impact_of(q, r)
                if im is not None:
                    S[5] = [im["seq"]]
    elif den:
        # denied cross-zone attempt: the refused requests and the attempt frames
        att = [e for e in src_m if e["doip_type"] == bp.DOIP_DIAG]
        S[2] = [e["seq"] for e in den] + [e["seq"] for e in att] + \
               [e["seq"] for e in gw_m if e["kind"] == bp.EK_GW_ROUTE and e["decision"] == "DENY"]
    last = max((e["t"] for e in evs if any(e["seq"] in v for v in S.values())), default=0)
    ref["t_end"] = last
    ref["reached"] = max(S) if S else 0
    return ref


# ---------------------------------------------------------------- #
# representation projection + correlator                            #
# ---------------------------------------------------------------- #
def alert_category(e, seen_unlock: set) -> str | None:
    """Local per-observer alert used by F4 (no endpoints in the output)."""
    if e["obs"] == bp.OBS_SRC and e["kind"] == bp.EK_ETH_DOIP:
        k = sess_key(e)
        if e["doip_type"] == bp.DOIP_VIR:
            return "DISCOVERY"
        u = uds_of_src(e)
        if u[:2] == b"\x27\x02":
            seen_unlock.add(k)
        if u[:3] == bytes([0x2E, 0xF1, 0xA0]) and k not in seen_unlock:
            return "VIOLATION"
    elif e["obs"] == bp.OBS_GW:
        if e["kind"] == bp.EK_GW_VIR:
            return "DISCOVERY"
        if e["kind"] == bp.EK_GW_ROUTE and e["decision"] == "AUDIT":
            return "VIOLATION"
    elif e["obs"] == bp.OBS_DST:
        d = can_data(e)
        if e["can_id"] in bp.DIAG_REQ_IDS and d[1:4] == bytes([0x2E, 0xF1, 0xA0]):
            return "XZONE_WRITE"
        if e["can_id"] in bp.DIAG_RESP_IDS and d[1:4] == bytes([0x6E, 0xF1, 0xA0]):
            return "TARGET_CHANGE"
        if e["can_id"] == bp.CANID_IMPACT:
            return "IMPACT"
    return None


def correlate(avail: list[dict], rep: str) -> dict:
    """Return {session_key: {stage: [seqs]}} and alarm flags.  `avail` holds
    only events the IDS processed before the deadline, in arrival order."""
    claims: dict = defaultdict(dict)
    if rep == "F4":
        seen_unlock: set = set()
        cats = []
        for e in avail:
            c = alert_category(e, seen_unlock)
            if c:
                cats.append((c, e["t"] // (100 * TICKS_MS), e["seq"]))
        order = ["DISCOVERY", "VIOLATION", "XZONE_WRITE", "TARGET_CHANGE", "IMPACT"]
        got, w_last = {}, -1
        for i, cat in enumerate(order):
            for c, w, seq in cats:
                if c == cat and w >= w_last:
                    got[i + 1] = [seq]
                    w_last = w
                    break
            else:
                break
        nviol = sum(1 for c, _, _ in cats if c == "VIOLATION")
        nxz = sum(1 for c, _, _ in cats if c == "XZONE_WRITE")
        if got:
            claims[None] = got
        return {"claims": dict(claims), "alarm": nviol > 0, "f4_multi": nxz > 1}

    use_gw_semantics = rep == "F3"
    src = [e for e in avail if e["obs"] == bp.OBS_SRC and e["kind"] == bp.EK_ETH_DOIP]
    gw = [e for e in avail if e["obs"] == bp.OBS_GW]
    can = [e for e in avail if e["obs"] == bp.OBS_DST]

    by_k = defaultdict(list)
    for e in src + gw:
        k = sess_key(e)
        if k:
            by_k[k].append(e)

    reqs = [e for e in can if e["can_id"] in bp.DIAG_REQ_IDS]
    resps = [e for e in can if e["can_id"] in bp.DIAG_RESP_IDS]
    impacts = [e for e in can if e["can_id"] == bp.CANID_IMPACT]
    used_req, used_imp = set(), set()

    # writes of every session, in arrival order (for FIFO linking)
    writes = []
    for k, es in by_k.items():
        es.sort(key=lambda e: e["t"])
        unlocked = False
        for e in es:
            if e["obs"] == bp.OBS_SRC and uds_of_src(e)[:2] == b"\x27\x02":
                unlocked = True
            if e["obs"] == bp.OBS_GW and e["kind"] == bp.EK_GW_RESP and e["sid"] == 0x67 and e["sub"] == 0x02:
                unlocked = True
            is_w_src = e["obs"] == bp.OBS_SRC and e["doip_type"] == bp.DOIP_DIAG and uds_of_src(e)[:3] == bytes([0x2E, 0xF1, 0xA0])
            is_w_gw = e["obs"] == bp.OBS_GW and e["kind"] == bp.EK_GW_ROUTE and e["sid"] == 0x2E and e["did"] == bp.DID_TEST_STATE
            if is_w_src or is_w_gw:
                viol = (e["decision"] == "AUDIT") if (is_w_gw and use_gw_semantics) else (not unlocked)
                fwd = (e["decision"] in ("ALLOW", "AUDIT")) if is_w_gw else None
                writes.append({"k": k, "e": e, "viol": viol, "fwd": fwd, "t": e["t"]})
    # one write per session; the gateway record says whether it was forwarded
    # (any representation: a forwarded frame is visible at packet level), and
    # under F3 it also carries the policy decision.
    merged = {}
    for w in sorted(writes, key=lambda w: w["t"]):
        e = w["e"]
        cur = merged.get(w["k"])
        if cur is None:
            cur = merged[w["k"]] = dict(w, seqs=[], gw=None, value=None, ta=None)
        cur["seqs"].append(e["seq"])
        if e.get("ta") is not None:
            cur["ta"] = e["ta"]                    # which target ECU was written
        if e["obs"] == bp.OBS_GW:
            cur["gw"], cur["fwd"] = e, w["fwd"]
            if use_gw_semantics:
                cur["viol"] = w["viol"]
        else:
            u = uds_of_src(e)
            if len(u) >= 4:
                cur["value"] = u[3]
            if not (use_gw_semantics and cur["gw"] is not None):
                cur["viol"] = w["viol"]          # F3 keeps the gateway's decision
    wlist = sorted(merged.values(), key=lambda w: w["t"])

    # destination bus: each target ECU answers its own requests in order (FIFO)
    pair = {}
    free = list(resps)
    for q in reqs:
        rid = bp.RESP_OF_REQ[q["can_id"]]
        r = next((r for r in free if r["can_id"] == rid and r["t"] >= q["t"]), None)
        if r is not None:
            free.remove(r)
            pair[q["seq"]] = r

    alarm = False
    for k, es in by_k.items():
        c = {}
        vir = [e for e in es if (e["obs"] == bp.OBS_GW and e["kind"] == bp.EK_GW_VIR) or
               (e["obs"] == bp.OBS_SRC and e["doip_type"] == bp.DOIP_VIR)]
        ra = [e for e in es if (e["obs"] == bp.OBS_GW and e["kind"] == bp.EK_GW_RA and e["decision"] == "ALLOW") or
              (e["obs"] == bp.OBS_SRC and e["doip_type"] == bp.DOIP_RA_REQ)]
        if vir and ra and max(r["t"] for r in ra) > min(v["t"] for v in vir):
            c[1] = [vir[0]["seq"], ra[0]["seq"]]
        w = merged.get(k)
        den = [e for e in es if e["obs"] == bp.OBS_GW and e["kind"] == bp.EK_GW_ROUTE and e["decision"] == "DENY"
               and (e["reason"] == "ROUTE_CLOSED" if use_gw_semantics
                    else e["ta"] not in (bp.LA_TARGET, bp.LA_TARGET_B))]
        if w and w["viol"]:
            c[2] = list(w["seqs"])
            alarm = True
        elif den:
            c[2] = [den[0]["seq"]]
            alarm = True
        if c:
            claims[k] = c

    # stage 3-5: FIFO linking along the destination bus, in write order
    # Every session's write consumes its bus frames (FIFO), even when that
    # session is not suspected; only suspected sessions get stage claims.
    for w in wlist:
        k = w["k"]
        c = claims.get(k) if (k in claims and 2 in claims[k]) else {}
        if w["gw"] is not None and w["fwd"] is False:
            continue                                  # denied: nothing on the bus
        if w["gw"] is not None and w["fwd"]:
            c[3] = [w["gw"]["seq"]]
        t_from = w["gw"]["t"] if w["gw"] is not None else w["t"]
        # stage 3 on the bus: first unused write request after the session's
        # write, with the same value when the value is known
        cands = [q for q in reqs if q["seq"] not in used_req and q["t"] >= t_from
                 and can_data(q)[1:4] == bytes([0x2E, 0xF1, 0xA0])]
        if w["ta"] in bp.REQ_OF_TA:                   # the request ID names the ECU
            cands = [q for q in cands if q["can_id"] == bp.REQ_OF_TA[w["ta"]]]
        if w["value"] is not None:
            cands = [q for q in cands if can_data(q)[4] == w["value"]] or []
        q = cands[0] if cands else None
        if q is not None:
            used_req.add(q["seq"])
            c.setdefault(3, []).append(q["seq"])
        # stage 4: the gateway's response to this endpoint (route seq under F3),
        # and/or the FIFO-paired 6E on the bus
        g4 = [e for e in by_k[k] if e["obs"] == bp.OBS_GW and e["kind"] == bp.EK_GW_RESP and e["sid"] == 0x6E
              and (not use_gw_semantics or w["gw"] is None or e["route_seq"] == w["gw"]["route_seq"])]
        r = pair.get(q["seq"]) if q is not None else None
        if r is not None and can_data(r)[1:4] != bytes([0x6E, 0xF1, 0xA0]):
            r = None
        if r is not None or g4:
            c[4] = ([r["seq"]] if r is not None else []) + [e["seq"] for e in g4[:1]]
        # stage 5: first unused impact after the 6E that is consistent with this
        # write: same value, and the same ECU when the frame names its source.
        # With two writers, equal values and no source byte, several impacts
        # fit; the earliest is taken and may be the wrong one (true ambiguity).
        if r is not None:
            val, ecu = can_data(q)[4], bp.ECU_OF_REQ[q["can_id"]]
            ims = [i for i in impacts if i["seq"] not in used_imp and i["t"] >= r["t"]
                   and can_data(i)[0] == val and can_data(i)[2] in (0, ecu)]
            im = ims[0] if ims else None
            if im is not None:
                used_imp.add(im["seq"])
                c[5] = [im["seq"]]
    return {"claims": dict(claims), "alarm": alarm}


# ---------------------------------------------------------------- #
# scoring                                                           #
# ---------------------------------------------------------------- #
def score_trial(trial: dict, rep: str, deadline_ms: int, scope_mask: int | None):
    evs = [bp.decode_event(dict(e, d=bytes.fromhex(e["d"]))) if "ip" not in e and "can_id" not in e else e
           for e in trial["dump"]["dlog"]]
    trial = dict(trial)
    trial["dump"] = dict(trial["dump"], dlog=evs)
    evs = events_of(trial)
    ref = reference(trial, evs)
    deadline = ref["t_end"] + deadline_ms * TICKS_MS

    def avail_ok(e):
        if e["dlv"] != "delivered":
            return False
        if scope_mask is not None and not (scope_mask & (1 << e["obs"])):
            return False
        return e["t_proc"] is not None and e["t_proc"] <= deadline

    avail = sorted([e for e in evs if avail_ok(e)], key=lambda e: e["t_proc"])
    out = correlate(avail, rep)
    claims = out["claims"]
    res = {"scenario": ref["scenario"], "malicious": ref["malicious"], "alarm": out["alarm"],
           "deadline_t": deadline, "ref_stages": sorted(ref["stages"]), "claim_sessions": len(claims)}
    if not ref["malicious"]:
        res["false_alarm"] = out["alarm"]
        return res, ref, evs, avail

    S, key = ref["stages"], ref["key"]
    if rep == "F4":
        n_sess = len(trial["gt"]["sessions"])
        mine = claims.get(None, {}) if n_sess == 1 else {}
        res["f4_unattributable"] = n_sess > 1
    else:
        mine = claims.get(key, {})
    mine_raw = mine
    # A forgery stands in for the genuine report it replaced: the firmware logs the
    # replaced report (forged_out) and its forgery as consecutive sequence numbers.
    # Scoring asks whether the correlator's conclusion is right, so a claim that
    # cites the forgery is checked as if it cited the replaced report.
    by_seq = {e["seq"]: e for e in evs}
    stand_in = {e["seq"]: e["seq"] - 1 for e in evs
                if e.get("forged") and by_seq.get(e["seq"] - 1, {}).get("dlv") == "forged_out"}
    if stand_in:
        mine = {s: [stand_in.get(q, q) for q in v] for s, v in mine.items()}
    # stage correctness: claimed evidence must include a reference event of that stage
    per = {}
    for s in range(1, 6):
        if s in S:
            # every claimed event must belong to the reference stage (no wrong links)
            per[s] = s in mine and bool(mine[s]) and set(mine[s]) <= set(S[s])
    exp = trial["gt"]["expected_stages"]
    over = [s for s in mine if s not in S]                  # claimed stages that did not happen
    wrong = [s for s in mine if s in S and not set(mine[s]) <= set(S[s])]
    res.update(per_stage=per, over_claim=over, wrong_link=wrong,
               complete=all(per.get(s, False) for s in S) and not over and bool(S),
               reached=max(S) if S else 0, expected=exp)
    if res["complete"]:
        used = [e for e in avail if any(e["seq"] in v for v in mine_raw.values())]
        res["t_claim"] = max(e["t_proc"] for e in used)
        res["latency_ms"] = (res["t_claim"] - ref["t_end"]) / TICKS_MS
    else:
        res["mechanism"] = mechanism(S, per, evs, deadline, scope_mask)
    return res, ref, evs, avail


def mechanism(S: dict, per: dict, evs: list[dict], deadline: int, scope_mask) -> str:
    by = {e["seq"]: e for e in evs}
    for s in sorted(S):
        if per.get(s):
            continue
        es = [by[q] for q in S[s] if q in by]
        if any(e["dlv"] == "forged_out" for e in es) and not (
                scope_mask is not None and all(not scope_mask & (1 << e["obs"]) for e in es if e["dlv"] == "forged_out")):
            # part of this stage's genuine evidence was replaced by a forgery
            # that the IDS received in its place
            return f"forgery:stage{s}"
        def delivered(e):
            return e["dlv"] == "delivered" and (scope_mask is None or scope_mask & (1 << e["obs"]))
        if not any(delivered(e) for e in es):
            why = Counter("scope" if (e["dlv"] == "masked" or (scope_mask is not None and not scope_mask & (1 << e["obs"])))
                          else e["dlv"] for e in es)
            if "forged_out" in why:
                # the stage's genuine evidence reached the observer but was
                # replaced by a forgery before delivery
                return f"forgery:stage{s}:{'+'.join(sorted(why))}"
            return f"insufficiency:stage{s}:{'+'.join(sorted(why))}"
        if not any(delivered(e) and e["t_proc"] is not None and e["t_proc"] <= deadline for e in es):
            kinds = Counter("admit_drop" if e["ids_status"] == "admit_drop" else
                            "unprocessed" if e["t_proc"] is None else "late" for e in es if delivered(e))
            return f"processing:stage{s}:{'+'.join(sorted(kinds))}"
        lost = [e for e in es if not (delivered(e) and e["t_proc"] is not None and e["t_proc"] <= deadline)]
        # some of this stage's evidence was available, but not all: a wrong or
        # undecidable link caused by partial loss is a combined effect
        if lost:
            return f"ambiguity:stage{s}:after_partial_loss"
        # the stage's own evidence was on time; was linking context (other
        # sessions' requests/responses used for FIFO pairing) lost?
        ctx_lost = any(delivered(e) and not (e["t_proc"] is not None and e["t_proc"] <= deadline)
                       for e in evs if not (e["obs"] == bp.OBS_DST and e.get("can_id") == bp.CANID_SYNC))
        return f"ambiguity:stage{s}:{'after_context_loss' if ctx_lost else 'all_evidence_on_time'}"
    return "ambiguity:overclaim"


# ---------------------------------------------------------------- #
# validity and independent Ethernet reference                       #
# ---------------------------------------------------------------- #
ALLOW_DEV = False   # --allow-dev: score internal-loopback runs (never for results)
DOIP_OF_OP = {"vir": bp.DOIP_VIR, "ra": bp.DOIP_RA_REQ, "diag": bp.DOIP_DIAG}


def ingress_check(trial: dict, evs: list[dict]) -> dict:
    """Tester logs are independent of the gateway: every DoIP message a tester
    sent should appear exactly once as a source-zone event (delivered or not).
    Missing = lost at gateway ingress (before any observer); duplicated = a
    cabling/mirror problem."""
    by_port = defaultdict(list)
    for e in evs:
        if e["obs"] == bp.OBS_SRC and e["kind"] == bp.EK_ETH_DOIP:
            by_port[e["port"]].append(e)
    sent = missing = dup = 0
    for port in {r["port"] for r in trial["gt"]["tester_log"]}:
        recs = [r for r in trial["gt"]["tester_log"] if r["port"] == port]
        es = by_port.get(port, [])
        used = set()
        for r in recs:
            sent += 1
            want = DOIP_OF_OP[r["op"]]
            m = [e for e in es if e["seq"] not in used and e["doip_type"] == want and
                 (r["op"] != "diag" or e.get("uds", "").startswith(r["req"][:min(8, len(r["req"]))]))]
            if not m:
                missing += 1
            else:
                used.add(m[0]["seq"])
        dup += len([e for e in es if e["seq"] not in used])
    return {"sent": sent, "missing_at_ingress": missing, "unmatched_src_events": dup}


def validity(trial: dict, ref: dict, ing: dict) -> list[str]:
    c = trial["dump"]["ctl"]
    why = []
    if not trial["start"]["ok"]:
        why.append("start_not_acked")
    if not trial["end"]["ok"]:
        why.append("end_not_acked")
    for k in ("can_tx_to", "tq_full", "c2_txq_full", "dlog_ovf", "c0_log_ovf"):
        if c.get(k, 0):
            why.append(k)
    if c.get("build_flags", 0) & bp.BUILD_FLAG_CAN_INTERNAL_LOOPBACK and not ALLOW_DEV:
        why.append("dev_build_can_internal_loopback")
    if ing["unmatched_src_events"]:
        why.append("duplicate_ingress")
    if ref["malicious"] and ref.get("reached", 0) < trial["gt"]["expected_stages"]:
        why.append("attack_not_executed_as_scripted")
    return why


def s4_write_gap_ms(trial: dict):
    w = [r for r in trial["gt"]["tester_log"] if r["op"] == "diag" and r["req"].startswith("2ef1a0")]
    if len(w) < 2:
        return None
    return abs(w[0]["t_send"] - w[1]["t_send"]) / 1e6


# ---------------------------------------------------------------- #
# cell summaries                                                    #
# ---------------------------------------------------------------- #
def pipeline_stats(trials_evs):
    """Fraction of non-background reference events at each pipeline stage."""
    c = Counter()
    for evs, deadline in trials_evs:
        for e in evs:
            if e["obs"] == bp.OBS_DST and e.get("can_id") == bp.CANID_SYNC:
                continue
            if e.get("forged"):
                c["forged_delivered"] += 1
                continue
            c["reference"] += 1
            if e["dlv"] != "delivered":
                c[f"not_delivered_{e['dlv']}"] += 1
                continue
            c["delivered"] += 1
            if e["ids_status"] == "admit_drop":
                c["admit_drop"] += 1
                continue
            c["admitted"] += 1
            if e["t_proc"] is None:
                c["unprocessed"] += 1
                continue
            c["processed"] += 1
            if e["t_proc"] <= deadline:
                c["on_time"] += 1
    return dict(c)


def sampling_stats(trials, cell):
    """Measured m (processed / arrivals per window) vs. floor(U T_w / w) / n."""
    rows = []
    for t in trials:
        c = t["dump"]["ctl"]
        proc = c["c0_proc"]
        busy = c["c0_busy_ticks"]
        w_mean = busy / proc if proc else float("nan")
        w_max = c["c0_wcet_ticks"]
        for w in t["dump"]["wlog"]:
            if w["arrivals"] == 0:
                continue
            rows.append({"arr": w["arrivals"], "proc": w["processed"], "busy": w["busy"],
                         "w_mean": w_mean, "w_max": w_max})
    if not rows:
        return {}
    u = min(cell["u_ppm"], 1_000_000) / 1e6
    tw = bp.IDS_WINDOW_MS * TICKS_MS
    w_max = max(r["w_max"] for r in rows)
    w_mean = st.mean(r["w_mean"] for r in rows if not math.isnan(r["w_mean"]))
    n_max = max(r["arr"] for r in rows)
    meas = [r["proc"] / r["arr"] for r in rows]
    k_cpu_wcet = math.floor(u * tw / w_max) if w_max else None
    return {"windows": len(rows), "arrivals_max_per_window": n_max,
            "arrivals_mean": st.mean(r["arr"] for r in rows),
            "w_mean_us": w_mean / bp.STM_HZ * 1e6, "w_max_us": w_max / bp.STM_HZ * 1e6,
            "m_measured_mean": st.mean(meas), "m_measured_min": min(meas),
            "k_cpu_wcet": k_cpu_wcet,
            "m_pred_wcet": min(1.0, k_cpu_wcet / n_max) if (k_cpu_wcet is not None and n_max) else None}


def forwarding_stats(trials):
    """Gateway forwarding: on-chip latency SRC write -> DST 0x7E0, and tester losses."""
    lat, lost, sent = [], 0, 0
    for t in trials:
        evs = t["_evs"]
        src = [e for e in evs if e["obs"] == bp.OBS_SRC and e.get("doip_type") == bp.DOIP_DIAG]
        for ta, req_id in bp.REQ_OF_TA.items():          # per target ECU, FIFO
            reqs = [e for e in evs if e["obs"] == bp.OBS_DST and e.get("can_id") == req_id]
            routes = sorted([e for e in evs if e["obs"] == bp.OBS_GW and e["kind"] == bp.EK_GW_ROUTE
                             and e["decision"] in ("ALLOW", "AUDIT") and e["ta"] == ta],
                            key=lambda e: e["route_seq"])
            for i, r in enumerate(routes):
                s = [e for e in src if e["port"] == r["port"] and e["t"] <= r["t"]]
                if s and i < len(reqs):
                    lat.append((reqs[i]["t"] - s[-1]["t"]) / TICKS_MS)
        for rec in t["gt"]["tester_log"]:
            if rec["op"] == "diag":
                sent += 1
                if rec.get("ack") == "ack" and not rec.get("resp"):
                    lost += 1
    out = {"diag_sent": sent, "acked_without_response": lost}
    if lat:
        lat.sort()
        out.update(fwd_latency_ms_median=st.median(lat), fwd_latency_ms_p95=lat[int(0.95 * (len(lat) - 1))],
                   fwd_latency_ms_max=lat[-1], n=len(lat))
    return out


def peak_consistency(trials):
    """Every destination-bus event in the delivery log should be in the PEAK capture."""
    tot = match = 0
    have = 0
    for t in trials:
        if not t.get("peak"):
            continue
        have += 1
        pk = [(f["id"], f["data"]) for f in t["peak"]]
        dl = [(e["can_id"], e["data"]) for e in t["_evs"] if e["obs"] == bp.OBS_DST]
        i = 0
        for x in dl:
            tot += 1
            while i < len(pk) and pk[i] != x:
                i += 1
            if i < len(pk):
                match += 1
                i += 1
    return {"trials_with_peak": have, "dst_events": tot, "matched_in_order": match}


def fano_floor(cell, trials, rep):
    """Failure-region check (converse only).  H(phi(V)) from the fixed mix: the
    task is to name which session (if any) ran the malicious chain and how far
    it got.  Budget proxy: processed-before-deadline reports x per-report
    entropy ceiling of the representation."""
    mix = dict(cell["mix_norm"])
    # labels: (family stage pattern, attacker index among sessions)
    labels = Counter()
    for fam, p in mix.items():
        n_sess = {"S1": 1, "S2": 1, "S3": 1, "S4": 2, "S5": 3, "S6": 1, "S7": 2}[fam]
        if fam in ("S1", "S2", "S3", "S4", "S7"):
            for i in range(n_sess):
                labels[(fam, i)] += p / n_sess
        else:
            labels[("benign", -1)] += p
    H = -sum(p * math.log2(p) for p in labels.values() if p > 0)
    T = len(labels)
    h_bits = {"F1": 160, "F2": 160, "F3": 160, "F4": math.log2(6)}[rep]  # 20-byte record / 6 alert classes
    out = []
    for t in trials:
        n_avail = t["_n_avail"]
        C = n_avail * h_bits
        out.append(max(0.0, (H - C - 1) / math.log2(T)) if T > 1 else 0.0)
    return {"H_phi_bits": H, "labels": T, "floor_max": max(out) if out else None,
            "trials_with_zero_available": sum(1 for t in trials if t["_n_avail"] == 0)}


def summarize(path, rep="F3", scope=None, deadline_ms=None):
    cell, trials = load_cell(path)
    dl = deadline_ms if deadline_ms is not None else cell.get("deadline_ms", 1000)
    smask = bp.SCOPES[scope] if scope else None
    rows, tev, kept, invalid, ingress = [], [], [], Counter(), Counter()
    gaps = []
    for t in trials:
        r, ref, evs, avail = score_trial(t, rep, dl, smask)
        ing = ingress_check(t, evs)
        for k, v in ing.items():
            ingress[k] += v
        bad = validity(t, ref, ing)
        r["invalid"] = bad
        if bad:
            for b in bad:
                invalid[b] += 1
            continue
        if r["scenario"] in ("S4", "S7"):
            g = s4_write_gap_ms(t)
            if g is not None:
                gaps.append(g)
        t["_evs"], t["_n_avail"] = evs, len(avail)
        rows.append(r)
        kept.append(t)
        tev.append((evs, r["deadline_t"]))
    trials = kept
    chain = [r for r in rows if r["scenario"] in ("S1", "S4", "S7")]
    part = [r for r in rows if r["scenario"] in ("S2", "S3")]
    ben = [r for r in rows if not r["malicious"]]
    k = sum(r["complete"] for r in chain)
    fa = sum(r["false_alarm"] for r in ben)
    lat = [r["latency_ms"] for r in chain if r.get("complete")]
    summ = {
        "cell": cell["name"], "rep": rep, "scope_live": cell["scope"], "scope_offline": scope,
        "u_ppm": cell["u_ppm"], "q_cap": cell["q_cap"], "bg_pps": cell["bg_pps"], "deadline_ms": dl,
        "trials": len(rows), "trials_invalid": sum(invalid.values()) and dict(invalid),
        "ingress": dict(ingress),
        "s4_write_gap_ms": ({"n": len(gaps), "median": st.median(gaps), "min": min(gaps), "max": max(gaps)}
                            if gaps else None),
        "P_chain": wilson(k, len(chain)), "chain_trials": len(chain), "chain_ok": k,
        "P_chain_by_family": {f: wilson(sum(r["complete"] for r in chain if r["scenario"] == f),
                                        sum(1 for r in chain if r["scenario"] == f)) for f in ("S1", "S4", "S7")},
        "partial_ok": wilson(sum(r["complete"] for r in part), len(part)),
        "benign_alarm_rate": wilson(fa, len(ben)), "benign_trials": len(ben),
        "stage_recall": {s: wilson(sum(r["per_stage"].get(s, False) for r in chain if s in r["per_stage"]),
                                   sum(1 for r in chain if s in r["per_stage"])) for s in range(1, 6)},
        "wrong_links": sum(len(r["wrong_link"]) for r in chain + part),
        "over_claims": sum(len(r["over_claim"]) for r in chain + part),
        "mechanisms": dict(Counter(r["mechanism"].split(":")[0] for r in chain if not r["complete"])),
        "mechanisms_detail": dict(Counter(r["mechanism"] for r in chain if not r["complete"])),
        "latency_ms": {"n": len(lat), "median": st.median(lat) if lat else None,
                       "max": max(lat) if lat else None, "deadline_failures": len(chain) - k},
        "pipeline": pipeline_stats(tev),
        "sampling": sampling_stats(trials, cell),
        "forwarding": forwarding_stats(trials),
        "peak": peak_consistency(trials),
        "fano": fano_floor(cell, trials, rep),
    }
    if scope and cell["scope"] != "all":
        summ["warning"] = "offline scope filter on a run that was not recorded with scope=all"
    if scope and cell["u_ppm"] < 1_000_000:
        summ["warning_u"] = ("offline scope filter at a binding CPU share: the live masked run would "
                             "have had less load, so processing results are not comparable")
    return summ, rows


def fmt_ci(t):
    p, lo, hi = t
    return "n/a" if p != p else f"{p:.2f} [{lo:.2f}, {hi:.2f}]"


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("cell_dir")
    ap.add_argument("--rep", default="F3", choices=["F1", "F2", "F3", "F4"])
    ap.add_argument("--scope", default=None, choices=sorted(bp.SCOPES),
                    help="offline scope filter (valid only on scope=all runs at non-binding U)")
    ap.add_argument("--deadline-ms", type=int, default=None)
    ap.add_argument("--json", default=None)
    ap.add_argument("--trials", action="store_true", help="print one line per trial")
    ap.add_argument("--allow-dev", action="store_true",
                    help="score runs from the internal-CAN-loopback dev build (debugging only)")
    a = ap.parse_args()
    global ALLOW_DEV
    ALLOW_DEV = a.allow_dev
    if a.allow_dev:
        print("!! DEV MODE: internal-loopback runs are scored. Not results; no PEAK reference.")
    s, rows = summarize(a.cell_dir, a.rep, a.scope, a.deadline_ms)
    if a.trials:
        for r in rows:
            print(r["scenario"], "OK " if r.get("complete") else ("FA " if r.get("false_alarm") else "-- "),
                  r.get("mechanism", ""), r.get("per_stage", ""), r.get("over_claim", ""))
    print(f"cell {s['cell']}  rep {s['rep']}  scope live={s['scope_live']} offline={s['scope_offline']}  "
          f"U={s['u_ppm']}ppm Q={s['q_cap']} bg={s['bg_pps']}pps deadline={s['deadline_ms']}ms")
    print(f"  P_chain        {fmt_ci(s['P_chain'])}  ({s['chain_ok']}/{s['chain_trials']})  "
          f"S1 {fmt_ci(s['P_chain_by_family']['S1'])}  S4 {fmt_ci(s['P_chain_by_family']['S4'])}  S7 {fmt_ci(s['P_chain_by_family']['S7'])}")
    print(f"  partial ok     {fmt_ci(s['partial_ok'])}   benign alarms {fmt_ci(s['benign_alarm_rate'])} (n={s['benign_trials']})")
    print("  stage recall   " + "  ".join(f"{k}:{fmt_ci(v)}" for k, v in s["stage_recall"].items()))
    print(f"  mechanisms     {s['mechanisms']}  wrong links {s['wrong_links']}  over-claims {s['over_claims']}")
    print(f"  latency        {s['latency_ms']}")
    print(f"  pipeline       {s['pipeline']}")
    print(f"  sampling       {s['sampling']}")
    print(f"  forwarding     {s['forwarding']}")
    print(f"  peak           {s['peak']}")
    print(f"  ingress        {s['ingress']}   (tester logs vs. source-zone events)")
    print(f"  invalid trials {s['trials_invalid'] or 0}   S4 write gap {s['s4_write_gap_ms']}")
    print(f"  fano           {s['fano']}")
    for w in ("warning", "warning_u"):
        if w in s:
            print("  WARNING:", s[w])
    if a.json:
        with open(a.json, "w") as f:
            json.dump({"summary": s, "trials": rows}, f, indent=1, default=str)


if __name__ == "__main__":
    main()
