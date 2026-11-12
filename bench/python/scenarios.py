"""scenarios.py -- scenario families S1-S6 for the chain-reconstruction study.

Every scenario returns its ground truth: which sessions exist, which one (if
any) is malicious, and which stages the malicious chain is *supposed* to
reach.  Whether a stage was actually reached is read later from the reference
evidence (complete delivery log + PEAK capture), never from the script.

Stages of the bench chain (protocol section 2):
  1 discovery      VIR answered, then the session activates routing
  2 unauth. diag   write to DID F1A0 without SecurityAccess (gateway AUDIT)
  3 cross-zone     that request routed onto CAN 0x7E0
  4 target         target positive response 6E F1 A0 and state change
  5 impact         target test message 0x1A0 carrying the written value
"""
from __future__ import annotations

import random
import threading
import time

from bench_proto import LA_OTHER_ZONE, LA_TARGET, LA_TARGET_B
from doip_tester import Tester

# Every session draws its tester logical address from one pool, so the
# address itself never tells the attacker from benign equipment.
SA_POOL = tuple(range(0x0E00, 0x0E10))

MALICIOUS = {"S1", "S2", "S3", "S4", "S7"}
EXPECTED_STAGES = {"S1": 5, "S2": 3, "S3": 2, "S4": 5, "S5": 0, "S6": 0, "S7": 5}
# S7: attacker and an authorised benign tester write the test state of two
# DIFFERENT target ECUs (A/B, chosen at random) at the same moment; both writes
# drive the shared actuator message 0x1A0.  Whether the impacts can be told
# apart depends on the trial: --impact-src (ECU id in the frame) and
# --same-value; the target adds random impact jitter (--jitter-ms).


def _sleep_ms(ms: float):
    if ms > 0:
        time.sleep(ms / 1000.0)


# ---------------- tester programmes ----------------
def prog_attacker(t: Tester, value: int, session: int = 0x03, ta: int = LA_TARGET,
                  gap_ms: float = 20.0, before_write=None):
    t.vir()
    _sleep_ms(gap_ms)
    t.ra()
    _sleep_ms(gap_ms)
    t.diag(bytes([0x10, session]), ta=ta)
    _sleep_ms(gap_ms)
    if before_write:
        before_write()
    t.diag(bytes([0x2E, 0xF1, 0xA0, value]), ta=ta)


def prog_benign_write(t: Tester, value: int, gap_ms: float = 20.0, discover: bool = False,
                      before_write=None, ta: int = LA_TARGET):
    if discover:
        t.vir()
        _sleep_ms(gap_ms)
    t.ra()
    _sleep_ms(gap_ms)
    t.diag(bytes([0x10, 0x03]), ta=ta)
    _sleep_ms(gap_ms)
    # The target holds one seed: concurrent sessions can overwrite each other's
    # seed and the key is then refused.  A real tester retries; it never writes
    # without SecurityAccess, so a benign session never commits a violation.
    unlocked = False
    for _ in range(4):
        if t.unlock(ta=ta):
            unlocked = True
            break
        _sleep_ms(random.uniform(5, 25))
    _sleep_ms(gap_ms)
    if before_write:
        before_write()
    if unlocked:
        t.diag(bytes([0x2E, 0xF1, 0xA0, value]), ta=ta)
        _sleep_ms(gap_ms)
    t.diag(bytes([0x22, 0xF1, 0xA0]), ta=ta)


def prog_benign_read(t: Tester, gap_ms: float = 20.0, discover: bool = True):
    if discover:
        t.vir()
        _sleep_ms(gap_ms)
    t.ra()
    _sleep_ms(gap_ms)
    t.diag(bytes([0x10, 0x03]))
    _sleep_ms(gap_ms)
    t.diag(bytes([0x22, 0xF1, 0xA0]))
    _sleep_ms(gap_ms)
    t.diag(bytes([0x3E, 0x00]))


# ---------------- scenario runner ----------------
def run_scenario(name: str, gw_ip: str, rng: random.Random, bind_ip: str = "",
                 same_value: bool = False, overlap_ms: float = 15.0) -> dict:
    """Execute one scenario; returns ground truth and all tester logs."""
    testers: list[Tester] = []
    gt = {"scenario": name, "malicious": name in MALICIOUS,
          "expected_stages": EXPECTED_STAGES[name], "sessions": []}

    sas = rng.sample(SA_POOL, 4)

    def mk(label: str, _unused: int, role: str) -> Tester:
        sa = sas[len(testers)]
        t = Tester(label, gw_ip, sa, bind_ip=bind_ip)
        testers.append(t)
        gt["sessions"].append({"name": label, "sa": sa, "port": t.port, "role": role})
        return t

    v_att = rng.randrange(1, 255)
    v_ben = v_att if same_value else (v_att + rng.randrange(1, 254)) % 255 + 1
    gt["values"] = {"attacker": v_att, "benign": v_ben}

    try:
        if name == "S1":                         # complete malicious chain
            a = mk("attacker", 0, "malicious")
            prog_attacker(a, v_att)
        elif name == "S2":                       # partial: target rejects (default session)
            a = mk("attacker", 0, "malicious")
            prog_attacker(a, v_att, session=0x01)
        elif name == "S3":                       # denied cross-zone attempt
            a = mk("attacker", 0, "malicious")
            prog_attacker(a, v_att, ta=LA_OTHER_ZONE)
        elif name == "S4":                       # benign write overlapping the attack
            a = mk("attacker", 0, "malicious")
            b = mk("benign", 0, "benign")
            # Both sessions prepare independently, meet at a barrier, then send
            # their writes with a drawn offset in [-overlap, +overlap] ms, so the
            # overlap does not depend on round-trip times.
            lead = rng.uniform(-overlap_ms, overlap_ms)      # >0: attacker writes later
            b_disc = rng.random() < 0.5          # discovery alone must not reveal the attacker
            gt["s4_lead_ms"] = lead
            gt["s4_benign_discovers"] = b_disc
            bar = threading.Barrier(2, timeout=5.0)

            def at_barrier(delay_ms):
                def f():
                    try:
                        bar.wait()
                    except threading.BrokenBarrierError:
                        pass
                    _sleep_ms(delay_ms)
                return f
            ta_ = threading.Thread(target=prog_attacker, args=(a, v_att),
                                   kwargs={"before_write": at_barrier(max(0.0, lead))})
            tb_ = threading.Thread(target=prog_benign_write, args=(b, v_ben),
                                   kwargs={"discover": b_disc, "before_write": at_barrier(max(0.0, -lead))})
            ta_.start(); tb_.start()
            ta_.join(); tb_.join()
        elif name == "S7":                       # two ECUs, one shared actuator message
            a = mk("attacker", 0, "malicious")
            b = mk("benign", 0, "benign")
            ta_att = LA_TARGET if rng.random() < 0.5 else LA_TARGET_B
            ta_ben = LA_TARGET_B if ta_att == LA_TARGET else LA_TARGET
            lead = rng.uniform(-overlap_ms, overlap_ms)
            b_disc = rng.random() < 0.5
            gt.update(s7_ta_attacker=ta_att, s7_ta_benign=ta_ben, s4_lead_ms=lead,
                      s4_benign_discovers=b_disc)
            bar = threading.Barrier(2, timeout=5.0)

            def at_barrier7(delay_ms):
                def f():
                    try:
                        bar.wait()
                    except threading.BrokenBarrierError:
                        pass
                    _sleep_ms(delay_ms)
                return f
            ta_ = threading.Thread(target=prog_attacker, args=(a, v_att),
                                   kwargs={"ta": ta_att, "before_write": at_barrier7(max(0.0, lead))})
            tb_ = threading.Thread(target=prog_benign_write, args=(b, v_ben),
                                   kwargs={"discover": b_disc, "ta": ta_ben,
                                           "before_write": at_barrier7(max(0.0, -lead))})
            ta_.start(); tb_.start()
            ta_.join(); tb_.join()
        elif name == "S5":                       # several benign sessions, similar patterns
            bs = [mk(f"benign{i}", 0, "benign") for i in range(3)]
            ths = [threading.Thread(target=prog_benign_write, args=(bs[0], v_ben)),
                   threading.Thread(target=prog_benign_write, args=(bs[1], (v_ben % 254) + 1)),
                   threading.Thread(target=prog_benign_read, args=(bs[2],))]
            for i, th in enumerate(ths):
                th.start()
                _sleep_ms(rng.uniform(0, 30))
            for th in ths:
                th.join()
        elif name == "S6":                       # same destination event, benign cause
            b = mk("benign", 0, "benign")
            prog_benign_write(b, v_ben, discover=True)
        else:
            raise ValueError(name)
    finally:
        logs = []
        for t in testers:
            logs.extend(t.log)
            t.close()
    gt["tester_log"] = logs
    return gt
