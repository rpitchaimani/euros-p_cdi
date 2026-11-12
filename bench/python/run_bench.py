"""run_bench.py -- run one experimental cell on the ChainRecon bench.

A cell fixes: observer scope (mask), IDS CPU share U, IDS queue capacity Q,
background load, scenario mix (fixed in advance), deadline, trial count, seed.
Each trial: START (resets all cores, CAN sync beacon) -> PEAK capture and
background load running -> scenario -> settle -> END -> dump logs -> JSON.

Examples (Git Bash, from chainrecon/python):
  python run_bench.py --gw 192.168.10.1 --bind 192.168.10.100 hello
  python run_bench.py --gw 192.168.10.1 --bind 192.168.10.100 cell \
      --name E3_all_U100 --scope all --u-ppm 1000000 --trials 30 \
      --mix S1:0.25,S4:0.25,S5:0.25,S6:0.25 --bg-pps 0 --peak PCAN_USBBUS1
  python run_bench.py ... cell --name E5_U02 --scope all --u-ppm 2000 --bg-pps 2000 ...
  python run_bench.py ... baseline --hours 8 --bg-pps 500     # B0, benign only

Output: runs/<name>/cell.json and runs/<name>/trial_XXXX.json
"""
from __future__ import annotations

import argparse
import json
import os
import random
import socket
import struct
import sys
import threading
import time

import bench_proto as bp
from scenarios import run_scenario

HERE = os.path.dirname(os.path.abspath(__file__))


# ---------------- background load ----------------
class BgLoad(threading.Thread):
    """Fixed-rate UDP datagrams to the gateway sink port (observed as BG)."""

    def __init__(self, gw_ip: str, pps: int, bind_ip: str = "", size: int = 64):
        super().__init__(daemon=True)
        self.addr, self.pps, self.size = (gw_ip, bp.BG_PORT), pps, size
        self.s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.s.bind((bind_ip, 0))
        self.stop_ev = threading.Event()
        self.sent = 0

    def run(self):
        if self.pps <= 0:
            return
        tick = 0.01                                   # 10 ms bursts
        per_tick = self.pps * tick
        acc, nxt = 0.0, time.perf_counter()
        payload = bytes(self.size)
        while not self.stop_ev.is_set():
            acc += per_tick
            n = int(acc)
            acc -= n
            for _ in range(n):
                self.s.sendto(payload, self.addr)
            self.sent += n
            nxt += tick
            d = nxt - time.perf_counter()
            if d > 0:
                time.sleep(d)
            else:
                nxt = time.perf_counter()

    def stop(self):
        self.stop_ev.set()
        self.join(timeout=1.0)
        self.s.close()


# ---------------- PEAK reference capture ----------------
class PeakBus(threading.Thread):
    """Independent CAN reference via PCAN-USB (python-can), opened once per
    cell.  It is also the bus's only other ACKing node: FlexCAN_0 frames are not
    acknowledged (and every can_tx times out) without it.  Normal mode, never
    transmits data frames."""

    def __init__(self, channel: str | None):
        super().__init__(daemon=True)
        self.bus, self.err = None, None
        self.lock = threading.Lock()
        self.buf: list[dict] = []
        self.rec = False
        self.stop_ev = threading.Event()
        if channel:
            try:
                import can  # noqa
                self.bus = can.Bus(interface="pcan", channel=channel, bitrate=500000)
            except Exception as ex:  # pragma: no cover - hardware only
                self.err = f"PEAK open failed: {ex}"
        self.start()

    def run(self):
        if not self.bus:
            return
        while not self.stop_ev.is_set():
            m = self.bus.recv(timeout=0.1)
            if m is None or m.is_error_frame:
                continue
            with self.lock:
                if self.rec:
                    self.buf.append({"t": m.timestamp, "t_host_ns": time.perf_counter_ns(),
                                     "id": m.arbitration_id, "dlc": m.dlc,
                                     "data": bytes(m.data).hex()})

    def begin(self):
        with self.lock:
            self.buf, self.rec = [], True

    def end(self) -> list[dict]:
        time.sleep(0.05)                       # let the driver queue drain
        with self.lock:
            self.rec = False
            out, self.buf = self.buf, []
        return out

    def close(self):
        self.stop_ev.set()
        self.join(timeout=1.0)
        if self.bus:
            self.bus.shutdown()


# ---------------- helpers ----------------
MIX_ALIASES = {
    "LOW": "S1:0.4,S2:0.1,S3:0.1,S6:0.4",     # one session per trial
    "HIGH": "S4:0.5,S5:0.5",                  # overlapping sessions
    "TWO": "S7:0.5,S5:0.5",                   # two ECUs, shared actuator message
}


def parse_mix(s: str) -> list[tuple[str, float]]:
    s = MIX_ALIASES.get(s, s)
    out = []
    for part in s.split(","):
        k, v = part.split(":")
        out.append((k.strip(), float(v)))
    tot = sum(v for _, v in out)
    return [(k, v / tot) for k, v in out]


def schedule(mix, n, rng):
    """Exact proportions (largest remainder), shuffled: the mix is fixed in advance."""
    raw = [(k, p * n) for k, p in mix]
    cnt = {k: int(x) for k, x in raw}
    rest = n - sum(cnt.values())
    for k, x in sorted(raw, key=lambda kx: kx[1] - int(kx[1]), reverse=True)[:rest]:
        cnt[k] += 1
    seq = [k for k, c in cnt.items() for _ in range(c)]
    rng.shuffle(seq)
    return seq


def decode_dump(d: dict) -> dict:
    d["dlog"] = [bp.decode_event(e) for e in d["dlog"]]
    for e in d["dlog"]:
        e["d"] = e["d"].hex()
    return d


def one_trial(ctl: bp.Ctl, peak: PeakBus, args, trial_id: int, scen: str, rng: random.Random) -> dict:
    peak.begin()
    bg = BgLoad(args.gw, args.bg_pps, args.bind)
    st = ctl.start(trial_id, args.u_ppm, bp.SCOPES[args.scope], args.q_cap,
                   args.deadline_ms, args.impact_ms,
                   flags=bp.CFGF_IMPACT_SRC if args.impact_src == "on" else 0,
                   jitter_ms=args.jitter_ms, seed=trial_id & 0xFFFFFFFF or 1)
    if not st.ok:
        print("  ! START: a core did not acknowledge (continuing, flagged)")
    bg.start()
    time.sleep(args.pre_ms / 1000.0)
    t_scen0 = time.perf_counter_ns()
    gt = run_scenario(scen, args.gw, rng, bind_ip=args.bind,
                      same_value=args.same_value, overlap_ms=args.overlap_ms)
    t_scen1 = time.perf_counter_ns()
    time.sleep(args.settle_ms / 1000.0)
    end = ctl.end()
    bg.stop()
    frames = peak.end()
    dump = decode_dump(ctl.dump())
    return {
        "trial_id": trial_id, "scenario": scen, "gt": gt,
        "start": st.__dict__, "end": end, "t_scen0": t_scen0, "t_scen1": t_scen1,
        "bg_sent": bg.sent, "peak": frames, "peak_err": peak.err, "dump": dump,
    }


def cmd_cell(args):
    out_dir = os.path.join(args.out, args.name)
    os.makedirs(out_dir, exist_ok=True)
    rng = random.Random(args.seed)
    mix = parse_mix(args.mix)
    plan = schedule(mix, args.trials, rng)
    cell = {k: v for k, v in vars(args).items() if k != "func"}
    cell.update({"mix_norm": mix, "plan": plan, "obs_mask": bp.SCOPES[args.scope],
                 "created": time.strftime("%Y-%m-%d %H:%M:%S")})
    with open(os.path.join(out_dir, "cell.json"), "w") as f:
        json.dump(cell, f, indent=1)
    if ctl_flags_dev(args):
        print("!! board runs the INTERNAL CAN LOOPBACK dev build: runs are dev-only, never results")
    if not args.peak and not args.no_peak:
        sys.exit("--peak is required: the PEAK is the CAN reference and the only other ACKing "
                 "node on the bus.  Use --no-peak only for the fake board.")
    peak = PeakBus(args.peak)
    if peak.err:
        peak.close()
        sys.exit(peak.err)
    ctl = bp.Ctl(args.gw, bind_ip=args.bind)
    print("hello:", ctl.hello())
    try:
        for i, scen in enumerate(plan):
            tid = args.seed * 10000 + i
            path = os.path.join(out_dir, f"trial_{i:04d}.json")
            if os.path.exists(path) and not args.overwrite:
                continue
            r = one_trial(ctl, peak, args, tid, scen, random.Random(tid))
            c = r["dump"]["ctl"]
            flag = "" if c["can_tx_to"] == 0 else f"  !! CAN TX timeouts={c['can_tx_to']} (ACK? termination?)"
            print(f"[{i + 1}/{len(plan)}] {scen} dlog={c['dlog_n']} ids={c['c0_log_n']} "
                  f"proc={c['c0_proc']} drop={c['c0_admit_drop']} unproc={c['c0_unproc_end']} "
                  f"peak={len(r['peak'])} impacts={c['c2_impacts']}{flag}")
            with open(path, "w") as f:
                json.dump(r, f)
            time.sleep(args.gap_ms / 1000.0)
    finally:
        peak.close()


def ctl_flags_dev(args) -> bool:
    try:
        c = bp.parse_ctl(bp.Ctl(args.gw, bind_ip=args.bind).peek(bp.OFF_CTL, bp.CTL_LEN))
        return bool(c.get("build_flags", 0) & bp.BUILD_FLAG_CAN_INTERNAL_LOOPBACK)
    except Exception:
        return False


def cmd_baseline(args):
    args.mix = "S5:0.5,S6:0.5"
    args.trials = max(1, int(args.hours * 3600 / max(1.0, (args.pre_ms + args.settle_ms) / 1000 + 1.5)))
    cmd_cell(args)


def cmd_hello(args):
    ctl = bp.Ctl(args.gw, bind_ip=args.bind)
    print(ctl.hello())


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--gw", default="192.168.10.1")
    ap.add_argument("--bind", default="", help="local IP of the bench NIC")
    sub = ap.add_subparsers(dest="cmd", required=True)
    h = sub.add_parser("hello")
    h.set_defaults(func=cmd_hello)
    for nm, fn in (("cell", cmd_cell), ("baseline", cmd_baseline)):
        c = sub.add_parser(nm)
        c.add_argument("--name", required=True)
        c.add_argument("--scope", default="all", choices=sorted(bp.SCOPES))
        c.add_argument("--u-ppm", type=int, default=1_000_000, help="IDS CPU share, ppm of T_w")
        c.add_argument("--q-cap", type=int, default=1024)
        c.add_argument("--bg-pps", type=int, default=0)
        c.add_argument("--mix", default="S1:0.25,S4:0.25,S5:0.25,S6:0.25")
        c.add_argument("--trials", type=int, default=30)
        c.add_argument("--hours", type=float, default=8.0)
        c.add_argument("--seed", type=int, default=1)
        c.add_argument("--deadline-ms", type=int, default=1000,
                       help="after the reference impact (or last malicious action)")
        c.add_argument("--impact-ms", type=int, default=5)
        c.add_argument("--impact-src", choices=["on", "off"], default="on",
                       help="impact frame names its ECU (off: only value/timing can link it)")
        c.add_argument("--jitter-ms", type=int, default=0,
                       help="extra random impact delay per write (reorders impacts in S7)")
        c.add_argument("--same-value", action="store_true", help="S4: both sessions write the same value")
        c.add_argument("--overlap-ms", type=float, default=15.0)
        c.add_argument("--pre-ms", type=int, default=300)
        c.add_argument("--settle-ms", type=int, default=1500)
        c.add_argument("--gap-ms", type=int, default=200)
        c.add_argument("--peak", default=None, help="PCAN channel, e.g. PCAN_USBBUS1 (required)")
        c.add_argument("--no-peak", action="store_true", help="fake board only")
        c.add_argument("--out", default=os.path.join(HERE, "..", "runs"))
        c.add_argument("--overwrite", action="store_true")
        c.set_defaults(func=fn)
    args = ap.parse_args(argv)
    args.func(args)


if __name__ == "__main__":
    sys.exit(main())
