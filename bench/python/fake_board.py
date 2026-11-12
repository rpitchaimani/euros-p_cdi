"""fake_board.py -- localhost emulation of the ChainRecon firmware, for testing
the host tools (run_bench.py, analyze.py) without the MPC5748G.

It speaks the same UDP protocols (DoIP 13400, control 13499, sink 30490) and
fills the same shared-memory layout that PEEK reads.  The CAN bus, the target
ECU and the IDS core are simulated in one event loop; IDS per-event cost is a
fixed simulated value (--w-us), so U sweeps behave like the firmware's limiter.
It is NOT evidence about the hardware.  Never report numbers from it.

  python fake_board.py --w-us 3            # then: run_bench.py --gw 127.0.0.1 ...
"""
from __future__ import annotations

import argparse
import select
import socket
import struct
import time

import bench_proto as bp

CTL = bp.CTL_FIELDS


class Board:
    def __init__(self, ip: str, w_us: float, can_ms: float):
        self.mem = bytearray(bp.SHARED_SIZE)
        self.t0 = time.perf_counter_ns()
        self.w_ticks = int(w_us * 40)
        self.can_ms = can_ms
        self.socks = {}
        for port in (bp.DOIP_PORT, bp.CTRL_PORT, bp.BG_PORT):
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.bind((ip, port))
            s.setblocking(False)
            self.socks[port] = s
        self.timers = []             # (due_ns, fn)
        self.reset_trial_state()
        self.set("layout_ver", 0x00020001)
        for k in ("c0_ready", "c1_ready", "c2_ready"):
            self.set(k, {"c0_ready": 0xCAFEBABE, "c1_ready": 0xDEADF00D, "c2_ready": 0x7A26E7C2}[k])
        self.mask = 0
        self.u_ppm, self.qcap, self.impact_ms = 1_000_000, 1024, 5
        self.active = False

    # ---- memory helpers ----
    def stm(self) -> int:
        return ((time.perf_counter_ns() - self.t0) * 40 // 1000) & 0xFFFFFFFF

    def set(self, k, v):
        struct.pack_into(">I", self.mem, CTL[k], v & 0xFFFFFFFF)

    def get(self, k):
        return struct.unpack_from(">I", self.mem, CTL[k])[0]

    def inc(self, k, n=1):
        self.set(k, self.get(k) + n)

    def reset_trial_state(self):
        self.seq = 0
        self.sess = []                  # dicts
        self.pend = []
        self.route_seq = 0
        self.ring = []
        self.q = []
        self.wstart = self.stm()
        self.busy = 0
        self.w = dict(arr=0, proc=0, drop=0)
        self.target = dict(dsess=1, unlocked=0, state=0, seed=0, cnt=0)

    # ---- observers (core 1) ----
    def emit(self, obs, kind, d: bytes, bg=False):
        self.seq += 1
        e = dict(seq=self.seq, t_obs=self.stm(), obs=obs, kind=kind, flags=1 if bg else 0, d=d)
        self.inc({1: "prod_src", 2: "prod_gw", 3: "prod_dst"}[obs])
        if not (self.mask & (1 << obs)):
            self.inc({1: "masked_src", 2: "masked_gw", 3: "masked_dst"}[obs])
            e["status"] = 2
        elif len(self.ring) >= 255:
            self.inc({1: "ringfull_src", 2: "ringfull_gw", 3: "ringfull_dst"}[obs])
            e["status"] = 3
        else:
            e["status"] = 1
            self.ring.append(e)
        if not bg:
            n = self.get("dlog_n")
            if n < bp.DLOG_SLOTS:
                struct.pack_into(">IIBBBB", self.mem, bp.OFF_DLOG + n * 32, e["seq"], e["t_obs"],
                                 obs, kind, e["flags"], e["status"])
                self.mem[bp.OFF_DLOG + n * 32 + 12: bp.OFF_DLOG + n * 32 + 32] = d.ljust(20, b"\0")[:20]
                self.set("dlog_n", n + 1)

    def obs_src(self, data: bytes, addr, dport):
        d = bytearray(20)
        d[0:4] = socket.inet_aton(addr[0])
        struct.pack_into(">HH", d, 4, addr[1], dport)
        kind, bg = bp.EK_ETH_OTHER, True
        if dport == bp.DOIP_PORT and len(data) >= 8:
            kind, bg = bp.EK_ETH_DOIP, False
            d[8:10] = data[2:4]
            d[10:12] = data[6:8]
            pl = data[8:16]
            d[12:12 + len(pl)] = pl
        self.emit(bp.OBS_SRC, kind, bytes(d), bg)

    def gw_log(self, kind, s, ip, port, sa, ta, dec, why, sid=0, sub=0, did=0, rseq=0):
        d = bytearray(20)
        d[0:4] = socket.inet_aton(ip) if ip else b"\0\0\0\0"
        struct.pack_into(">HHH", d, 4, port, sa, ta)
        d[10], d[11], d[12], d[13] = dec, why, sid, sub
        struct.pack_into(">H", d, 14, did)
        d[16] = s["auth"] if s else 0
        d[17] = s["dsess"] if s else 0
        struct.pack_into(">H", d, 18, rseq)
        self.emit(bp.OBS_GW, kind, bytes(d))

    # ---- CAN bus ----
    def can_tx(self, cid, data8: bytes):
        self.timers.append((time.perf_counter_ns() + int(self.can_ms * 1e6), lambda: self.can_rx(cid, data8)))

    def can_rx(self, cid, data):
        self.inc("can_rx")
        d = bytearray(20)
        struct.pack_into(">IB", d, 0, cid, 8)
        d[5:13] = data
        self.emit(bp.OBS_DST, bp.EK_CAN, bytes(d),
                  bg=cid not in (bp.CANID_DIAG_REQ, bp.CANID_DIAG_RESP, bp.CANID_IMPACT, bp.CANID_SYNC))
        if cid == bp.CANID_DIAG_REQ:
            self.target_handle(data)
        elif cid == bp.CANID_DIAG_RESP:
            self.route_response(data)

    # ---- target (core 2) ----
    def t_reply(self, uds: bytes):
        f = bytes([len(uds)]) + uds
        self.can_tx(bp.CANID_DIAG_RESP, f.ljust(8, b"\xcc"))

    def target_handle(self, f):
        t = self.target
        n = f[0] & 0x0F
        u = f[1:1 + n]
        sid = u[0]
        if sid == 0x10:
            t["dsess"] = u[1]
            if u[1] != 3:
                t["unlocked"] = 0
            self.t_reply(bytes([0x50, u[1], 0, 0x32, 1, 0xF4]))
        elif sid == 0x3E:
            self.t_reply(b"\x7e\x00")
        elif sid == 0x27:
            if t["dsess"] != 3:
                self.t_reply(bytes([0x7F, 0x27, 0x7F]))
            elif u[1] == 1:
                t["seed"] = (self.stm() >> 4) & 0xFFFF or 0x1234
                self.t_reply(bytes([0x67, 1, t["seed"] >> 8, t["seed"] & 0xFF]))
            elif u[1] == 2:
                key = (u[2] << 8) | u[3]
                if key == t["seed"] ^ bp.SA_KEY_XOR:
                    t["unlocked"] = 1
                    self.t_reply(b"\x67\x02")
                else:
                    self.t_reply(b"\x7f\x27\x35")
        elif sid == 0x22:
            self.t_reply(bytes([0x62, u[1], u[2], t["state"]]))
        elif sid == 0x2E:
            if (u[1] << 8 | u[2]) == bp.DID_TEST_STATE:
                if t["dsess"] != 3:
                    self.t_reply(b"\x7f\x2e\x22")
                    return
                t["state"] = u[3]
                self.set("c2_state", u[3])
                self.t_reply(bytes([0x6E, u[1], u[2]]))

                def impact(v=u[3]):
                    t["cnt"] += 1
                    self.set("c2_impacts", t["cnt"])
                    self.can_tx(bp.CANID_IMPACT, bytes([v, t["cnt"], 0, 0, 0, 0, 0, 0]))
                self.timers.append((time.perf_counter_ns() + self.impact_ms * 1_000_000, impact))
            else:
                self.t_reply(b"\x7f\x2e\x33" if not t["unlocked"] else b"\x7f\x2e\x31")
        else:
            self.t_reply(bytes([0x7F, sid, 0x11]))

    # ---- gateway (core 1) ----
    def doip_send(self, addr, ptype, pl: bytes):
        self.socks[bp.DOIP_PORT].sendto(struct.pack(">BBHI", 2, 0xFD, ptype, len(pl)) + pl, addr)

    def find_sess(self, ip, port):
        for i, s in enumerate(self.sess):
            if s["ip"] == ip and s["port"] == port:
                return i
        return -1

    def handle_doip(self, b: bytes, addr):
        ip, port = addr
        if len(b) < 8 or b[0] != 2 or b[1] != 0xFD:
            return
        ptype, plen = struct.unpack_from(">HI", b, 2)
        pl = b[8:8 + plen]
        if ptype == bp.DOIP_VIR:
            r = bytearray(33)
            r[0:17] = b"WCHAINRECON000001"
            struct.pack_into(">H", r, 17, bp.LA_GATEWAY)
            self.doip_send(addr, bp.DOIP_VAM, bytes(r))
            self.gw_log(bp.EK_GW_VIR, None, ip, port, 0, bp.LA_GATEWAY, 1, 0)
        elif ptype == bp.DOIP_RA_REQ and len(pl) >= 7:
            sa, = struct.unpack_from(">H", pl, 0)
            si = self.find_sess(ip, port)
            if si < 0:
                self.sess.append(dict(ip=ip, port=port, sa=0, active=0, auth=0, dsess=1))
                si = len(self.sess) - 1
            s = self.sess[si]
            ok = 0x0E00 <= sa <= 0x0EFF
            if ok:
                s.update(sa=sa, active=1)
            self.doip_send(addr, bp.DOIP_RA_RESP, struct.pack(">HHB4x", sa, bp.LA_GATEWAY, 0x10 if ok else 0))
            self.gw_log(bp.EK_GW_RA, s if ok else None, ip, port, sa, bp.LA_GATEWAY, 1 if ok else 3, 0 if ok else 6)
        elif ptype == bp.DOIP_DIAG and len(pl) >= 5:
            sa, ta = struct.unpack_from(">HH", pl, 0)
            uds = pl[4:]
            sid = uds[0]
            sub = uds[1] if len(uds) > 1 else 0
            did = (uds[1] << 8 | uds[2]) if len(uds) > 2 else 0
            si = self.find_sess(ip, port)
            if si < 0 or not self.sess[si]["active"] or self.sess[si]["sa"] != sa:
                self.doip_send(addr, bp.DOIP_DIAG_NACK, struct.pack(">HHB", ta, sa, 2))
                self.gw_log(bp.EK_GW_ROUTE, None, ip, port, sa, ta, 3, 1, sid, sub, did)
                return
            s = self.sess[si]
            dec, why = 3, 0
            if ta == bp.LA_OTHER_ZONE:
                why = 2
            elif ta != bp.LA_TARGET:
                why = 3
            elif sid in (0x10, 0x3E, 0x22, 0x27):
                dec = 1
            elif sid == 0x2E:
                if s["auth"]:
                    dec = 1
                elif did == bp.DID_TEST_STATE:
                    dec, why = 2, 5
                else:
                    why = 5
            else:
                why = 4
            if dec == 3:
                self.doip_send(addr, bp.DOIP_DIAG_NACK, struct.pack(">HHB", ta, sa, 3 if why == 3 else 6))
                self.gw_log(bp.EK_GW_ROUTE, s, ip, port, sa, ta, dec, why, sid, sub, did)
                return
            self.doip_send(addr, bp.DOIP_DIAG_ACK, struct.pack(">HHB", ta, sa, 0))
            self.route_seq += 1
            self.pend.append(dict(sess=si, rseq=self.route_seq))
            self.gw_log(bp.EK_GW_ROUTE, s, ip, port, sa, ta, dec, why, sid, sub, did, self.route_seq)
            self.can_tx(bp.CANID_DIAG_REQ, (bytes([len(uds)]) + uds).ljust(8, b"\xcc"))
            self.inc("fwd_eth")

    def route_response(self, data):
        n = data[0] & 0x0F
        uds = data[1:1 + n]
        if not self.pend:
            self.gw_log(bp.EK_GW_RESP_ORPHAN, None, None, 0, bp.LA_TARGET, 0, 3, 0, uds[0], uds[1] if n > 1 else 0)
            return
        p = self.pend.pop(0)
        s = self.sess[p["sess"]]
        if uds[0] == 0x67 and n >= 2 and uds[1] == 2:
            s["auth"] = 1
        if uds[0] == 0x50:
            s["dsess"] = uds[1]
        self.doip_send((s["ip"], s["port"]), bp.DOIP_DIAG, struct.pack(">HH", bp.LA_TARGET, s["sa"]) + uds)
        self.gw_log(bp.EK_GW_RESP, s, s["ip"], s["port"], bp.LA_TARGET, s["sa"], 1, 0,
                    uds[0], uds[1] if n > 1 else 0, (uds[1] << 8 | uds[2]) if n > 3 else 0, p["rseq"])
        self.inc("fwd_can")

    # ---- control ----
    def handle_ctrl(self, b: bytes, addr):
        s = self.socks[bp.CTRL_PORT]
        c = b[:1]
        if c == b"H":
            s.sendto(b"h" + struct.pack(">IBBBI", 0x00020001, 1, 1, 1, self.stm()), addr)
        elif c == b"S" and len(b) >= 26:
            tid, u, mask, q, dl, imp, hns = struct.unpack_from(">IIBHIHQ", b, 1)
            seq = self.get("trial_seq") + 1
            for k in [k for k in CTL if k not in ("c0_ready", "c1_ready", "c2_ready", "layout_ver", "end_seq", "c0_end_ack")]:
                self.set(k, 0)
            self.set("layout_ver", 0x00020001)
            self.set("trial_seq", seq)
            self.set("c0_trial_ack", seq)
            self.set("c2_trial_ack", seq)
            for k, v in (("trial_id", tid), ("u_ppm", u), ("obs_mask", mask), ("q_cap", q),
                         ("deadline_ms", dl), ("impact_ms", imp)):
                self.set(k, v)
            self.u_ppm, self.qcap, self.impact_ms = min(u, 1_000_000), (q or 1024), imp
            self.reset_trial_state()
            self.mask = mask
            self.active = True
            self.set("t_start", self.stm())
            sync = struct.pack(">II", tid, self.get("t_start"))
            self.can_tx(bp.CANID_SYNC, sync)
            self.set("t_cansync", self.stm())
            s.sendto(b"A\x00" + struct.pack(">III", seq, self.get("t_start"), self.get("t_cansync")), addr)
        elif c == b"E":
            self.set("t_end", self.stm())
            self.mask = 0
            self.ingest()
            self.window_close()
            self.set("c0_unproc_end", len(self.q))
            self.active = False
            seq = self.get("end_seq") + 1
            self.set("end_seq", seq)
            self.set("c0_end_ack", seq)
            s.sendto(b"F\x00" + struct.pack(">II", seq, self.get("t_end")), addr)
        elif c == b"P" and len(b) >= 7:
            off, n = struct.unpack_from(">IH", b, 1)
            n = min(n, 1024, bp.SHARED_SIZE - off)
            s.sendto(b"D" + struct.pack(">IH", off, n) + bytes(self.mem[off:off + n]), addr)

    # ---- IDS (core 0) ----
    def log_new(self, e, t_ing, status):
        n = self.get("c0_log_n")
        if n >= bp.IDSLOG_SLOTS:
            self.inc("c0_log_ovf")
            return None
        struct.pack_into(">IIIBBBB", self.mem, bp.OFF_IDSLOG + n * 16, e["seq"], t_ing, 0, e["obs"], status, 0, 0xFF)
        self.set("c0_log_n", n + 1)
        return n

    def ingest(self):
        while self.ring:
            e = self.ring.pop(0)
            t = self.stm()
            self.inc("c0_ing")
            self.w["arr"] += 1
            if len(self.q) < self.qcap:
                e["log"] = None if e["flags"] & 1 else self.log_new(e, t, 2)
                self.q.append(e)
                self.inc("c0_admit")
                if len(self.q) > self.get("c0_max_backlog"):
                    self.set("c0_max_backlog", len(self.q))
            else:
                self.inc("c0_admit_drop")
                self.w["drop"] += 1
                if not e["flags"] & 1:
                    self.log_new(e, t, 3)

    def process(self):
        budget = self.u_ppm * 4
        while self.q and self.busy < budget:
            e = self.q.pop(0)
            self.busy += self.w_ticks
            self.set("c0_wcet_ticks", max(self.get("c0_wcet_ticks"), self.w_ticks))
            if e.get("log") is not None:
                base = bp.OFF_IDSLOG + e["log"] * 16
                struct.pack_into(">I", self.mem, base + 8, self.stm())   # t_proc
                self.mem[base + 13] = 1                                    # status = processed
            self.w["proc"] += 1
            self.inc("c0_proc")

    def window_close(self):
        if self.active:
            n = self.get("c0_wlog_n")
            if n < bp.WLOG_SLOTS:
                struct.pack_into(">HHHHI", self.mem, bp.OFF_WLOG + n * 12, self.w["arr"] & 0xFFFF,
                                 self.w["proc"] & 0xFFFF, self.w["drop"] & 0xFFFF, len(self.q) & 0xFFFF, self.busy)
                self.set("c0_wlog_n", n + 1)
            self.inc("c0_windows")
            self.inc("c0_busy_ticks", self.busy)
        self.busy = 0
        self.w = dict(arr=0, proc=0, drop=0)

    # ---- main loop ----
    def run(self):
        print("fake board up (NOT hardware evidence)")
        while True:
            r, _, _ = select.select(list(self.socks.values()), [], [], 0.0005)
            for s in r:
                port = s.getsockname()[1]
                try:
                    data, addr = s.recvfrom(4096)
                except (BlockingIOError, ConnectionResetError):
                    continue
                if port != bp.CTRL_PORT:
                    self.inc("enet_rx")
                    self.obs_src(data, addr, port)
                if port == bp.DOIP_PORT:
                    self.handle_doip(data, addr)
                elif port == bp.CTRL_PORT:
                    self.handle_ctrl(data, addr)
            now = time.perf_counter_ns()
            due = [t for t in self.timers if t[0] <= now]
            self.timers = [t for t in self.timers if t[0] > now]
            for _, fn in sorted(due, key=lambda t: t[0]):
                fn()
            self.ingest()
            if self.active:
                self.process()
            while ((self.stm() - self.wstart) & 0xFFFFFFFF) >= 4_000_000:
                self.window_close()
                self.wstart = (self.wstart + 4_000_000) & 0xFFFFFFFF


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--ip", default="127.0.0.1")
    ap.add_argument("--w-us", type=float, default=3.0, help="simulated IDS cost per event")
    ap.add_argument("--can-ms", type=float, default=0.3, help="simulated CAN frame latency")
    a = ap.parse_args()
    Board(a.ip, a.w_us, a.can_ms).run()


if __name__ == "__main__":
    main()
