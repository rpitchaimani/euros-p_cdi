"""bench_proto.py -- host mirror of include/bench.h and include/shared_mem.h,
plus the bench control client.  Change together with the C headers.
"""
from __future__ import annotations

import socket
import struct
import time
from dataclasses import dataclass

# ---------------- bench.h ----------------
IDS_WINDOW_MS = 100
DOIP_PORT = 13400
CTRL_PORT = 13499
BG_PORT = 30490            # background load (host -> gateway), not DoIP

DOIP_VIR, DOIP_VAM = 0x0001, 0x0004
DOIP_RA_REQ, DOIP_RA_RESP = 0x0005, 0x0006
DOIP_DIAG, DOIP_DIAG_ACK, DOIP_DIAG_NACK = 0x8001, 0x8002, 0x8003

LA_GATEWAY, LA_TARGET, LA_OTHER_ZONE = 0x1000, 0x0010, 0x0020
LA_TARGET_B = 0x0011
CANID_DIAG_REQ, CANID_DIAG_RESP, CANID_IMPACT, CANID_SYNC = 0x7E0, 0x7E8, 0x1A0, 0x7F0
CANID_DIAG_REQ_B, CANID_DIAG_RESP_B = 0x7E1, 0x7E9
DIAG_REQ_IDS = (CANID_DIAG_REQ, CANID_DIAG_REQ_B)
DIAG_RESP_IDS = (CANID_DIAG_RESP, CANID_DIAG_RESP_B)
RESP_OF_REQ = {CANID_DIAG_REQ: CANID_DIAG_RESP, CANID_DIAG_REQ_B: CANID_DIAG_RESP_B}
REQ_OF_TA = {LA_TARGET: CANID_DIAG_REQ, LA_TARGET_B: CANID_DIAG_REQ_B}
ECU_OF_REQ = {CANID_DIAG_REQ: 1, CANID_DIAG_REQ_B: 2}
CFGF_IMPACT_SRC = 0x01        # impact frame byte 2 names the ECU (1/2)
DID_TEST_STATE = 0xF1A0
SA_KEY_XOR = 0x5A5A

GWD = {1: "ALLOW", 2: "AUDIT", 3: "DENY"}
GWR = {0: "OK", 1: "NO_RA", 2: "ROUTE_CLOSED", 3: "UNKNOWN_TA", 4: "SID_BLOCKED",
       5: "WRITE_NOAUTH", 6: "BAD_SA"}

EK_ETH_OTHER, EK_ETH_DOIP = 1, 2
EK_GW_VIR, EK_GW_RA, EK_GW_ROUTE, EK_GW_RESP, EK_GW_RESP_ORPHAN = 10, 11, 12, 13, 14
EK_CAN = 20

OBS_SRC, OBS_GW, OBS_DST = 1, 2, 3
OBS_NAME = {OBS_SRC: "src", OBS_GW: "gw", OBS_DST: "dst"}
MASK_ALL = (1 << OBS_SRC) | (1 << OBS_GW) | (1 << OBS_DST)


def mask_of(*obs: int) -> int:
    m = 0
    for o in obs:
        m |= 1 << o
    return m


SCOPES = {
    "src": mask_of(OBS_SRC),
    "gw": mask_of(OBS_GW),
    "dst": mask_of(OBS_DST),
    "src+dst": mask_of(OBS_SRC, OBS_DST),
    "all": MASK_ALL,
}

STM_HZ = 40_000_000           # measured on the DEVKIT: 40.000 MHz (prescaler 2)
BUILD_FLAG_CAN_INTERNAL_LOOPBACK = 0x1

# ---------------- shared_mem.h ----------------
SHARED_SIZE = 0x20000
OFF_CTL, CTL_LEN = 0x0000, 0x100
OFF_IDSLOG, IDSLOG_SLOTS, IDSLOG_REC = 0x2400, 1536, 16
OFF_DLOG, DLOG_SLOTS, DLOG_REC = 0x8400, 512, 32
OFF_WLOG, WLOG_SLOTS, WLOG_REC = 0xC400, 1024, 12
OFF_IMPLOG_N, OFF_IMPLOG, IMPLOG_SLOTS, IMPLOG_REC = 0xF400, 0xF410, 64, 8

DLV = {1: "delivered", 2: "masked", 3: "ringfull"}
IDS_ST = {1: "processed", 2: "unprocessed", 3: "admit_drop"}

CTL_FIELDS = {  # name: offset (all uint32 big-endian)
    "c0_ready": 0x00, "c1_ready": 0x04, "c2_ready": 0x08, "layout_ver": 0x0C,
    "trial_seq": 0x10, "trial_id": 0x14, "u_ppm": 0x18, "obs_mask": 0x1C, "q_cap": 0x20,
    "deadline_ms": 0x24, "impact_ms": 0x28, "t_start": 0x2C, "t_cansync": 0x30,
    "host_t_hi": 0x34, "host_t_lo": 0x38, "end_seq": 0x3C, "c0_trial_ack": 0x40,
    "c0_end_ack": 0x44, "c2_trial_ack": 0x48, "t_end": 0x4C,
    "prod_src": 0x54, "prod_gw": 0x58, "prod_dst": 0x5C,
    "masked_src": 0x64, "masked_gw": 0x68, "masked_dst": 0x6C,
    "ringfull_src": 0x74, "ringfull_gw": 0x78, "ringfull_dst": 0x7C,
    "dlog_ovf": 0x80, "fwd_eth": 0x84, "fwd_can": 0x88, "can_tx_to": 0x8C,
    "enet_rx": 0x90, "can_rx": 0x94, "tq_full": 0x98, "c0_bcet_ticks": 0x9C,
    "c0_ing": 0xA0, "c0_admit": 0xA4, "c0_admit_drop": 0xA8, "c0_proc": 0xAC,
    "c0_unproc_end": 0xB0, "c0_windows": 0xB4, "c0_busy_ticks": 0xB8,
    "c0_max_backlog": 0xBC, "c0_log_n": 0xC0, "c0_log_ovf": 0xC4, "c0_wlog_n": 0xC8,
    "c0_wcet_ticks": 0xCC, "c2_rx": 0xD0, "c2_tx": 0xD4, "c2_state": 0xD8,
    "c2_impacts": 0xDC, "c2_txq_full": 0xE0, "dlog_n": 0xF0,
    "c1_step": 0xF4, "c2_step": 0xF8, "build_flags": 0xFC,
}


def parse_ctl(b: bytes) -> dict:
    return {k: struct.unpack_from(">I", b, o)[0] for k, o in CTL_FIELDS.items()}


def parse_evt(b: bytes, off: int = 0) -> dict:
    seq, t_obs, obs, kind, flags, status = struct.unpack_from(">IIBBBB", b, off)
    return {"seq": seq, "t_obs": t_obs, "obs": obs, "kind": kind, "flags": flags,
            "status": status, "d": bytes(b[off + 12: off + 32])}


def parse_idslog(b: bytes, off: int = 0) -> dict:
    seq, t_ing, t_proc, obs, status, feat, sess = struct.unpack_from(">IIIBBBB", b, off)
    return {"seq": seq, "t_ing": t_ing, "t_proc": t_proc, "obs": obs, "status": status,
            "feat": feat, "sess": sess}


def parse_implog(b: bytes, off: int = 0) -> dict:
    ecu, value, counter, _pad, t = struct.unpack_from(">BBBBI", b, off)
    return {"ecu": ecu, "value": value, "counter": counter, "t": t}


def parse_wlog(b: bytes, off: int = 0) -> dict:
    a, p, d, bl, busy = struct.unpack_from(">HHHHI", b, off)
    return {"arrivals": a, "processed": p, "dropped": d, "backlog": bl, "busy": busy}


# ---------------- decoded event views ----------------
def decode_event(e: dict) -> dict:
    """Add human-readable fields to a delivery-log event (payload layouts in bench.h)."""
    d, out = e["d"], dict(e)
    if e["obs"] == OBS_SRC:
        out["ip"] = socket.inet_ntoa(d[0:4])
        out["port"] = struct.unpack(">H", d[4:6])[0]
        out["dport"] = struct.unpack(">H", d[6:8])[0]
        out["doip_type"] = struct.unpack(">H", d[8:10])[0]
        out["doip_len"] = struct.unpack(">H", d[10:12])[0]
        pl = d[12:20]
        out["payload"] = pl.hex()
        if out["doip_type"] == DOIP_DIAG:
            out["sa"], out["ta"] = struct.unpack(">HH", pl[0:4])
            n = max(0, min(4, out["doip_len"] - 4))
            out["uds"] = pl[4:4 + n].hex()
        elif out["doip_type"] == DOIP_RA_REQ:
            out["sa"] = struct.unpack(">H", pl[0:2])[0]
    elif e["obs"] == OBS_GW:
        out["ip"] = socket.inet_ntoa(d[0:4])
        out["port"], out["sa"], out["ta"] = struct.unpack(">HHH", d[4:10])
        out["decision"] = GWD.get(d[10], str(d[10]))
        out["reason"] = GWR.get(d[11], str(d[11]))
        out["sid"], out["sub"] = d[12], d[13]
        out["did"] = struct.unpack(">H", d[14:16])[0]
        out["auth"], out["dsess"] = d[16], d[17]
        out["route_seq"] = struct.unpack(">H", d[18:20])[0]
    elif e["obs"] == OBS_DST:
        out["can_id"] = struct.unpack(">I", d[0:4])[0]
        out["dlc"] = d[4]
        out["data"] = d[5:13].hex()
    return out


# ---------------- control client ----------------
class BenchError(RuntimeError):
    pass


@dataclass
class StartReply:
    ok: bool
    trial_seq: int
    t_start: int
    t_cansync: int
    host_t_send_ns: int
    host_t_reply_ns: int


class Ctl:
    """UDP client for the gateway control endpoint (port 13499)."""

    def __init__(self, gw_ip: str, port: int = CTRL_PORT, bind_ip: str = "", timeout: float = 3.0):
        self.addr = (gw_ip, port)
        self.s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.s.bind((bind_ip, 0))
        self.s.settimeout(timeout)

    def _xfer(self, msg: bytes, expect: bytes, retries: int = 3) -> bytes:
        last = None
        for _ in range(retries):
            self.s.sendto(msg, self.addr)
            try:
                while True:
                    data, _a = self.s.recvfrom(2048)
                    if data[:1] == expect:
                        return data
            except socket.timeout as ex:
                last = ex
        raise BenchError(f"no '{expect.decode()}' reply from {self.addr}: {last}")

    def hello(self) -> dict:
        r = self._xfer(b"H", b"h")
        ver, = struct.unpack_from(">I", r, 1)
        return {"layout_ver": ver, "c0": r[5], "c1": r[6], "c2": r[7],
                "stm": struct.unpack_from(">I", r, 8)[0]}

    def start(self, trial_id: int, u_ppm: int, obs_mask: int, q_cap: int,
              deadline_ms: int, impact_ms: int, flags: int = CFGF_IMPACT_SRC,
              jitter_ms: int = 0, seed: int = 0) -> StartReply:
        t_ns = time.perf_counter_ns()
        msg = b"S" + struct.pack(">IIBHIHQBHI", trial_id, u_ppm, obs_mask, q_cap,
                                 deadline_ms, impact_ms, t_ns, flags, jitter_ms, seed)
        assert len(msg) == 33
        r = self._xfer(msg, b"A", retries=1)
        t_r = time.perf_counter_ns()
        seq, t0, tsync = struct.unpack_from(">III", r, 2)
        return StartReply(r[1] == 0, seq, t0, tsync, t_ns, t_r)

    def end(self) -> dict:
        r = self._xfer(b"E", b"F", retries=1)
        seq, t_end = struct.unpack_from(">II", r, 2)
        return {"ok": r[1] == 0, "end_seq": seq, "t_end": t_end}

    def peek(self, off: int, n: int) -> bytes:
        out = bytearray()
        while n > 0:
            k = min(n, 1024)
            r = self._xfer(b"P" + struct.pack(">IH", off, k), b"D")
            roff, rn = struct.unpack_from(">IH", r, 1)
            if roff != off:
                continue
            out += r[7:7 + rn]
            off += rn
            n -= rn
            if rn == 0:
                break
        return bytes(out)

    def dump(self) -> dict:
        """Read control block and all logs of the trial that just ended."""
        ctl = parse_ctl(self.peek(OFF_CTL, CTL_LEN))
        nd = min(ctl["dlog_n"], DLOG_SLOTS)
        ni = min(ctl["c0_log_n"], IDSLOG_SLOTS)
        nw = min(ctl["c0_wlog_n"], WLOG_SLOTS)
        db = self.peek(OFF_DLOG, nd * DLOG_REC) if nd else b""
        ib = self.peek(OFF_IDSLOG, ni * IDSLOG_REC) if ni else b""
        wb = self.peek(OFF_WLOG, nw * WLOG_REC) if nw else b""
        nim = min(struct.unpack(">I", self.peek(OFF_IMPLOG_N, 4))[0], IMPLOG_SLOTS)
        mb = self.peek(OFF_IMPLOG, nim * IMPLOG_REC) if nim else b""
        return {
            "ctl": ctl,
            "dlog": [parse_evt(db, i * DLOG_REC) for i in range(nd)],
            "idslog": [parse_idslog(ib, i * IDSLOG_REC) for i in range(ni)],
            "wlog": [parse_wlog(wb, i * WLOG_REC) for i in range(nw)],
            # ground truth only (core 2's private log; no observer sees it)
            "implog": [parse_implog(mb, i * IMPLOG_REC) for i in range(nim)],
        }
