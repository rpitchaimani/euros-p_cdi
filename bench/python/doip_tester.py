"""doip_tester.py -- minimal DoIP-over-UDP test equipment for the bench.

Each Tester owns one UDP socket, so (IP, port) identifies its session at the
gateway.  Every request and response is recorded with host perf_counter_ns
timestamps; the runner maps them to STM time through the START exchange.
"""
from __future__ import annotations

import socket
import struct
import time

from bench_proto import (DOIP_PORT, DOIP_VIR, DOIP_VAM, DOIP_RA_REQ, DOIP_RA_RESP,
                         DOIP_DIAG, DOIP_DIAG_ACK, DOIP_DIAG_NACK, LA_TARGET, SA_KEY_XOR)


def doip(ptype: int, payload: bytes = b"") -> bytes:
    return struct.pack(">BBHI", 0x02, 0xFD, ptype, len(payload)) + payload


class Tester:
    def __init__(self, name: str, gw_ip: str, sa: int, bind_ip: str = "", timeout: float = 0.5):
        self.name, self.sa = name, sa
        self.gw = (gw_ip, DOIP_PORT)
        self.s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.s.bind((bind_ip, 0))
        self.s.settimeout(timeout)
        self.port = self.s.getsockname()[1]
        self.log: list[dict] = []

    def close(self):
        self.s.close()

    # -------------------------------------------------------------
    def _recv(self, until_ns: int):
        while True:
            left = (until_ns - time.perf_counter_ns()) / 1e9
            if left <= 0:
                return None, None
            self.s.settimeout(left)
            try:
                data, _ = self.s.recvfrom(2048)
            except socket.timeout:
                return None, None
            if len(data) >= 8 and data[0] == 0x02 and data[1] == 0xFD:
                ptype, = struct.unpack_from(">H", data, 2)
                return ptype, data[8:]

    def _rec(self, op, req: bytes, t0: int, **kw):
        r = {"tester": self.name, "sa": self.sa, "port": self.port, "op": op,
             "req": req.hex(), "t_send": t0}
        r.update(kw)
        self.log.append(r)
        return r

    def vir(self, wait: float = 0.3):
        t0 = time.perf_counter_ns()
        self.s.sendto(doip(DOIP_VIR), self.gw)
        ptype, pl = self._recv(t0 + int(wait * 1e9))
        ok = ptype == DOIP_VAM
        return self._rec("vir", b"", t0, t_resp=time.perf_counter_ns() if ok else None,
                         ok=ok, resp=pl.hex() if pl else None)

    def ra(self, wait: float = 0.3):
        t0 = time.perf_counter_ns()
        self.s.sendto(doip(DOIP_RA_REQ, struct.pack(">HB4x", self.sa, 0)), self.gw)
        ptype, pl = self._recv(t0 + int(wait * 1e9))
        ok = ptype == DOIP_RA_RESP and pl is not None and len(pl) >= 5 and pl[4] == 0x10
        return self._rec("ra", b"", t0, t_resp=time.perf_counter_ns() if ptype else None,
                         ok=ok, resp=pl.hex() if pl else None)

    def diag(self, uds: bytes, ta: int = LA_TARGET, wait: float = 0.5):
        """Send one UDS request; wait for ACK/NACK and, after ACK, the response."""
        t0 = time.perf_counter_ns()
        self.s.sendto(doip(DOIP_DIAG, struct.pack(">HH", self.sa, ta) + uds), self.gw)
        deadline = t0 + int(wait * 1e9)
        ack = None
        resp = None
        t_ack = t_resp = None
        while True:
            ptype, pl = self._recv(deadline)
            if ptype is None:
                break
            if ptype == DOIP_DIAG_ACK:
                ack, t_ack = "ack", time.perf_counter_ns()
            elif ptype == DOIP_DIAG_NACK:
                ack, t_ack = f"nack{pl[4]:02x}" if len(pl) >= 5 else "nack", time.perf_counter_ns()
                break
            elif ptype == DOIP_DIAG and len(pl) >= 5:
                resp, t_resp = pl[4:], time.perf_counter_ns()
                if not (len(resp) >= 3 and resp[0] == 0x7F and resp[2] == 0x78):
                    break
        return self._rec("diag", uds, t0, ta=ta, ack=ack, t_ack=t_ack,
                         resp=resp.hex() if resp else None, t_resp=t_resp)

    # convenience -------------------------------------------------
    def unlock(self, ta: int = LA_TARGET) -> bool:
        r = self.diag(bytes([0x27, 0x01]), ta=ta)
        if not r["resp"] or not r["resp"].startswith("6701"):
            return False
        seed = int(r["resp"][4:8], 16)
        key = seed ^ SA_KEY_XOR
        r2 = self.diag(bytes([0x27, 0x02, key >> 8, key & 0xFF]), ta=ta)
        return bool(r2["resp"]) and r2["resp"].startswith("6702")
