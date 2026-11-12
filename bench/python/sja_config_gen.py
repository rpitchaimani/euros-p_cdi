#!/usr/bin/env python3
"""
sja_config_gen.py  —  SJA1105Q static configuration generator
ChainRecon bench

Ported from NXP sw425110 (Python 2) to Python 3.
Generates the binary config block that main.c uploads via SPI at boot.

Port layout:
  (Header list below is the ORIGINAL layout; see HOST_PORT/TESTER_PORT for the bench cabling.)
  Port 0 (MII, MAC, 100 Mbps):  Attacker laptop via media converter
  Port 1 (MII, MAC, 100 Mbps):  IDS mirror destination
  Port 2 (MII, MAC, 100 Mbps):  Unused
  Port 3 (MII, MAC, 100 Mbps):  Unused
  Port 4 (RGMII, MAC, 1 Gbps):  MPC5748G ENET (host port)

Key static settings:
  HOST_PORT  = 4      (MPC5748G is the CPU port)
  ChainRecon: mirroring is STATIC.  MIRR_PORT = MIRROR_DST (reference capture
  NIC), ingress+egress mirroring on MIRROR_SRC_PORTS, MIRR_PTACU = 0 so the
  mirror configuration cannot be changed at run time.
  Check the port numbers below against your cabling before generating.

Outputs:
  ../include/sja1105_config.h   C header with uint8_t array
  sja1105q_poc.hex              Intel HEX (for reference/verification)
"""

import struct
import binascii
import os
import sys

# ─── Device IDs ───────────────────────────────────────────────────────────────
SJA1105Q_DEVICE_ID = 0xAE00030E   # SJA1105Q/S per NXP EVB tools (default.py); read back from the board 7 Nov 2026
SJA1105PR_DEVICE_ID = 0xAF00030E  # SJA1105P/R

# ─── CRC helper ───────────────────────────────────────────────────────────────
def crc32(data: bytes) -> int:
    return binascii.crc32(data) & 0xFFFFFFFF

# ─── Field / Entry / Table / Configuration ────────────────────────────────────
# Ported from NXP configuration.py (MIT License, Copyright NXP 2017)

class Field:
    def __init__(self, lst):
        self.name   = lst[0]
        self.len    = lst[1]
        self.value  = lst[2]
        self.offset = 0   # set by Entry._process_layout

class Entry:
    def __init__(self, layout, data=None):
        self.fields = [Field(l) for l in layout]
        # Compute bit offsets: first field at top, decreasing
        total_bits = sum(f.len for f in self.fields)
        words      = (total_bits + 31) // 32
        self.len   = words * 32          # total bits including padding
        top = self.len
        for f in self.fields:
            f.offset = top - f.len
            top      = f.offset
        if data:
            for k, v in data.items():
                self[k] = v

    def _field(self, name):
        for f in self.fields:
            if f.name == name:
                return f
        return None

    def __setitem__(self, key, value):
        f = self._field(key)
        if f is None:
            raise KeyError(f"No field '{key}' in layout")
        mask = (1 << f.len) - 1
        f.value = int(value) & mask

    def __getitem__(self, key):
        f = self._field(key)
        if f is None:
            raise KeyError(f"No field '{key}' in layout")
        return f.value

    def to_bytes(self) -> bytes:
        d = 0
        for f in self.fields:
            d |= f.value << f.offset
        # Little-endian byte output
        out = bytearray(self.len // 8)
        for i in range(self.len // 8):
            out[i] = (d >> (i * 8)) & 0xFF
        return bytes(out)

class Table:
    def __init__(self, tableid, layout):
        self.tableid = tableid
        self.layout  = layout
        self.entries = []

    def append(self, data: dict):
        self.entries.append(Entry(self.layout, data))

    def to_bytes(self) -> bytes:
        payload = bytearray()
        for e in self.entries:
            payload += e.to_bytes()
        hdr1 = struct.pack("<I", self.tableid << 24)
        hdr2 = struct.pack("<I", len(payload) // 4)
        hdr_crc  = struct.pack("<I", crc32(hdr1 + hdr2))
        payl_crc = struct.pack("<I", crc32(bytes(payload)))
        return hdr1 + hdr2 + hdr_crc + bytes(payload) + payl_crc

class Configuration:
    def __init__(self, device_id: int):
        self.device_id = device_id
        self.tables    = []

    def add(self, table: Table):
        self.tables.append(table)

    def to_bytes(self) -> bytes:
        self.tables.sort(key=lambda t: t.tableid)
        buf = struct.pack("<I", self.device_id)
        for t in self.tables:
            buf += t.to_bytes()
        # Terminator: two zero words
        buf += struct.pack("<I", 0)
        buf += struct.pack("<I", 0)
        buf += struct.pack("<I", crc32(buf))
        return buf

    def to_hex(self, filename: str):
        data = self.to_bytes()
        with open(filename, 'w') as f:
            addr = 0
            while addr < len(data):
                chunk = data[addr:addr+4]
                rec   = f":{len(chunk):02X}{addr:04X}00"
                for b in chunk:
                    rec += f"{b:02X}"
                chksum = (-sum(bytes.fromhex(rec[1:]))) & 0xFF
                f.write(rec + f"{chksum:02X}\n")
                addr += 4
            f.write(":00000001FF\n")

# ─── Table layouts (from tables_sja1105pqrs.py, MIT License, NXP 2017) ────────

general_parameters_layout = [
   ['VLLUPFORMAT', 1, 0x0],
   ['MIRR_PTACU',  1, 0x0],
   ['SWITCHID',    3, 0x0],
   ['HOSTPRIO',    3, 0x0],
   ['MAC_FLTRES[1]', 48, 0x180c2000000],
   ['MAC_FLTRES[0]', 48, 0x180c2000000],
   ['MAC_FLT[1]',  48, 0xffffff000000],
   ['MAC_FLT[0]',  48, 0xffffff000000],
   ['INCL_SRCPT[1]', 1, 0x0],
   ['INCL_SRCPT[0]', 1, 0x0],
   ['SEND_META[1]',  1, 0x0],
   ['SEND_META[0]',  1, 0x0],
   ['CASC_PORT',  3, 0x5],
   ['HOST_PORT',  3, 0x5],
   ['MIRR_PORT',  3, 0x5],
   ['VIMARKER',  32, 0x0],
   ['VIMASK',    32, 0xffffffff],
   ['TPID',      16, 0x88a8],
   ['IGNORE2STF',  1, 0x1],
   ['TPID2',     16, 0x8100],
   ['QUEUE_TS',    1, 0x0],
   ['EGRMIRRVID', 12, 0x0],
   ['EGRMIRRPCP',  3, 0x0],
   ['EGRMIRRDEI',  1, 0x0],
   ['REPLAY_PORT', 3, 0x7],
]

mac_configuration_layout = [
   ['TOP[7]',    9, 0x0], ['BASE[7]',   9, 0x0], ['ENABLED[7]', 1, 0x0],
   ['TOP[6]',    9, 0x0], ['BASE[6]',   9, 0x0], ['ENABLED[6]', 1, 0x0],
   ['TOP[5]',    9, 0x0], ['BASE[5]',   9, 0x0], ['ENABLED[5]', 1, 0x0],
   ['TOP[4]',    9, 0x0], ['BASE[4]',   9, 0x0], ['ENABLED[4]', 1, 0x0],
   ['TOP[3]',    9, 0x0], ['BASE[3]',   9, 0x0], ['ENABLED[3]', 1, 0x0],
   ['TOP[2]',    9, 0x0], ['BASE[2]',   9, 0x0], ['ENABLED[2]', 1, 0x0],
   ['TOP[1]',    9, 0x0], ['BASE[1]',   9, 0x0], ['ENABLED[1]', 1, 0x0],
   ['TOP[0]',    9, 0x0], ['BASE[0]',   9, 0x0], ['ENABLED[0]', 1, 0x0],
   ['IFG',       5, 0x0],
   ['SPEED',     2, 0x0],
   ['TP_DELIN', 16, 0x0],
   ['TP_DELOUT',16, 0x0],
   ['MAXAGE',    8, 0x0],
   ['VLANPRIO',  3, 0x0],
   ['VLANID',   12, 0x0],
   ['ING_MIRR',  1, 0x0],
   ['EGR_MIRR',  1, 0x0],
   ['DRPNONA664',1, 0x0],
   ['DRPDTAG',   1, 0x0],
   ['DRPSOTAG',  1, 0x0],
   ['DRPSITAG',  1, 0x0],
   ['DRPUNTAG',  1, 0x0],
   ['RETAG',     1, 0x0],
   ['DYN_LEARN', 1, 0x1],
   ['EGRESS',    1, 0x1],
   ['INGRESS',   1, 0x1],
   ['MIRRCIE',   1, 0x0],
   ['MIRRCETAG', 1, 0x0],
   ['INGMIRRVID',12, 0x0],
   ['INGMIRRPCP', 3, 0x0],
   ['INGMIRRDEI', 1, 0x0],
]

l2_policing_layout = [
   ['SHARINDX',  6, 0x0],
   ['SMAX',     16, 0x0],
   ['RATE',     16, 0x0],
   ['MAXLEN',   11, 0x0],
   ['PARTITION', 3, 0x0],
]

vlan_lookup_layout = [
   ['VING_MIRR',  5, 0x0],
   ['VEGR_MIRR',  5, 0x0],
   ['VMEMB_PORT', 5, 0x0],
   ['VLAN_BC',    5, 0x0],
   ['TAG_PORT',   5, 0x0],
   ['VLANID',    12, 0x0],
]

l2_lookup_parameters_layout = [
   ['DRPBC',      5, 0x0],
   ['DRPMC',      5, 0x0],
   ['DRPUNI',     5, 0x0],
   ['MAXADDRP[4]',11, 0x400],
   ['MAXADDRP[3]',11, 0x400],
   ['MAXADDRP[2]',11, 0x400],
   ['MAXADDRP[1]',11, 0x400],
   ['MAXADDRP[0]',11, 0x400],
   ['MAXAGE',    15, 0x0],
   ['START_DYNSPC',10, 0x0],
   ['DRPNOLEARN', 5, 0x0],
   ['SHARED_LEARN',1, 0x0],
   ['NO_ENF_HOSTPRT',1, 0x0],
   ['NO_MGMT_LEARN', 1, 0x0],
   ['USE_STATIC',  1, 0x0],
   ['OWR_DYN',     1, 0x1],
   ['LEARN_ONCE',  1, 0x0],
]

l2_forwarding_layout = [
   ['BC_DOMAIN',    5, 0x0],
   ['REACH_PORT',   5, 0x0],
   ['FL_DOMAIN',    5, 0x0],
   ['VLAN_PMAP[7]', 3, 0x0],
   ['VLAN_PMAP[6]', 3, 0x0],
   ['VLAN_PMAP[5]', 3, 0x0],
   ['VLAN_PMAP[4]', 3, 0x0],
   ['VLAN_PMAP[3]', 3, 0x0],
   ['VLAN_PMAP[2]', 3, 0x0],
   ['VLAN_PMAP[1]', 3, 0x0],
   ['VLAN_PMAP[0]', 3, 0x0],
]

l2_forwarding_parameters_layout = [
   ['MAX_DYNP',    3, 0x0],
   ['PART_SPC[7]',10, 0x0],
   ['PART_SPC[6]',10, 0x0],
   ['PART_SPC[5]',10, 0x0],
   ['PART_SPC[4]',10, 0x0],
   ['PART_SPC[3]',10, 0x0],
   ['PART_SPC[2]',10, 0x0],
   ['PART_SPC[1]',10, 0x0],
   ['PART_SPC[0]',10, 0x0],
]

avb_parameters_layout = [
   ['L2CBS',      1, 0x0],
   ['CAS_MASTER', 1, 0x0],
   ['DESTMETA',  48, 0x0],
   ['SRCMETA',   48, 0x0],
]

mii_mode_parameters_layout = [
   ['PHY_MAC[4]',  1, 0x0],
   ['xMII_MODE[4]',2, 0x0],
   ['PHY_MAC[3]',  1, 0x0],
   ['xMII_MODE[3]',2, 0x0],
   ['PHY_MAC[2]',  1, 0x0],
   ['xMII_MODE[2]',2, 0x0],
   ['PHY_MAC[1]',  1, 0x0],
   ['xMII_MODE[1]',2, 0x0],
   ['PHY_MAC[0]',  1, 0x0],
   ['xMII_MODE[0]',2, 0x0],
]

# ─── PoC Configuration ────────────────────────────────────────────────────────

NO_PORTS      = 5
NO_PRIORITIES = 8

MII   = 0; RMII  = 1; RGMII = 2
MAC_MODE = 0; PHY_MODE = 1

SPEED_1GBPS   = 1
SPEED_100MBPS = 2
SPEED_10MBPS  = 3

# Port speeds
port_speed      = [SPEED_100MBPS, SPEED_100MBPS,
                   SPEED_100MBPS, SPEED_100MBPS, SPEED_1GBPS]
port_speed_Mbps = [100, 100, 100, 100, 1000]

# Bench cabling (10 Nov 2026), SJA1105Q-EVB per AH1707 Table 2:
#   J13 = port 1 (TJA1102 U7A) -> media converter (slave) -> PC tester NIC
#   J11 = port 3 (TJA1102 U6A) -> media converter (slave) -> MPC5748G ENET
#   J14 = port 2, J12 = port 4 free; port 0 = host-CPU connector, unused.
# NOTE: the xMII modes / speeds above still describe the old RGMII-on-port-4
# layout, not the EVB's TJA1102 MII/RMII wiring (AH1707 Table 2). Fix them
# before this config is ever uploaded (SJA_BOOT_CONFIG=1 or the EVB tool).
TESTER_PORT = 1
HOST_PORT = 3
# Mirroring is OFF: the PC has one NIC (no reference-capture port).
ENABLE_MIRROR = False
MIRROR_DST = 2                 # free port, for a future reference-capture NIC
MIRROR_SRC_PORTS = (TESTER_PORT, HOST_PORT)  # tester port and gateway port, both directions
DEFAULT_VLAN = 0xFFF


def build_config() -> Configuration:
    c = Configuration(SJA1105Q_DEVICE_ID)

    # ── General Parameters (ID 17) ────────────────────────────────────────────
    gp = Table(17, general_parameters_layout)
    gp.append({
        'VLLUPFORMAT':    0,
        'MIRR_PTACU':     0,   # ChainRecon: no runtime mirror changes
        'SWITCHID':       0,
        'HOSTPRIO':       5,
        'MAC_FLTRES[0]':  0x0180C200000E,
        'MAC_FLTRES[1]':  0x0180C2000003,
        'MAC_FLT[0]':     0xFFFFFF0000FF,
        'MAC_FLT[1]':     0xFFFFFF0000FF,
        'INCL_SRCPT[0]':  1,
        'INCL_SRCPT[1]':  1,
        'SEND_META[0]':   1,
        'SEND_META[1]':   0,
        'CASC_PORT':      6,   # disabled
        'HOST_PORT':      HOST_PORT,
        'MIRR_PORT':      MIRROR_DST if ENABLE_MIRROR else 6,  # 6 = disabled
        'VIMARKER':       0xFFFFFFFF,
        'VIMASK':         0xFFFFFFFF,
        'TPID':           0x88A8,
        'IGNORE2STF':     0,
        'TPID2':          0x8100,
        'QUEUE_TS':       0,
        'EGRMIRRVID':     0,
        'EGRMIRRPCP':     0,
        'EGRMIRRDEI':     0,
        'REPLAY_PORT':    7,
    })
    c.add(gp)

    # ── MAC Configuration Table (ID 9) ────────────────────────────────────────
    mac = Table(9, mac_configuration_layout)
    for i in range(NO_PORTS):
        mac.append({
            'INGMIRRDEI': 0, 'INGMIRRPCP': 0, 'INGMIRRVID': 0,
            'MIRRCETAG':  0, 'MIRRCIE':    0,
            'INGRESS':    1, 'EGRESS':     1, 'DYN_LEARN':  1,
            'DRPNONA664': 0,
            'EGR_MIRR':   1 if (ENABLE_MIRROR and i in MIRROR_SRC_PORTS) else 0,
            'ING_MIRR':   1 if (ENABLE_MIRROR and i in MIRROR_SRC_PORTS) else 0,
            'VLANID':     DEFAULT_VLAN,
            'VLANPRIO':   0,
            'MAXAGE':     255,
            'TP_DELOUT':  0,  'TP_DELIN':  0,
            'SPEED':      port_speed[i],
            'IFG':        0,
            'ENABLED[0]': 1, 'BASE[0]': 0,   'TOP[0]': 63,
            'ENABLED[1]': 1, 'BASE[1]': 64,  'TOP[1]': 127,
            'ENABLED[2]': 1, 'BASE[2]': 128, 'TOP[2]': 191,
            'ENABLED[3]': 1, 'BASE[3]': 192, 'TOP[3]': 255,
            'ENABLED[4]': 1, 'BASE[4]': 256, 'TOP[4]': 319,
            'ENABLED[5]': 1, 'BASE[5]': 320, 'TOP[5]': 383,
            'ENABLED[6]': 1, 'BASE[6]': 384, 'TOP[6]': 447,
            'ENABLED[7]': 1, 'BASE[7]': 448, 'TOP[7]': 511,
        })
    c.add(mac)

    # ── L2 Policing Table (ID 6) ──────────────────────────────────────────────
    pol = Table(6, l2_policing_layout)
    for port in range(NO_PORTS):
        speed_bps = port_speed_Mbps[port] * 1_000_000
        for prio in range(NO_PRIORITIES):
            rate = int(speed_bps / 8 * 1000 / 15625)
            pol.append({
                'SHARINDX':  port * NO_PRIORITIES + prio,
                'SMAX':      10 * 1526,
                'RATE':      rate,
                'MAXLEN':    1526,
                'PARTITION': prio,
            })
    # Broadcast storm prevention entries (5 per port = 45 entries above, +5 here)
    for port in range(NO_PORTS):
        speed_bps = port_speed_Mbps[port] * 1_000_000
        rate = int(speed_bps / 8 * 1000 / 15625)
        pol.append({
            'SHARINDX':  40 + port,
            'SMAX':      10 * 1526,
            'RATE':      rate,
            'MAXLEN':    1526,
            'PARTITION': 0,
        })
    c.add(pol)

    # ── VLAN Lookup Table (ID 7) ──────────────────────────────────────────────
    vlan = Table(7, vlan_lookup_layout)
    # Default VLAN (0xFFF): all ports member, untagged egress
    vlan.append({
        'VING_MIRR': 0, 'VEGR_MIRR': 0,
        'VMEMB_PORT': 0x1F, 'VLAN_BC': 0x1F,
        'TAG_PORT':  0x00,
        'VLANID':    DEFAULT_VLAN,
    })
    # VLANs 0-31 with all ports as members (covers VLAN 10, 20, 30)
    for vid in range(32):
        vlan.append({
            'VING_MIRR': 0, 'VEGR_MIRR': 0,
            'VMEMB_PORT': 0x1F, 'VLAN_BC': 0x1F,
            'TAG_PORT':  0x1F,
            'VLANID':    vid,
        })
    c.add(vlan)

    # ── L2 Lookup Parameters Table (ID 13) ────────────────────────────────────
    lkp = Table(13, l2_lookup_parameters_layout)
    lkp.append({
        'LEARN_ONCE': 0, 'OWR_DYN': 0, 'USE_STATIC': 0,
        'NO_MGMT_LEARN': 1, 'NO_ENF_HOSTPRT': 0,
        'DRPNOLEARN': 0, 'START_DYNSPC': 0, 'MAXAGE': 0,
        'MAXADDRP[0]': 1024, 'MAXADDRP[1]': 1024,
        'MAXADDRP[2]': 1024, 'MAXADDRP[3]': 1024, 'MAXADDRP[4]': 1024,
        'DRPUNI': 0, 'DRPMC': 0, 'DRPBC': 0,
    })
    c.add(lkp)

    # ── L2 Forwarding Table (ID 8) ────────────────────────────────────────────
    fwd = Table(8, l2_forwarding_layout)
    for i in range(NO_PORTS):
        if i == HOST_PORT:
            reachable = 0x1F   # host port reaches itself (hybrid mode)
        else:
            reachable = 0x1F & ~(1 << i)
        bc_domain    = 0x1F & ~(1 << i)
        fl_domain    = 0x1F & ~(1 << i)
        fwd.append({
            'FL_DOMAIN':    fl_domain,
            'BC_DOMAIN':    bc_domain,
            'REACH_PORT':   reachable,
            'VLAN_PMAP[0]': 0, 'VLAN_PMAP[1]': 1,
            'VLAN_PMAP[2]': 2, 'VLAN_PMAP[3]': 3,
            'VLAN_PMAP[4]': 4, 'VLAN_PMAP[5]': 5,
            'VLAN_PMAP[6]': 6, 'VLAN_PMAP[7]': 7,
        })
    # Priority map entries (8 entries for output queue mapping)
    for i in range(NO_PRIORITIES):
        fwd.append({
            'VLAN_PMAP[0]': i, 'VLAN_PMAP[1]': i,
            'VLAN_PMAP[2]': i, 'VLAN_PMAP[3]': i,
            'VLAN_PMAP[4]': i,
        })
    c.add(fwd)

    # ── L2 Forwarding Parameters Table (ID 14) ────────────────────────────────
    fwdp = Table(14, l2_forwarding_parameters_layout)
    fwdp.append({
        'MAX_DYNP':    0,
        'PART_SPC[0]': 210,
        'PART_SPC[1]': 100, 'PART_SPC[2]': 100,
        'PART_SPC[3]': 100, 'PART_SPC[4]': 100,
        'PART_SPC[5]': 100, 'PART_SPC[6]': 100,
        'PART_SPC[7]': 100,
    })
    assert sum([210, 100, 100, 100, 100, 100, 100, 100]) <= 910
    c.add(fwdp)

    # ── AVB Parameters Table (ID 16) ──────────────────────────────────────────
    avb = Table(16, avb_parameters_layout)
    avb.append({
        'SRCMETA':   0x026037C0FFEE,
        'DESTMETA':  0x026037DECADE,
        'CAS_MASTER': 1,
        'L2CBS':     0,
    })
    c.add(avb)

    # ── MII Mode Parameters Table (ID 78) ─────────────────────────────────────
    mii = Table(78, mii_mode_parameters_layout)
    mii.append({
        'PHY_MAC[0]':  MAC_MODE, 'xMII_MODE[0]': MII,    # Port 0: MII
        'PHY_MAC[1]':  MAC_MODE, 'xMII_MODE[1]': MII,    # Port 1: MII
        'PHY_MAC[2]':  MAC_MODE, 'xMII_MODE[2]': MII,    # Port 2: unused
        'PHY_MAC[3]':  MAC_MODE, 'xMII_MODE[3]': MII,    # Port 3: unused
        'PHY_MAC[4]':  MAC_MODE, 'xMII_MODE[4]': RGMII,  # Port 4: RGMII
    })
    c.add(mii)

    return c


def write_c_header(data: bytes, out_path: str):
    lines = [
        "/* sja1105_config.h — auto-generated by sja_config_gen.py */",
        "/* SJA1105Q static config block for CDI PoC */",
        "#ifndef SJA1105_CONFIG_H",
        "#define SJA1105_CONFIG_H",
        "#include <stdint.h>",
        f"#define SJA1105_CONFIG_SIZE {len(data)}u",
        "static const uint8_t sja1105_static_config[] = {",
    ]
    # 16 bytes per line
    for i in range(0, len(data), 16):
        chunk = data[i:i+16]
        hex_vals = ", ".join(f"0x{b:02X}" for b in chunk)
        lines.append(f"    {hex_vals},")
    lines += ["};", "", "#endif /* SJA1105_CONFIG_H */", ""]
    with open(out_path, 'w') as f:
        f.write('\n'.join(lines))
    print(f"[cfg] Written: {out_path}  ({len(data)} bytes)")


if __name__ == "__main__":
    script_dir = os.path.dirname(os.path.abspath(__file__))
    project_dir = os.path.dirname(script_dir)

    print("[cfg] Building SJA1105Q static configuration…")
    cfg   = build_config()
    data  = cfg.to_bytes()
    print(f"[cfg] Config size: {len(data)} bytes")

    # C header
    hdr_path = os.path.join(project_dir, "include", "sja1105_config.h")
    write_c_header(data, hdr_path)

    # Intel HEX for reference
    hex_path = os.path.join(script_dir, "sja1105q_poc.hex")
    cfg.to_hex(hex_path)
    print(f"[cfg] Written: {hex_path}")

    # Verify device ID round-trips correctly
    dev_id = struct.unpack_from("<I", data, 0)[0]
    print(f"[cfg] Device ID in config: 0x{dev_id:08X}"
          f"  ({'OK' if dev_id == SJA1105Q_DEVICE_ID else 'MISMATCH'})")
