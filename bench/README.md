# Chain-reconstruction bench (Section 7)

Firmware, host scripts, and raw logs for the hardware test of the paper. The bench is an
NXP MPC5748G gateway behind an NXP SJA1105Q automotive-Ethernet switch, with a PEAK
PCAN-USB on the CAN bus as an independent reference. No exploit is used: the chain sends
standard diagnostic requests to target ECUs that the firmware itself emulates.

## What runs where

| Core | Files | Role |
|---|---|---|
| Z4a (core 0) | `src/main.c`, `src/ids_core0.c` | boots the chip, then runs the IDS under test: ingest, queue, CPU-share limiter (first-in, first-out, non-preemptive), logs |
| Z4b (core 1) | `src/core1_gateway.c`, `src/doip_gw.c`, `src/observers.c`, `src/can_drv.c`, `src/lwip_port.c` | zonal gateway (DoIP message formats over UDP 13400 to UDS on CAN), the three observers, bench control on UDP 13499 |
| Z2 (core 2) | `src/core2_target.c` | two emulated target ECUs (UDS on 0x7E0/0x7E8 and 0x7E1/0x7E9, test-state DID F1A0, shared impact message 0x1A0) and a private impact log used only as ground truth |

The three observers sit on core 1: `src` sees each Ethernet frame at ingress, `gw` each
routing and policy decision, `dst` each CAN frame read back from the bus. The trial's scope
mask chooses which observers reach the IDS. Every non-background event also goes into a
delivery log, so a missing event can be told apart from a late one.

## Hardware and wiring

- NXP DEVKIT-MPC5748G (OpenSDA debug and UART at 57600 baud).
- NXP SJA1105Q-EVB, running its boot configuration. Ports per the EVB user manual (AH1707,
  Table 2): connector J13 = switch port 1, connector J11 = switch port 3. Each 100BASE-T1
  port is a master, so each media converter must be set to slave.
  - PC tester NIC (192.168.10.100/24) -> media converter -> J13 (port 1)
  - MPC5748G Ethernet (192.168.10.1) -> media converter -> J11 (port 3)
- PEAK PCAN-USB on CAN0 at 500 kbit/s, 120 ohm at each end, open in normal mode for every
  cell (FlexCAN frames are only acknowledged by another node). The PEAK never transmits.
- After any re-cabling, reboot the board: the Ethernet PHY brings its link up only at boot.

`python/sja_config_gen.py` writes a static switch configuration (`include/sja1105_config.h`,
`python/sja1105q_poc.hex`) for this cabling with mirroring off. The counted runs did **not**
upload it (`SJA_BOOT_CONFIG=0` in `src/main.c`); its xMII modes still need adapting to the
EVB's PHY wiring before it is used.

## Build and flash

Requires NXP S32 Design Studio for Power Architecture v2.1 with S32 SDK RTM 3.0.0
(toolchain `powerpc-eabivle-4_9`, msys `make`, PEmicro GDB server).

```
export PATH="<S32DS>/S32DS/build_tools/msys32/usr/bin:$PATH"
python python/sja_config_gen.py
make all S32DS_HOME=<S32DS>           # build/chainrecon_c{0,1,2}.elf
./flash_and_boot.sh <COMPORT> 60      # one merged load, then releases cores 1 and 2
```

`flash_and_boot.sh` merges the three images into one S-record (the PEMicro flash algorithm
erases the flash on every load) and resumes cores 1 and 2, which stop at their entry
address while the debugger is attached.

## Running cells

```
cd python
python run_bench.py --gw 192.168.10.1 --bind 192.168.10.100 hello
python run_bench.py --gw 192.168.10.1 --bind 192.168.10.100 cell --name C1 \
   --scope all --u-ppm 1000000 --mix LOW --trials 60 --peak PCAN_USBBUS1
python run_bench.py ... baseline --name B0 --hours 8 --bg-pps 500 --scope all --u-ppm 1000000 --peak PCAN_USBBUS1
```

Host tools need Python 3.9+, `python-can`, and `pyserial`. `fake_board.py` is a software
emulation used only to test the host tools; no reported number comes from it.

## Counted cells

All cells ran through the switch with the PEAK capture on; no trial was invalid. `U* = 3770`
ppm was fixed from C4 before C5 to C9 ran (`runs/sweep_params.json`), and the held-out
parameters were frozen before scoring (`runs/heldout_params.json`, `runs/params.json`).

| Cell | Scope | Families | U, background | Trials |
|---|---|---|---|---|
| C1 | all (offline subsets) | S1, S2, S3, S6 | full, none | 60 |
| C2, C2b | all | S4, S5 (C2b: same value) | full, none | 60, 60 |
| C2c | all | S4, same value, writes at most 2.5 ms apart | full, none | 30 |
| C3 | gw (live) | S1, S2, S3, S6 | full, none | 30 |
| C4 | all | S1, S2, S3, S6 | full, 2000 pps | 20 |
| C5 to C8 | all | S1, S2, S3, S6 | 2U* to U*/4, 2000 pps | 4 x 40 |
| C9 | all | S1, S2, S3, S6 | 20 ppm, 2000 pps | 20 |
| C10, C11, C12 | all | S7-A, S7-B, S7-C | full, none | 3 x 30 |
| C13a, C13b | all | S7-A | U*, U*/2, 2000 pps | 2 x 30 |
| C14 | all | S4 | U*/4, 2000 pps | 20 |
| E7_gw, E7_dst, E7_all | gw, dst, all | S1 | U*/2, 2000 pps | 3 x 20 |
| B0 (`runs/B0.zip`) | all | S5, S6 (benign only) | full, 500 pps | 8727 (5.3 h) |
| FX100, FX075, FX050, FX025, FX000 | all (scored offline per scope) | S1, gw observer forged at random, alpha = 1, 0.75, 0.5, 0.25, 0 | full, none | 5 x 30 |
| FA | all (scored offline per scope) | S1, gw observer forged after the attacker's write | full, none | 30 |

The forgery cells (12 November 2026, parameters frozen in `runs/forgery_params.json`) emulate a
compromised gw observer in firmware (`src/observers.c`, modes `FORGE_EXO` and `FORGE_ATTACK`,
set per trial by `run_bench.py --forge exo|attack --forge-alpha A`). A replaced genuine report
stays in the delivery log with status `forged_out`; the forgery is delivered and flagged. The
reference chain uses genuine reports only, and a forgery stands in for the report it replaced
when claims are scored. Summary: `python forgery_report.py ../runs` (written to
`runs/forgery_summary.json`). The observers share one chip, so their separation is a design
choice, not enforced by hardware.

`C1_noswitch` is a copy of C1 run with the PC cabled directly to the board; it gave identical
results and is not counted. `B0_partial_sleep.zip` is a first B0 attempt that stopped after
580 trials when the host went into standby; it is not counted.

Each `runs/<cell>/` holds `cell.json` (the frozen command-line parameters) and one
`trial_NNNN.json` per trial: ground truth and tester log, the PEAK capture, and the full
dump of the board's counters, delivery log, IDS log, window log, and impact log.

## Analysis

`python/analyze.py` builds the reference chain from the complete delivery log and the impact
log, applies the report format (F1 to F4) and an optional offline scope filter, and scores
P_chain with Wilson intervals. Every miss is attributed to insufficiency, processing, or
ambiguity. It also checks the PEAK capture and the tester logs against the observers.
`python/predict.py` fits the failure-region models on the calibration families (S1 to S3)
and tests them on the held-out families (S4, S7) without refitting.

One fix was made to the reference during the analysis. When two writes put the same value
on the same ECU, the impact log cannot tell which write caused which impact; the reference
first gave the attacker the first impact in every case. It now pairs such impacts with writes
in write order, which is exact because the impact delay is constant in those cells. Every
cell was re-scored, and cells without two such writes did not change.

## Limits

DoIP messages are carried over UDP rather than TCP. All observers and both target ECUs run on
one chip, so the scope controls which information reaches the IDS rather than where sensors
sit, and forgery is not tested. The bench tests the failure region only.
