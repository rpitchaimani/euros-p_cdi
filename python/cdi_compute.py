#!/usr/bin/env python3
"""
cdi_compute.py: CDI information budget (Theorem thm:main, Eq. cdi)

Implements, per observer o (per-window units):
    alpha_o(j) = P(no exogenous failure by step j) [authenticity, Eq. alpha; default 1]
    c(G, j)    = sum_o alpha_o(j) * m_o(j) * rho_o [per-window budget, bits per window]
    C_<=n      = sum_{s=1..n} c(G, j(s))           [cumulative budget, bits by window n]
    n_min      = first n with C_<=n >= b_eps                         [Corollary cor:dwell]
    b_eps      = H(phi) - h2(eps) - eps*log2(|T|-1); b_0 = H(phi) (zero error forces I = H)
  The budget is an upper bound on report entropy, not a Shannon capacity.
  alpha_o is an explicit input. It must describe a failure that is independent of
  the attack's techniques (Assumption ass:oblivious). Never pass a route-compromise
  probability (theta) here: a too-small alpha lowers an upper bound and produces a
  false error floor. The audit uses alpha = 1.
  The sum over observers uses entropy subadditivity and ignores overlap (Remark ass:corr).
  A cut time that depends on the technique must not be passed to windows_needed:
  Theorem thm:main does not apply to it, although the library will compute a number.

This file is a library plus a UART-log parser. It contains no per-system parameter
values: the audit of published systems is audit.py, driven by audit_worksheet.csv.

Usage:
    python cdi_compute.py --uart ids.txt   # parse the hardware UART log
    python cdi_compute.py --demo           # worked example with explicit inputs
"""
import argparse, math, sys
from dataclasses import dataclass, field
from typing import List


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass
class Observer:
    name:  str
    m:     float          # sampling coverage while the observer's input is intact (fraction 0-1)
    rho:   float          # richness: reports per window x entropy per report (bits per window)
    cut_at: int = 10**9   # first step j at which the input is cut (m_o(j) = 0 from then on);
                          # must not depend on the technique (Assumption ass:oblivious)
    alpha_exo: float = 1.0  # exogenous authenticity, independent of V (default: most favorable)
    cut_caused_by_technique: bool = False  # True if the chosen technique causes the cut;
                                           # then Theorem thm:main does not apply

    def m_at(self, j: int) -> float:
        return 0.0 if j >= self.cut_at else self.m

    def alpha(self, j: int) -> float:
        return self.alpha_exo


def budget(observers: List[Observer], j: int) -> float:
    """
    Compute C_CDI(G, j) = sum_o alpha_o(j) m_o(j) rho_o for attack step j.
    Returns the per-window budget in bits per window (>= 0).
    Refuses an observer whose cut is caused by the technique: the budget bound
    does not hold for it, and only the pathwise result (prop:pathwise) remains.
    """
    bad = [o.name for o in observers if o.cut_caused_by_technique and o.cut_at < 10**9]
    if bad:
        raise ValueError("technique-caused cut for " + ", ".join(bad) +
                         ": Assumption ass:oblivious(iv) fails, no budget is computed")
    return sum(o.alpha(j) * o.m_at(j) * o.rho for o in observers)


T_W = 0.1  # detection window length in seconds (100 ms, Section 9)


def cumulative_budget(observers: List[Observer], schedule: List[int]) -> float:
    """C_<=n: sum of per-window budgets over windows s=1..n, where schedule[s-1] = j(s)."""
    return sum(budget(observers, j) for j in schedule)


def h2(p: float) -> float:
    """Binary entropy in bits."""
    return 0.0 if p in (0.0, 1.0) else -p * math.log2(p) - (1 - p) * math.log2(1 - p)


def windows_needed(per_window: List[float], H_phi: float, eps: float = 0.0,
                   T_size: int = 2) -> float:
    """First window n (1-based) at which the cumulative budget reaches the bar
    b_eps = H_phi - h2(eps) - eps*log2(T_size - 1) (Corollary cor:dwell), valid for
    eps <= 1 - 1/T_size. For eps = 0 the bar is H_phi. per_window[s-1] is the budget
    of window s; the list ends at the blinding window s*, which must not depend on
    the technique. Returns inf if the bar is never reached before s*. Necessary,
    not sufficient."""
    bar = max(0.0, H_phi - h2(eps) - eps * math.log2(max(T_size - 1, 1)))
    if bar == 0:
        return 0
    total = 0.0
    for n, c in enumerate(per_window, start=1):
        total += c
        if total >= bar:
            return n
    return math.inf


def fmt_time(t: float) -> str:
    if math.isinf(t):
        return "never"
    for lim, div, unit in ((60, 1, "s"), (3600, 60, "min"), (86400, 3600, "h")):
        if t < lim:
            return f"{t/div:.1f} {unit}"
    return f"{t/86400:.1f} d"


# ---------------------------------------------------------------------------
# Miller-Madow entropy estimator (matches C firmware Q5.3 implementation)
# ---------------------------------------------------------------------------

def miller_madow(counts: List[int]) -> float:
    """
    H_MM = H_MLE + (k_hat - 1) / (2*N)
    counts: histogram bucket counts
    Returns entropy in bits.
    """
    N = sum(counts)
    if N == 0:
        return 0.0
    k_hat = sum(1 for c in counts if c > 0)
    h_mle = -sum((c / N) * math.log2(c / N) for c in counts if c > 0)
    return h_mle + (k_hat - 1) / (2.0 * N)


# ---------------------------------------------------------------------------
# Utilities
# ---------------------------------------------------------------------------

def parse_uart_log(path: str):
    """
    Parse IDS UART log produced by core1_ids.c.
    Lines match: [IDS] #N t=T  pkts=P  ...  H=E  MIRROR=C  PHASE
    (older firmware logs name the same field CCDI). Returns a list of
    (window, entropy_fp, mirror, phase) tuples. The field is 3.0 x (mirror enabled),
    an indicator rather than bits, and it is not the budget C^CDI. The H field is
    not used for any number in the paper.
    """
    import re
    results = []
    pat = re.compile(r'\[IDS\] #(\d+).*H=(\d+).*(?:MIRROR|CCDI)=([\d.]+)\s+(\w+)')
    try:
        with open(path) as f:
            for line in f:
                m = pat.search(line)
                if m:
                    win   = int(m.group(1))
                    h_fp  = int(m.group(2))          # Q5.3 fixed-point (/ 8 = bits)
                    flag  = float(m.group(3))
                    phase = m.group(4)
                    results.append((win, h_fp / 8.0, flag, phase))
    except FileNotFoundError:
        print(f"[warn] log file not found: {path}", file=sys.stderr)
    return results


def print_uart_summary(records):
    if not records:
        print("No IDS records parsed.")
        return
    print(f"\n{'Win':>5} {'H(bits)':>9} {'mirror':>8}  Phase")
    print("-" * 35)
    for win, h, flag, phase in records[:50]:
        mirror = "on" if flag > 0 else "off"   # mirror_en flag, not bits
        marker = " *** INPUT CUT" if mirror == "off" and phase not in ("NONE",) else ""
        print(f"{win:>5} {h:>9.3f} {mirror:>8}  {phase}{marker}")
    if len(records) > 50:
        print(f"  ... {len(records)-50} more windows")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def demo():
    """Worked example with explicit, labelled inputs (not a measurement).
    One observer, binary output (rho = 7 b/window, as LATTE in audit.py), most
    favorable exogenous authenticity alpha = 1, input cut at step 3 (a fixed step,
    independent of the technique). Single-stage task H_IMP = log2(6) bits
    (hv_atm.py, scoped)."""
    obs = [Observer("example", m=1.0, rho=7.0, cut_at=3)]
    schedule = [0, 1, 2, 3, 3, 3]           # j(s) for windows s = 1..6
    per_window = [budget(obs, j) for j in schedule]
    s_star = next((i for i, c in enumerate(per_window) if c == 0), len(per_window))
    H_IMP = math.log2(6)
    print("per-window budget:", per_window)
    print("cumulative budget at s*-1:", cumulative_budget(obs, schedule[:s_star]))
    n = windows_needed(per_window[:s_star], H_IMP)
    print(f"first window reaching the zero-error bar H_IMP = {H_IMP:.2f} b: {n} "
          f"(T_min = {n*T_W*1000:.0f} ms; necessary only)")


def main():
    parser = argparse.ArgumentParser(description="CDI information budget (Theorem thm:main)")
    parser.add_argument("--uart", metavar="FILE",
                        help="Parse hardware UART IDS log from core1_ids.c")
    parser.add_argument("--demo", action="store_true", help="Run the worked example")
    args = parser.parse_args()

    if args.uart:
        print(f"Parsing UART log: {args.uart}")
        print_uart_summary(parse_uart_log(args.uart))
    elif args.demo:
        demo()
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
