#!/usr/bin/env python3
"""prior_sensitivity.py: how the detection bar moves with the narrative prior.

Usage:
    python prior_sensitivity.py

Per-stage technique counts are ATM v4.02 scoped to the threat model (hv_atm.py):
    IA 5, PES 7, C2 6, LM 6, IMP 6.
Each prior below fixes P(a | tau) per stage; the tactic order is fixed, so
H(V) is the sum of the per-stage entropies. Rows:
  uniform   : the paper's DAG prior (least informative)
  zipf s=1  : technique of rank r has probability ~ 1/r
  zipf s=2  : technique of rank r has probability ~ 1/r^2 (strongly skewed)
  dominant  : one technique carries probability 0.9, the rest share 0.1
  full ATM  : uniform over the unscoped counts (8, 8, 6, 6, 8)
  no DAG    : uniform over all 77 active techniques at each of 5 steps
For every prior the script also prints 1 - max_a P(a) for the impact stage: the
error of the best guess with no observation at all, which is the floor that the
coverage corollary gives for a stage no observer records.
"""
import math

SCOPED = {"IA": 5, "PES": 7, "C2": 6, "LM": 6, "IMP": 6}
FULL = {"IA": 8, "PES": 8, "C2": 6, "LM": 6, "IMP": 8}
PREFIX = ["IA", "PES", "C2", "LM"]
LATTE_C = 7.0    # bits per window, audit.py scenario at U = 1.5% (7 reports max)
T_W = 0.1


def windows(h):
    """First window n with n * LATTE_C >= h (zero-error bar, Corollary cor:dwell)."""
    return 0 if h <= 0 else math.ceil(h / LATTE_C)


def H(p):
    return -sum(x * math.log2(x) for x in p if x > 0)


def uniform(n):
    return [1.0 / n] * n


def zipf(n, s):
    w = [1.0 / (r ** s) for r in range(1, n + 1)]
    z = sum(w)
    return [x / z for x in w]


def dominant(n, top=0.9):
    return [top] + [(1 - top) / (n - 1)] * (n - 1)


PRIORS = [
    ("uniform (paper)", lambda n: uniform(n), SCOPED),
    ("Zipf, s=1", lambda n: zipf(n, 1), SCOPED),
    ("Zipf, s=2", lambda n: zipf(n, 2), SCOPED),
    ("dominant, 0.9", lambda n: dominant(n), SCOPED),
    ("uniform, full ATM", lambda n: uniform(n), FULL),
]


def main():
    print(f"{'prior':<20} {'H(V)':>6} {'prefix':>7} {'H_IMP':>6} {'1-maxP_IMP':>11} "
          f"{'LATTE n_min':>12}")
    for name, f, counts in PRIORS:
        hs = {st: H(f(n)) for st, n in counts.items()}
        hv = sum(hs.values())
        hp = sum(hs[s] for s in PREFIX)
        hi = hs["IMP"]
        floor = 1 - max(f(counts["IMP"]))
        print(f"{name:<20} {hv:>6.2f} {hp:>7.2f} {hi:>6.2f} {floor:>11.2f} {windows(hi):>9} win")
    hv = 5 * math.log2(77)
    print(f"{'no DAG, 77 each':<20} {hv:>6.2f} {4*math.log2(77):>7.2f} {math.log2(77):>6.2f} "
          f"{1-1/77:>11.2f} {windows(math.log2(77)):>9} win")


if __name__ == "__main__":
    main()
