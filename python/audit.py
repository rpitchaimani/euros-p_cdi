#!/usr/bin/env python3
"""audit.py: coverage verdicts and single-stage budget scenarios from audit_worksheet.csv.

Usage:
    python audit.py [audit_worksheet.csv] [--write-tex]

With --write-tex the script also writes ../tables/casestudy.tex (Table 2) and
../tables/latte.tex (Table 3). These two tables have no other writer.

Two outputs, kept apart on purpose.

1. Coverage (no numbers needed). The script reports whether a system is mapped
   to every pre-impact tactic (IA, PES, C2, LM), as mapped_all_pre_impact. A "no"
   is a property of our mapping. Corollary cor:coverage turns it into "cannot
   identify" only if the missing tactic leaves no other trace in the system's
   sensors; the script does not check that condition. A row whose basis is the
   title alone has an empty stage label, is reported as "not read", and is left
   out of Table 2. The stage mapping is the paper's mapping of each system onto
   the five-stage running example, not a claim made by the source paper. Column
   stage_mapping_basis says what it rests on. OTHER marks a system that watches a
   bus this chain does not use ("other bus"); such rows answer a different
   question. The Execution tactic is folded into IA, so there is no EX column.

2. Single-stage budget (a loose scenario ceiling, not a measured value). The
   notation is the paper's (Definitions def:richness and def:sampling):
     n_o   = ceil(rate * T_w), the largest number of reports in one window
             (an average count is not an upper bound),
     h_o   = log2(k), the alphabet ceiling of one alert with k output classes,
     rho_o = n_o * h_o, bits per window,
     k_cpu = floor(U * T_w / latency), whole reports the CPU share U allows,
     m_o   = min(1, k_cpu / n_o), a fraction,
   and the budget term is m_o * rho_o bits per window, with alpha_o = 1.
   The latency is an average, not the best-case time of Definition 5.2, and
   acquisition, queueing and batching are ignored.  A faster best case would raise
   k_cpu, so counts below n_o are not certified ceilings; m_o = 1 always is. No standard fixes U, so the
   script sweeps it, and no point of the sweep is preferred. A value is computed
   only for rows marked budget_comparable = yes (embedded-class CPU with a
   reported per-report latency). Every other row stays unresolved.

The window count is the zero-error necessary condition of Corollary cor:dwell:
the first window n with n * c >= H_k. Zero error forces I(phi; W) = H(phi), so
the bar is H_k rather than H_k - 1. It is not a measured dwell, and reaching it
does not show that a detector succeeds. The budget bounds what a rule can learn
from this classifier's alerts. It is not the architectural budget of the bus.
Task entropies come from the scoped technique counts of hv_atm.py (ATM v4.02).
"""
import csv
import math
import os
import sys

T_W = 0.1                                   # detection window, s
U_SWEEP = [0.001, 0.005, 0.015, 0.05]       # assumed monitoring CPU shares, equal weight

# Scoped per-stage technique entropies, bits (hv_atm.py, ATM v4.02)
H_STAGE = {"IA": math.log2(5), "PES": math.log2(7),
           "C2": math.log2(6), "LM": math.log2(6), "IMP": math.log2(6)}
PREFIX = ["IA", "PES", "C2", "LM"]          # steps before impact in the running example
TEX_STAGE = {"IA": r"$\tIA$", "PES": r"$\tPES$", "C2": r"$\tCC$", "LM": r"$\tLM$", "IMP": r"$\tIMP$"}

HERE = os.path.dirname(os.path.abspath(__file__))
WORDS = {7: "seven", 8: "eight", 9: "nine", 10: "ten", 11: "eleven", 12: "twelve",
         13: "thirteen", 14: "fourteen"}


def terms(row, u):
    """(n_o, h_o, k_cpu, m_o, rho_o) for one monitor at CPU share u, or None."""
    if row.get("budget_comparable") != "yes":
        return None
    if not row["latency_s"] or not row["classes"] or not row["events_per_s"]:
        return None
    n_o = math.ceil(float(row["events_per_s"]) * T_W - 1e-9)
    h_o = math.log2(int(row["classes"]))
    k_cpu = math.floor(u * T_W / float(row["latency_s"]))   # whole reports only
    m_o = 0.0 if n_o == 0 else min(1.0, k_cpu / n_o)
    return n_o, h_o, k_cpu, m_o, n_o * h_o


def budget(row, u):
    t = terms(row, u)
    return None if t is None else t[3] * t[4]


def windows_needed(c, h):
    """First n with n*c >= h (zero-error bar, Corollary cor:dwell); None if c unknown."""
    if c is None:
        return None
    if h <= 0:
        return 0
    return math.inf if c == 0 else math.ceil(h / c - 1e-9)


def fmt_n(n):
    if n is None:
        return "unresolved"
    if math.isinf(n):
        return "never"
    return str(n)


def stages_of(r):
    return [s for s in r["stages_covered"].split(";") if s]


def verdict(r):
    stages = stages_of(r)
    if r["stage_mapping_basis"] == "title only":
        return "not read"
    if stages == ["OTHER"]:
        return "other bus"
    if all(s in stages for s in PREFIX):
        return "yes"
    if any(s in stages for s in PREFIX):
        return "partial (" + ", ".join(s for s in PREFIX if s in stages) + ")"
    return "no"


def tex_verdict(v):
    if v.startswith("partial"):
        inner = v[len("partial ("):-1].split(", ")
        return "partial (" + ", ".join(TEX_STAGE[s] for s in inner) + ")"
    return v


def tex_stages(r):
    stages = stages_of(r)
    if stages == ["OTHER"]:
        return "other bus"
    cell = ", ".join(TEX_STAGE[s] for s in stages)
    if "not settled" in r["monitor_placement"]:
        cell += " (placement unknown)"
    return cell


def write_table2(rows, path):
    read = [r for r in rows if r["stage_mapping_basis"] != "title only"]
    unread = [r for r in rows if r["stage_mapping_basis"] == "title only"]
    if unread:
        names = ", ".join(r["system"] for r in unread[:-1]) + ", and " + unread[-1]["system"]
        cites = ",".join(r["bibkey"] for r in unread)
        unread_txt = (names + r"~\cite{" + cites + r"}"
                      r" were read only as far as the title, so they are not mapped and are used in no claim.")
    else:
        unread_txt = r"We read every system in full."
    out = [
        "% Generated by python/audit.py --write-tex from python/audit_worksheet.csv. Do not edit by hand.",
        r"\begin{table*}[!t]",
        r"\centering",
        r"\caption{\textbf{CDI audit: the " + WORDS.get(len(read), str(len(read))) + r" systems we read.} \textbf{Stages} is our mapping"
        r" of each system onto the five-stage running example (\texttt{audit\_worksheet.csv}), rather than a claim"
        r" of the source paper. Execution is folded into $\tIA$. \textbf{Basis} says what the mapping rests on."
        r" ``Other bus'' marks a system that watches a bus this chain does not use. The last column is a property"
        r" of our mapping. A ``no'' does not mean ``cannot identify'' unless the missing tactics leave no other"
        r" trace (Corollary~\ref{cor:coverage}), which we do not establish. " + unread_txt +
        r" n.a.: not assessable from the material we have; n.r.: the paper does not report it;"
        r" n.c.: reported, but not comparable. Generated by \texttt{audit.py}.}",
        r"\label{tab:cs_audit11}",
        r"\footnotesize",
        r"\setlength\tabcolsep{3pt}",
        r"\resizebox{\textwidth}{!}{%",
        r"\begin{tabular}{@{}lllllllc@{}}",
        r"\toprule",
        r"\textbf{System} & \textbf{Observes} & \textbf{Platform (as reported)} & \textbf{Stages} & \textbf{Basis}"
        r" & \textbf{Per-report latency} & \textbf{Classes $k$} & \textbf{Mapped to every pre-impact tactic?} \\",
        r"\midrule",
    ]
    for r in read:
        out.append(" & ".join([
            r["system"] + r"~\cite{" + r["bibkey"] + "}", r["table_observes"], r["table_platform"],
            tex_stages(r), r["stage_mapping_basis"], r["table_latency"], r["classes"] or "n.a.",
            tex_verdict(verdict(r))]) + r" \\")
    out += [r"\bottomrule", r"\end{tabular}}", r"\end{table*}", ""]
    open(path, "w", encoding="utf-8", newline="\n").write("\n".join(out))


def write_table3(row, path):
    t = [terms(row, u) for u in U_SWEEP]
    n_o, h_o = t[0][0], t[0][1]
    h = H_STAGE["IMP"]
    shares = " & ".join(f"${u * 100:g}\\%$" for u in U_SWEEP)
    out = [
        "% Generated by python/audit.py --write-tex from python/audit_worksheet.csv. Do not edit by hand.",
        r"\begin{table}[t]",
        r"\centering",
        r"\caption{\textbf{" + row["system"] + r" single-stage scenario} (\texttt{audit.py}). $n_o = "
        + str(n_o) + r"$ reports can arrive in a $T_w = 100$\,ms window, each alert has $h_o \le "
        + f"{h_o:g}" + r"$\,bit, so $\rho_o = " + f"{n_o * h_o:g}" + r"$\,bits. $k_{\mathrm{CPU}} = \lfloor U T_w/\ell \rfloor$"
        r" uses the mean latency $\ell$ on a developer board rather than a best-case time. A faster best case would raise it, so only the columns with $m_o = 1$ are certain ceilings."
        r" $m_o = \min(1, k_{\mathrm{CPU}}/n_o)$ and $\alpha_o = 1$. Every share is assumed, and none is preferred."
        r" The last row is the zero-error necessary condition for $H_{\mathrm{IMP}} = "
        + f"{h:.2f}" + r"$\,b rather than a dwell.}",
        r"\label{tab:latte}",
        r"\footnotesize",
        r"\setlength\tabcolsep{4pt}",
        r"\begin{tabular}{@{}lcccc@{}}",
        r"\toprule",
        r"Assumed CPU share $U$ & " + shares + r" \\",
        r"\midrule",
        r"Reports the share allows, $k_{\mathrm{CPU}}$ & " + " & ".join(f"${x[2]}$" for x in t) + r" \\",
        r"Sampling $m_o$ & " + " & ".join(f"${x[2]}/{n_o}$" if 0 < x[3] < 1 else f"${x[3]:g}$" for x in t) + r" \\",
        r"Budget $m_o \rho_o$ (bits/window) & " + " & ".join(f"${x[3] * x[4]:g}$" for x in t) + r" \\",
        r"First window with $\Ccum{n} \ge H_{\mathrm{IMP}}$ & "
        + " & ".join(fmt_n(windows_needed(x[3] * x[4], h)) for x in t) + r" \\",
        r"\bottomrule",
        r"\end{tabular}",
        r"\end{table}",
        "",
    ]
    open(path, "w", encoding="utf-8", newline="\n").write("\n".join(out))


def main():
    args = [a for a in sys.argv[1:] if a != "--write-tex"]
    path = args[0] if args else os.path.join(HERE, "audit_worksheet.csv")
    rows = list(csv.DictReader(open(path, encoding="utf-8")))
    print(f"T_w = {T_W*1000:.0f} ms\n")
    print(f"{'System':<12} {'stages':<8} {'mapping basis':<14} {'mapped_all_pre_impact':>22}  status")
    for r in rows:
        print(f"{r['system']:<12} {r['stages_covered'] or '--':<8} {r['stage_mapping_basis']:<14} "
              f"{verdict(r):>22}  {r['status']}")
    basis = [r["stage_mapping_basis"] for r in rows]
    print("\nmapping basis: " + ", ".join(f"{b}: {basis.count(b)}"
                                          for b in ("full text", "abstract", "title only")))

    print("\nCPU-share sweep (rows with budget_comparable = yes), alpha = 1:")
    for r in rows:
        if r.get("budget_comparable") != "yes":
            continue
        h1 = min(H_STAGE[s] for s in stages_of(r))
        for u in U_SWEEP:
            n_o, h_o, k_cpu, m_o, rho_o = terms(r, u)
            c = m_o * rho_o
            print(f"{r['system']:<12} U={u:.1%}: n_o={n_o} h_o={h_o:g} rho_o={rho_o:g} "
                  f"k_cpu={k_cpu} m_o={m_o:.3f} budget={c:g} b/window, "
                  f"first window >= H={h1:.2f}: {fmt_n(windows_needed(c, h1))}")
    not_cmp = [r["system"] for r in rows if r.get("budget_comparable") == "no"]
    if not_cmp:
        print(f"\nnot comparable (reason in the source column): {', '.join(not_cmp)}")

    if "--write-tex" in sys.argv:
        tables = os.path.join(HERE, "..", "tables")
        write_table2(rows, os.path.join(tables, "casestudy.tex"))
        latte = [r for r in rows if r.get("budget_comparable") == "yes"]
        write_table3(latte[0], os.path.join(tables, "latte.tex"))
        print("\nwrote tables/casestudy.tex and tables/latte.tex")


if __name__ == "__main__":
    main()
