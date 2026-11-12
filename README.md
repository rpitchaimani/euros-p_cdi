# Artifact: Architectural limits of intrusion detectability (Cross-Domain Inference)

Anonymous artifact for the IEEE Euro S&P 2027 submission. It contains everything needed
to reproduce the paper's computed numbers and its hardware results:

1. the analysis scripts for the audit, the narrative entropies, the prior sensitivity,
   the information budget, the brute-force check of the attacker-timed-cut bound, and the
   platform CVE table (`python/`, `data/`);
2. the bench: firmware for the three cores of the NXP MPC5748G gateway, the fixed
   switch configuration, the host scripts that run and analyze the cells, and the raw
   logs of every counted run (`bench/`).

The bench uses no exploit and was run only on development boards in a laboratory.
Nothing is withheld.

## Layout

| Path | Contents | Paper |
|---|---|---|
| `python/audit_worksheet.csv` | One row per audited detector (14), with the source of every value and the basis of the stage mapping | Section 6 |
| `python/audit.py` | Writes the audit table and the LATTE scenario from the worksheet alone | Tables 3, 4 |
| `python/hv_atm.py`, `data/atm_v4.02_techniques.csv` | Narrative entropies H(V), prefix and single-stage bars, from the Auto-ISAC ATM v4.02 technique lists (exported from the public STIX bundle) | Section 4.4 |
| `python/prior_sensitivity.py` | The six-prior sensitivity table | Table 12 |
| `python/cdi_compute.py` | Equation 3 with the authenticity alpha as an explicit input (default 1), the cumulative budget, and the window condition of Corollary 5.7 | Section 5 |
| `python/check_prop_timed.py` | Brute-force check of Proposition 5.6 on random finite models | Section 5 |
| `python/nvd_platforms.py`, `python/nvd_raw/` | Platform CVE table, rebuilt offline from the saved NVD responses | Table 10 |
| `bench/` | Bench firmware, host scripts, and run data; see `bench/README.md` | Section 7, Appendix I |

## Reproduce the analysis (Python 3.9+, standard library only)

```
cd python
python audit.py audit_worksheet.csv                 # audit verdicts and LATTE sweep
python audit.py audit_worksheet.csv --write-tex     # also writes ../tables/casestudy.tex, latte.tex
python hv_atm.py ../data/atm_v4.02_techniques.csv   # scoped H(V) = 12.88 b, prefix 10.30 b, impact 2.58 b
python prior_sensitivity.py                        # prior table
python cdi_compute.py --demo                       # budget, cumulative budget, window condition
python check_prop_timed.py                         # bound holds in every random model
python nvd_platforms.py --offline 2026-11-05       # platform table from the saved responses
```

## Reproduce the bench results from the logs (no hardware needed)

```
cd bench/python
python analyze.py ../runs/C1 --rep F3              # all observers: P_chain 24/24
python analyze.py ../runs/C1 --rep F3 --scope gw   # one observer: 0/24, insufficiency
python analyze.py ../runs/C12 --rep F3             # link in no report: 17/30 = 0.57
python analyze.py ../runs/C2 --rep F4              # aggregated alerts lose the link: 0/30
python predict.py test --cells ../runs/C2 ../runs/C10 ../runs/C11 ../runs/C12 \
       ../runs/C13a ../runs/C13b ../runs/C14 --families S4,S7 --params ../runs/params.json
python forgery_report.py ../runs                   # forged gw observer: P_chain falls with alpha (E5)
```

`bench/runs/<cell>_F3.json` holds the analysis summary of each cell as reported in the paper.
The benign baseline B0 (8727 trials) is in `bench/runs/B0.zip`; unzip it into `bench/runs/`
before running `analyze.py ../runs/B0`.

## License

MIT (see `LICENSE`). The ATM technique list is derived from the public Auto-ISAC ATM STIX
bundle, and the files in `python/nvd_raw/` are unmodified NVD API responses.
