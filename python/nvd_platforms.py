"""Count NVD CVE records for commercial automotive OS and hypervisor platforms.

This script is the only writer of tables/platforms.tex (Appendix table
tab:platforms). It shows why published CVE counts cannot calibrate the trust
gap Gamma_o (Section 6). It does not compute Gamma_o, rank the platforms, or
turn counts into probabilities.

Method
  * Counts come from the NVD CVE API 2.0 with virtualMatchString set to a CPE
    prefix and noRejected set. A product with several CPE names is the union
    of their CVE IDs.
  * A product with no CPE name in the NVD CPE dictionary is reported as
    "no NVD product entry", never as zero. For these we also record how many
    CVE descriptions mention the product name (keywordSearch).
  * Raw API responses are saved under python/nvd_raw/<query date>/ so the
    table can be checked without querying NVD again.

Usage
  python nvd_platforms.py              # query NVD, save raw JSON, write table
  python nvd_platforms.py --offline D  # rebuild the table from nvd_raw/D
"""
import argparse
import datetime
import json
import os
import time
import urllib.parse
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
CVE_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
PAUSE = 7  # seconds; the public NVD API allows 5 requests per 30 s

# (supplier, product as named by the supplier, type, CPE prefixes, keyword)
PLATFORMS = [
    ("Green Hills", "INTEGRITY", "OS",
     ["cpe:2.3:o:ghs:integrity_rtos"], "INTEGRITY RTOS"),
    ("Green Hills", "INTEGRITY Multivisor", "HV", [], "Multivisor"),
    ("QNX", "QNX OS", "OS",
     ["cpe:2.3:o:blackberry:qnx_neutrino_rtos",
      "cpe:2.3:o:blackberry:qnx_neutrino_real-time_operating_system",
      "cpe:2.3:o:blackberry:qnx_os_for_safety",
      "cpe:2.3:o:blackberry:qnx_os_for_medical",
      "cpe:2.3:a:blackberry:qnx_software_development_platform"], None),
    ("QNX", "QNX Hypervisor", "HV",
     ["cpe:2.3:a:blackberry:qnx_hypervisor",
      "cpe:2.3:a:blackberry:qnx_hypervisor_for_safety"], "QNX Hypervisor"),
    ("Wind River", "VxWorks", "OS",
     ["cpe:2.3:o:windriver:vxworks"], None),
    ("Wind River", "VxWorks virtualization profile", "HV", [],
     "VxWorks virtualization"),
    ("Sysgo", "PikeOS (native and hypervisor)", "OS/HV", [], "PikeOS"),
    ("Mentor (Siemens)", "Nucleus RTOS", "OS",
     ["cpe:2.3:o:siemens:nucleus_rtos",
      "cpe:2.3:a:siemens:nucleus_net",
      "cpe:2.3:a:siemens:nucleus_source_code",
      "cpe:2.3:a:siemens:nucleus_readystart",
      "cpe:2.3:a:siemens:nucleus_readystart_v3",
      "cpe:2.3:a:siemens:nucleus_readystart_v4",
      "cpe:2.3:a:siemens:nucleus_4",
      "cpe:2.3:a:siemens:nucleus_safetycert"], None),
    ("Mentor (Siemens)", "Mentor Embedded Hypervisor", "HV", [],
     "Mentor Embedded Hypervisor"),
    ("Lynx", "LynxOS", "OS", [], "LynxOS"),
    ("Lynx", "LynxSecure", "HV", [], "LynxSecure"),
    ("OpenSynergy", "RT-Linux", "OS", None, None),  # kernel = Linux reference row
    ("OpenSynergy", "COQOS Hypervisor", "HV", [], "COQOS"),
]
# Reference row: the kernel under a Linux partition (also under RT-Linux).
LINUX = ("Linux kernel (reference)", ["cpe:2.3:o:linux:linux_kernel"])


def get(params, raw_dir, tag):
    url = CVE_API + "?" + urllib.parse.urlencode(params)
    for attempt in range(5):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "cdi-audit-script"})
            data = json.load(urllib.request.urlopen(req, timeout=120))
            break
        except Exception as exc:  # network errors and 403 rate limits
            print("  retry", tag, exc, flush=True)
            time.sleep(15)
    else:
        raise RuntimeError("NVD query failed: " + url)
    with open(os.path.join(raw_dir, tag + ".json"), "w", encoding="utf-8") as fh:
        json.dump({"url": url, "response": data}, fh)
    time.sleep(PAUSE)
    return data


def all_ids(cpe, raw_dir, tag):
    """CVE IDs matching a CPE prefix, following pagination."""
    ids, start, page = set(), 0, 0
    while True:
        d = get({"virtualMatchString": cpe, "noRejected": "", "resultsPerPage": 2000,
                 "startIndex": start}, raw_dir, f"{tag}_p{page}")
        ids |= {v["cve"]["id"] for v in d.get("vulnerabilities", [])}
        start += d.get("resultsPerPage", 0)
        page += 1
        if start >= d.get("totalResults", 0) or d.get("resultsPerPage", 0) == 0:
            return ids, d.get("totalResults", 0)


def years(ids):
    ys = sorted(int(i.split("-")[1]) for i in ids)
    if not ys:
        return ""
    return str(ys[0]) if ys[0] == ys[-1] else f"{ys[0]}--{ys[-1]}"


def query(raw_dir):
    rows = []
    for k, (sup, prod, typ, cpes, kw) in enumerate(PLATFORMS):
        print(prod, flush=True)
        if cpes is None:
            rows.append(dict(supplier=sup, product=prod, type=typ, cpes=[], count="linux"))
            continue
        if cpes:
            ids = set()
            for m, cpe in enumerate(cpes):
                got, _ = all_ids(cpe, raw_dir, f"r{k:02d}_cpe{m}")
                ids |= got
            row = dict(supplier=sup, product=prod, type=typ, cpes=cpes,
                       count=len(ids), years=years(ids), ids=sorted(ids))
            if kw:  # cross-check: records whose description names the product
                d = get({"keywordSearch": kw, "noRejected": "", "resultsPerPage": 200},
                        raw_dir, f"r{k:02d}_kw")
                row["keyword"], row["keyword_hits"] = kw, d.get("totalResults", 0)
            rows.append(row)
        else:
            d = get({"keywordSearch": kw, "noRejected": "", "resultsPerPage": 200},
                    raw_dir, f"r{k:02d}_kw")
            rows.append(dict(supplier=sup, product=prod, type=typ, cpes=[],
                             count=None, keyword=kw,
                             keyword_hits=d.get("totalResults", 0)))
    print(LINUX[0], flush=True)
    d = get({"virtualMatchString": LINUX[1][0], "noRejected": "", "resultsPerPage": 1},
            raw_dir, "linux_total")
    rows.append(dict(supplier="Linux", product=LINUX[0], type="OS", cpes=LINUX[1],
                     count=d.get("totalResults", 0), years=""))
    return rows


def write_tex(rows, date, path):
    def cell(r):
        if r["count"] == "linux":
            return "see Linux kernel row"
        if r["count"] is None:
            hits = r["keyword_hits"]
            return ("no NVD entry" +
                    ("" if hits == 0 else f"; {hits} records name it"))
        return f"{r['count']:,}".replace(",", "{,}") + (f" ({r['years']})" if r["years"] else "")
    lines = [
        "% Generated by python/nvd_platforms.py from python/nvd_raw/" + date +
        ". Do not edit by hand.",
        r"\begin{table}[t]",
        r"\centering",
        r"\caption{\textbf{Published CVE records for commercial automotive OS and"
        r" hypervisor platforms} (NVD, queried " + date + r", CPE match, rejected"
        r" records excluded, \texttt{nvd\_platforms.py}). The counts are not a"
        r" trust gap $\Gamma_o$ and not a ranking. They depend on how much a"
        r" product is studied, how widely it is deployed, how its vendor"
        r" discloses, and which bundled components share its product name."
        r" ``No NVD entry'' means that the NVD has no product name (CPE) for it,"
        r" not that it has no flaw. Records that the NVD has not yet analyzed"
        r" carry no CPE and are missed, so recent years are undercounted."
        r" PikeOS native and hypervisor share one row.}",
        r"\label{tab:platforms}",
        r"\footnotesize",
        r"\setlength\tabcolsep{3pt}",
        r"\begin{tabular}{@{}>{\raggedright\arraybackslash}p{0.19\columnwidth}"
        r" >{\raggedright\arraybackslash}p{0.33\columnwidth} c"
        r" >{\raggedright\arraybackslash}p{0.27\columnwidth}@{}}",
        r"\toprule",
        r"\textbf{Supplier} & \textbf{Product} & \textbf{Type} & \textbf{CVE records (years)} \\",
        r"\midrule",
    ]
    for r in rows:
        if r["supplier"] == "Linux":
            lines.append(r"\midrule")
            lines.append(r"\multicolumn{2}{@{}l}{Linux kernel (reference)} & OS & " + cell(r) + r" \\")
            continue
        lines.append(f"{r['supplier']} & {r['product']} & {r['type']} & {cell(r)} \\\\")
    lines += [r"\bottomrule", r"\end{tabular}", r"\end{table}", ""]
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--offline", metavar="DATE", help="rebuild from nvd_raw/DATE/rows.json")
    a = ap.parse_args()
    if a.offline:
        date = a.offline
        rows = json.load(open(os.path.join(HERE, "nvd_raw", date, "rows.json"), encoding="utf-8"))
        for r in rows:
            if r.get("ids"):
                r["years"] = years(r["ids"])
    else:
        date = datetime.date.today().isoformat()
        raw_dir = os.path.join(HERE, "nvd_raw", date)
        os.makedirs(raw_dir, exist_ok=True)
        rows = query(raw_dir)
        with open(os.path.join(raw_dir, "rows.json"), "w", encoding="utf-8") as fh:
            json.dump(rows, fh, indent=1)
    write_tex(rows, date, os.path.join(HERE, "..", "tables", "platforms.tex"))
    for r in rows:
        print(r["product"], r["count"], r.get("years", ""), r.get("keyword_hits", ""))


if __name__ == "__main__":
    main()
