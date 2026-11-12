"""merge_srec.py -- one S-record image of all three cores.

The PEMicro flash algorithm erases the flash module on every GDB `load`, so
loading the three ELFs one after another leaves only the last one.  This merges
the data records of build/chainrecon_c{0,1,2}.srec into build/chainrecon_all.srec
(one S0 header, all S1/S2/S3 data records, one S7 start record = core 0 entry),
which is then programmed with a single `load`.
  python python/merge_srec.py          (after `make all` and the objcopy step)
"""
import os
import sys

root = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "build")
out_lines, s7 = [], None
for c in (0, 1, 2):
    p = os.path.join(root, f"chainrecon_c{c}.srec")
    with open(p) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            t = line[:2]
            if t == "S0":
                if c == 0:
                    out_lines.append(line)
            elif t == "S3":
                if int(line[4:12], 16) >= 0x40000000:
                    continue                      # RAM (.data of cores 1/2): not flash
                out_lines.append(line)
            elif t == "S7" and c == 0:
                s7 = line
            # S5/S7/S8/S9 of cores 1 and 2 are dropped
if s7 is None:
    sys.exit("core 0 S7 start record missing")
out_lines.append(s7)
dst = os.path.join(root, "chainrecon_all.srec")
with open(dst, "w") as f:
    f.write("\n".join(out_lines) + "\n")
print(f"wrote {dst}: {len(out_lines) - 2} data records")
