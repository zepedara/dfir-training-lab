#!/usr/bin/env python3
"""merge_timeline.py -- combine the per-artifact CSVs that MFTECmd and EvtxECmd
emit into ONE chronological "super timeline". This is the core super-timeline idea:
every artifact carries timestamps; normalize them to a single time-sorted view so
you can pivot across filesystem + event-log activity at once.

Usage:  python3 merge_timeline.py <csv_dir>   (writes super_timeline.csv there)
Extend it by adding more (glob, source, time-column, description-columns) tuples.
"""
import sys, os, csv, glob

# (filename glob, source label, timestamp column, description columns to try in order)
SOURCES = [
    ("*mft.csv",  "MFT",  "LastModified0x10", ["FileName", "ParentPath"]),
    ("*evtx.csv", "EVTX", "TimeCreated",      ["MapDescription", "PayloadData1", "Channel"]),
]

def main(outdir):
    rows = []
    for pattern, src, tcol, desc_cols in SOURCES:
        for fp in glob.glob(os.path.join(outdir, pattern)):
            with open(fp, encoding="utf-8", errors="ignore") as fh:
                for r in csv.DictReader(fh):
                    t = (r.get(tcol) or "").strip()
                    if not t:
                        continue
                    desc = next((r.get(c) for c in desc_cols if r.get(c)), "") or ""
                    rows.append((t, src, desc[:80]))
    rows.sort(key=lambda x: x[0])
    out = os.path.join(outdir, "super_timeline.csv")
    with open(out, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["Time", "Source", "Description"])
        w.writerows(rows)
    print("merged super-timeline: %d events -> %s" % (len(rows), out))
    print("  span: %s  ..  %s" % (rows[0][0][:19], rows[-1][0][:19]) if rows else "  (empty)")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(__doc__); sys.exit(2)
    main(sys.argv[1])
