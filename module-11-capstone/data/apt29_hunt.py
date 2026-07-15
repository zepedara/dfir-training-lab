#!/usr/bin/env python3
"""apt29_hunt.py -- kill-chain hunting over the MITRE ATT&CK Evals APT29 (OTRF)
day-1 telemetry. The dataset is Mordor-format JSON (one Windows event per line:
Sysmon, Security, PowerShell, WMI-Activity channels). This is a triage helper for
the capstone: each subcommand isolates one ATT&CK stage so you can map evidence ->
technique and grade yourself against APT29-ANSWER-KEY.md.

Usage:  python3 apt29_hunt.py <stage> apt29_day1.json
Stages: summary execution powershell lsass dcsync wmi persistence <or> all
"""
import sys, json, collections

# Cheap substring pre-filter per stage: skip json-parsing lines that can't match,
# so each stage scans the 368 MB telemetry fast (only parses relevant events).
PREFILTER = {
    "execution":   ('"EventID":1,',),
    "powershell":  ('"EventID":4104',),
    "lsass":       ("lsass.exe",),
    "dcsync":      ("1131f6a",),
    "wmi":         ("WMI-Activity", "WmiPrvSE"),
    "persistence": ('"EventID":7045', '"EventID":13,'),
}

def load(path, stage):
    keys = PREFILTER.get(stage)
    with open(path, encoding="utf-8", errors="ignore") as fh:
        for line in fh:
            if keys and not any(k in line for k in keys):
                continue
            line = line.strip()
            if not line:
                continue
            try:
                yield json.loads(line)
            except Exception:
                continue

def base(p):
    return (p or "").split("\\")[-1]

def run(stage, path):
    hits = collections.Counter()
    samples = {}
    def note(k, s):
        hits[k] += 1
        samples.setdefault(k, s[:140])
    for d in load(path, stage):
        eid = d.get("EventID"); msg = d.get("Message") or ""; chan = d.get("Channel", "")
        img = d.get("Image") or ""; pimg = d.get("ParentImage") or ""
        if stage in ("summary", "all"):
            note("channel:" + chan, chan)
        if stage in ("execution", "all") and eid == 1 and any(
                x in img.lower() for x in ("rundll32", "regsvr32", "wscript", "mshta", "powershell")):
            note("exec_lolbin", "%s  <-  %s" % (base(img), base(pimg)))
        if stage in ("powershell", "all") and eid == 4104:
            note("powershell_scriptblock", "4104 ScriptBlock (T1059.001)")
        if stage in ("lsass", "all") and eid == 10 and "lsass.exe" in msg.lower():
            fields = dict(l.split(":", 1) for l in msg.splitlines() if ":" in l)
            mask = (fields.get("GrantedAccess", "") or "").strip()
            src = base((fields.get("SourceImage", "") or "").strip())
            note("lsass_access GrantedAccess=%s" % mask, "%s -> lsass.exe  (T1003.001)" % src)
        if stage in ("dcsync", "all") and eid == 4662 and "1131f6a" in msg.lower():
            note("dcsync_4662", "4662 DS-Replication-Get-Changes from non-DC (T1003.006)")
        if stage in ("wmi", "all") and chan == "Microsoft-Windows-WMI-Activity/Operational":
            note("wmi_activity_eid_%s" % eid, "WMI-Activity (T1047 / T1021.003)")
        if stage in ("wmi", "all") and eid == 1 and "wmiprvse.exe" in pimg.lower():
            note("wmi_spawned_proc", "%s  <-  WmiPrvSE.exe (remote WMI exec)" % base(img))
        if stage in ("persistence", "all") and eid == 7045:
            note("service_install_7045", "7045 service install (T1543.003)")
        if stage in ("persistence", "all") and eid == 13 and "\\run" in msg.lower() and "currentversion" in msg.lower():
            note("registry_run_13", "Run-key value set (T1547.001)")
    if not hits:
        print("  (no events matched stage '%s')" % stage); return
    for k, n in hits.most_common(25):
        print("  %-40s %6d   e.g. %s" % (k, n, samples.get(k, "")))

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print(__doc__); sys.exit(2)
    run(sys.argv[1], sys.argv[2])
