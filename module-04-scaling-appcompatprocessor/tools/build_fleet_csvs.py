# -*- coding: utf-8 -*-
"""
build_fleet_csvs.py  --  Generates the Module 04 "Middle-earth" AppCompat (ShimCache) fleet.

WHY THIS EXISTS
---------------
AppCompatProcessor's superpower is *frequency stacking* across many hosts: software that
is common across an enterprise stacks high (benign baseline), while an intruder's tools --
run on only one or two boxes -- fall to the bottom as rare Count=1/2 outliers. To teach
that, we need a realistic multi-host fleet. This script emits one ShimCacheParser-style CSV
per host (filename == hostname, the format ACP's appcompat_csv ingest plugin expects):

    First line:  Last Modified,Last Update,Path,File Size,Exec Flag
    Data rows :  YYYY-MM-DD HH:MM:SS,N/A,C:\\path\\file.exe,<size>,True

THEME (clearly a teaching construct -- NOT real evidence)
---------------------------------------------------------
The fictional org is "Middle-earth".  Threat actor = SAURON (APT-MORDOR).  The intruder's
tooling is named after the One Ring saga so the rare hits are easy to spot in a stack:

    theonering.exe   initial dropper (phished into BAG-END; "it always comes back" = persistence)
    gollum.exe       temp-resident stager ("my precious", hides in %TEMP%)
    palantir.exe     the seeing-stone = recon/C2 beacon (spreads ISENGARD -> CITADEL = Count 2)
    nazgul.exe       lateral-movement agent (the nine ride out)
    morgul.dll       credential theft on the DC (Morgul-blade poisons -> NTDS/DCSync)
    balrog.exe       heavy payload deep on the DC ("you shall not pass" -- it did)
    mordor-update.exe masquerading "software updater" (lives in ProgramData)

All planted malware carries the incident-window date 2024-09-13..14.  Benign baseline
binaries are dated to OS-install/patch windows so they cluster apart from the intrusion.
"""
import io, os, sys

OUTDIR = sys.argv[1] if len(sys.argv) > 1 else "fleet"
if not os.path.isdir(OUTDIR):
    os.makedirs(OUTDIR)

HEADER = "Last Modified,Last Update,Path,File Size,Exec Flag"

# ---- benign baseline: present on (nearly) every host -> stacks HIGH (the known-good wall) ----
BASE_DATE = "2021-03-15 09:14:22"
COMMON = [
    (r"C:\Windows\System32\kernel32.dll", "1114112"),
    (r"C:\Windows\System32\ntdll.dll", "1990656"),
    (r"C:\Windows\System32\svchost.exe", "55320"),
    (r"C:\Windows\System32\services.exe", "731136"),
    (r"C:\Windows\System32\lsass.exe", "83768"),
    (r"C:\Windows\System32\winlogon.exe", "830136"),
    (r"C:\Windows\System32\csrss.exe", "17944"),
    (r"C:\Windows\System32\smss.exe", "144664"),
    (r"C:\Windows\System32\conhost.exe", "841728"),
    (r"C:\Windows\System32\dllhost.exe", "21816"),
    (r"C:\Windows\System32\RuntimeBroker.exe", "1233920"),
    (r"C:\Windows\System32\taskhostw.exe", "100864"),
    (r"C:\Windows\System32\cmd.exe", "289792"),
    (r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe", "452608"),
    (r"C:\Windows\System32\notepad.exe", "201216"),
    (r"C:\Windows\System32\rundll32.exe", "69632"),
    (r"C:\Windows\System32\regsvr32.exe", "24064"),
    (r"C:\Windows\System32\schtasks.exe", "230400"),
    (r"C:\Windows\System32\wbem\WmiPrvSE.exe", "496640"),
    (r"C:\Windows\System32\mmc.exe", "1413120"),
    (r"C:\Windows\System32\mstsc.exe", "1265664"),
    (r"C:\Windows\System32\net.exe", "55808"),
    (r"C:\Windows\System32\net1.exe", "50176"),
    (r"C:\Windows\System32\ipconfig.exe", "33792"),
    (r"C:\Windows\System32\tasklist.exe", "78848"),
    (r"C:\Windows\System32\whoami.exe", "63488"),
    (r"C:\Windows\explorer.exe", "4296072"),
    (r"C:\Windows\System32\SearchIndexer.exe", "893952"),
    (r"C:\Program Files\Windows Defender\MsMpEng.exe", "129024"),
    (r"C:\Program Files\Microsoft Office\root\Office16\OUTLOOK.EXE", "34603008"),
    (r"C:\Program Files\Microsoft Office\root\Office16\EXCEL.EXE", "57344000"),
    (r"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE", "1959936"),
    (r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe", "3258560"),
    (r"C:\Program Files\Google\Chrome\Application\chrome.exe", "2723024"),
    (r"C:\Windows\System32\MicrosoftEdgeUpdate.exe", "175208"),
    (r"C:\Program Files\7-Zip\7zFM.exe", "1050624"),
    (r"C:\Windows\System32\SnippingTool.exe", "1372672"),
    (r"C:\Windows\System32\mspaint.exe", "6536704"),
    (r"C:\Windows\System32\calc.exe", "27648"),
    (r"C:\Windows\System32\dwm.exe", "111616"),
]

# ---- role-specific benign: legitimately rare (Count 1) -> teaches "rare != automatically evil" ----
ROLE = {
    "dc": [
        (r"C:\Windows\System32\lsass.exe", "83768"),
        (r"C:\Windows\System32\ntdsutil.exe", "418304"),
        (r"C:\Windows\System32\dfsrs.exe", "1453568"),
        (r"C:\Windows\System32\dns.exe", "1839616"),
        (r"C:\Windows\System32\ismserv.exe", "57344"),
        (r"C:\Windows\System32\netdom.exe", "118784"),
        (r"C:\Windows\System32\dsac.exe", "1359872"),
        (r"C:\Windows\System32\repadmin.exe", "248320"),
    ],
    "sql": [
        (r"C:\Program Files\Microsoft SQL Server\MSSQL15.MSSQLSERVER\MSSQL\Binn\sqlservr.exe", "525112"),
        (r"C:\Program Files\Microsoft SQL Server\150\Tools\Binn\SQLCMD.EXE", "300208"),
        (r"C:\Program Files (x86)\Microsoft SQL Server Management Studio 18\Common7\IDE\Ssms.exe", "832120"),
    ],
    "file": [
        (r"C:\Windows\System32\srmhost.exe", "129536"),
        (r"C:\Windows\System32\dfsrs.exe", "1453568"),
    ],
    "ws": [
        (r"C:\Program Files\Adobe\Acrobat DC\Acrobat\Acrobat.exe", "2842624"),
        (r"C:\Program Files\Microsoft Teams\current\Teams.exe", "127512576"),
    ],
    "laptop": [
        (r"C:\Program Files\Microsoft Teams\current\Teams.exe", "127512576"),
        (r"C:\Program Files\PuTTY\putty.exe", "1134592"),
    ],
}

# ---- the intrusion: SAURON's toolkit (planted; rare by design) ----
EVIL_DATE = "2024-09-13 22:47:11"
EVIL_DATE2 = "2024-09-14 02:09:48"
# host -> list of (date, path, size)
EVIL = {
    "BAG-END-LT01": [
        (EVIL_DATE, r"C:\Users\frodo.baggins\Downloads\theonering.exe", "284160"),
        (EVIL_DATE, r"C:\Users\frodo.baggins\AppData\Local\Temp\gollum.exe", "96256"),
    ],
    "ISENGARD-WS04": [
        (EVIL_DATE, r"C:\ProgramData\palantir.exe", "412672"),
        (EVIL_DATE2, r"C:\Windows\Temp\nazgul.exe", "151552"),
        (EVIL_DATE, r"C:\Users\saruman.white\AppData\Roaming\mordor-update.exe", "208896"),
    ],
    "MINAS-TIRITH-DC01": [
        (EVIL_DATE2, r"C:\Windows\Temp\palantir.exe", "412672"),
        (EVIL_DATE2, r"C:\Windows\NTDS\morgul.dll", "76288"),
        (EVIL_DATE2, r"C:\PerfLogs\balrog.exe", "1340416"),
        (EVIL_DATE2, r"C:\Windows\Temp\nazgul.exe", "151552"),
    ],
}

# fleet: name -> role
# Naming scheme:  <LOTR-LOCATION>-<ROLE><nn>   (ROLE: WS workstation, DC domain controller,
# FS file server, SQL database server, LT laptop)
FLEET = [
    ("RIVENDELL-WS01", "ws"),       # Elrond's house -- a standard analyst workstation
    ("GONDOR-WS02", "ws"),          # realm of men -- standard workstation
    ("ROHAN-WS03", "ws"),           # the horse-lords -- standard workstation
    ("ISENGARD-WS04", "ws"),        # Saruman's tower -- the INSIDER (saruman.white) who turned; lateral-movement launch point
    ("LOTHLORIEN-FS01", "file"),    # Galadriel's wood -- the file server
    ("EREBOR-SQL01", "sql"),        # the Lonely Mountain's hoard -- the database server
    ("BAG-END-LT01", "laptop"),     # Frodo's home -- the exec laptop; PATIENT ZERO (phishing landed here)
    ("MINAS-TIRITH-DC01", "dc"),    # the White City / its Citadel -- the domain controller, the crown jewel
]


def rows_for(name, role):
    rows = []
    for (path, size) in COMMON:
        rows.append((BASE_DATE, "N/A", path, size, "True"))
    for (path, size) in ROLE.get(role, []):
        rows.append((BASE_DATE, "N/A", path, size, "True"))
    for (d, path, size) in EVIL.get(name, []):
        rows.append((d, "N/A", path, size, "True"))
    return rows


def main():
    total = 0
    for (name, role) in FLEET:
        rows = rows_for(name, role)
        total += len(rows)
        path = os.path.join(OUTDIR, name + ".csv")
        f = io.open(path, "wb")  # binary write -> identical bytes under Python 2 and 3
        f.write((HEADER + "\r\n").encode("ascii"))
        for r in rows:
            f.write((",".join(r) + "\r\n").encode("ascii"))
        f.close()
        evil = len(EVIL.get(name, []))
        print("%-22s rows=%-3d  planted-evil=%d" % (name, len(rows), evil))
    print("Fleet: %d hosts, %d total entries -> %s" % (len(FLEET), total, OUTDIR))


if __name__ == "__main__":
    main()
