#!/usr/bin/env sh
# get-data.sh — obtain the large SOFTWARE hive (and, optionally, the full hive set)
# for this module from the public DFIR-Madness Case 001 dataset.
#
# The small hives (SYSTEM, SAM, NTUSER.DAT, UsrClass.dat, Administrator_NTUSER.DAT)
# ship with the repo. The CITADEL-DC01 **SOFTWARE** hive (~44 MB) is NOT shipped —
# it is needed for Steps 7-9 (Run-key persistence, installed apps, NetworkList).
# Every SOFTWARE command's real output is already captured in ../reference-output/,
# so you can read the module fully without fetching anything.
#
# This script does NOT auto-download multi-GB evidence; it prints exactly where to
# get it and the exact commands to carve the hive out. Offline-safe (exit 0).
#
# Usage:   sh get-data.sh
set -eu

HERE="$(cd "$(dirname "$0")" && pwd)"

cat <<EOF
[i] Fetch the SOFTWARE hive for Module 16
-------------------------------------------------------------------------------
Source: DFIR-Madness — "The Stolen Szechuan Sauce" (Case 001)
    Landing page : https://dfirmadness.com/the-stolen-szechuan-sauce/
    Datasets     : https://dfirmadness.com/case-001-the-stolen-szechuan-sauce/
                   (the "CITADEL-DC01" server and "DESKTOP-SDN1RPT" desktop images)

License/terms : published for education & practice. Use for defensive/training
                forensics only; respect the author's terms; do not redistribute
                non-educationally.

The SOFTWARE hive used in this module is C:\\Windows\\System32\\config\\SOFTWARE
from the server **CITADEL-DC01**. To obtain it, download the case's server disk
image and carve the hive with The Sleuth Kit (TSK 4.11.1 is in the lab; the same
icat workflow as Module 15):

    # 1) find the Windows partition's start sector S
    mmls  <CITADEL-DC01 image>

    # 2) locate the config\\SOFTWARE inode I (walk Windows\\System32\\config with fls)
    fls  -o S <image> <inode-of-config-dir> | grep -iw SOFTWARE

    # 3) carve it into this data/ folder
    icat -o S <image> I > "$HERE/SOFTWARE"

Then re-run the SOFTWARE steps from the module, e.g.:

    rip -r SOFTWARE -p run           # fileless 'coreupdate' Run-key persistence
    rip -r SOFTWARE -p uninstall     # installed programs
    rip -r SOFTWARE -p networklist   # C137.local domain / gateway MAC
    rip -r SOFTWARE -p lastloggedon  # last user at the console
    rip -r SOFTWARE -p profilelist   # SID -> profile path mapping

Prefer not to download multi-GB images? Read the committed captures instead:
    ../reference-output/09-software-run.txt
    ../reference-output/10-software-uninstall.txt
    ../reference-output/11-software-networklist.txt
    ../reference-output/12-software-lastloggedon.txt
    ../reference-output/13-software-profilelist.txt
-------------------------------------------------------------------------------
EOF
exit 0
