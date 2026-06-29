#!/usr/bin/env sh
# get-data.sh — pointers for practising this module on a REAL forensic disk image.
#
# The bundled `disk-DESKTOP-SDN1RPT.raw` is a small synthetic teaching image (see
# data/README.md). To exercise mmls/fls/icat/istat/MFTECmd against a full, real
# Windows intrusion image, fetch the public DFIR Madness Case 001 dataset — the
# same case the lab's narrative is built around.
#
# This script does NOT auto-download multi-GB evidence; it prints exactly where to
# get it and how to drive the same workflow against it. Offline-safe (exit 0).
#
# Usage:   sh get-data.sh
set -eu

cat <<'EOF'
[i] Real-image practice for Module 15
-------------------------------------------------------------------------------
DFIR Madness — "The Stolen Szechuan Sauce" (Case 001)
    Landing page : https://dfirmadness.com/the-stolen-szechuan-sauce/
    Datasets     : https://dfirmadness.com/case-001-the-stolen-szechuan-sauce/
                   (the desktop "DESKTOP-SDN1RPT" and the server disk images, E01)

License/terms : published for education & practice. Use for defensive/training
                forensics only; respect the author's terms; do not redistribute
                non-educationally.

After downloading the desktop image (e.g. an .E01 or raw .dd), run the EXACT same
commands from the module against it (TSK 4.11.1 in dfir-aio:v2 supports .E01):

    mmls  <image>                         # find the NTFS partition's start sector S
    fls  -o S -r -p <image>               # list every file (incl. * deleted)
    istat -o S <image> <mft_entry>        # inspect a file: compare $SI vs $FN
    icat  -o S -r <image> <mft_entry> > recovered.bin
    fls  -o S -r -m C: <image> > fs.body  # bodyfile
    mactime -b fs.body -d -z UTC > timeline.csv

To run MFTECmd on the REAL $MFT, carve it out first (entry 0 is always the $MFT):

    icat -o S <image> 0 > MFT
    MFTECmd -f MFT --csv ./out --csvf mft.csv      # sort on SI<FN / uSecZeros

Heavier alternative (NOT in dfir-aio:v2): Plaso / log2timeline.py + psort.py build a
full SUPER-timeline (filesystem + registry + EVTX + browser) in one pass. It is the
standard merger but is not installed in this container — build per-layer here and
merge in Timeline Explorer, or add Plaso to the image if you need the one-shot tool.
-------------------------------------------------------------------------------
EOF
exit 0
