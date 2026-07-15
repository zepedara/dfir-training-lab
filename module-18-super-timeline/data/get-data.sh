#!/usr/bin/env bash
# Populate this module's evidence/ by reusing the inert artifacts already in the lab:
# the $MFT from Module 15 and the event logs from Module 05. No new evidence needed.
cd "$(dirname "$0")"
mkdir -p evidence
cp ../../module-15-filesystem-timeline/data/MFT evidence/MFT 2>/dev/null
cp ../../module-05-evtx-evtxecmd/data/*.evtx evidence/ 2>/dev/null
echo "evidence: MFT=$([ -f evidence/MFT ] && echo yes) evtx=$(ls evidence/*.evtx 2>/dev/null | wc -l)"
