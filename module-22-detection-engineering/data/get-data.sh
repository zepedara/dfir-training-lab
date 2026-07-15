#!/usr/bin/env bash
# Populate evtx/ with inert detection targets already in the lab (Modules 08 + 06).
cd "$(dirname "$0")"; mkdir -p evtx
cp ../../module-08-lateral-movement/data/LM_Remote_Service02_7045.evtx evtx/ 2>/dev/null
cp ../../module-06-sigma-chainsaw-hayabusa/data/Powershell-Invoke-Obfuscation-encoding-menu.evtx evtx/ 2>/dev/null
echo "evtx targets: $(ls evtx/*.evtx 2>/dev/null | wc -l)"
