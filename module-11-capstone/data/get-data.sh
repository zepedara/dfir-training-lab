#!/usr/bin/env bash
# get-data.sh -- fetch the MITRE ATT&CK Evals APT29 day-1 telemetry (OTRF).
# One-time, online host only; the analysis itself is offline. The dataset is a
# reputable, inert, pre-recorded Windows-event JSON (Sysmon/Security/PowerShell/WMI)
# from the OTRF detection-hackathon-apt29 project -- no malware, no payloads.
set -e
cd "$(dirname "$0")"
URL="https://github.com/OTRF/detection-hackathon-apt29/raw/master/datasets/day1/apt29_evals_day1_manual.zip"
echo "[*] Downloading APT29 day-1 telemetry (~120 MB compressed)..."
curl -L --fail -o apt29_day1.zip "$URL"
echo "[*] Unzipping (~368 MB JSON)..."
unzip -o apt29_day1.zip
# normalize the timestamped filename to a stable name the lab commands use
mv -f apt29_evals_day1_manual_*.json apt29_day1.json
rm -f apt29_day1.zip
echo "[*] Ready: $(wc -l < apt29_day1.json) events in apt29_day1.json"
