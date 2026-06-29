#!/usr/bin/env sh
# get-data.sh — fetch additional practice samples for this module (online only).
#
# Provenance: EVTX-ATTACK-SAMPLES by @sbousseaden (https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES)
# A curated library of real ATT&CK-technique event logs. Bundled lab data is a small,
# representative slice; this script pulls the full ATT&CK category for extra practice.
#
# Offline-friendly: if there's no network (the lab runs --network none on purpose),
# the script prints guidance and exits 0 without failing your workflow.
#
# Usage:   sh get-data.sh
set -eu

# ---- per-module config (edit ATTACK_DIR for each module) --------------------
ATTACK_DIR="Credential Access"          # ATT&CK category folder inside the repo
REPO="https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES.git"
# -----------------------------------------------------------------------------

HERE="$(cd "$(dirname "$0")" && pwd)"
DST="$HERE/data"
mkdir -p "$DST"

if ! command -v git >/dev/null 2>&1; then
  echo "[i] git not found. Run this on a host with git + network access, then copy the"
  echo "    *.evtx into $DST"
  exit 0
fi

# Probe connectivity quickly; the analysis container runs offline by design.
if ! git ls-remote "$REPO" >/dev/null 2>&1; then
  echo "[i] No network to GitHub (expected inside the offline container)."
  echo "    Run get-data.sh on the HOST (online), or manually fetch from:"
  echo "      $REPO"
  echo "      folder: '$ATTACK_DIR'  ->  copy the *.evtx into $DST"
  exit 0
fi

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
echo "[+] Shallow-cloning EVTX-ATTACK-SAMPLES (sparse: $ATTACK_DIR) ..."
git clone --depth 1 --filter=blob:none --sparse "$REPO" "$TMP/repo" >/dev/null 2>&1
( cd "$TMP/repo" && git sparse-checkout set "$ATTACK_DIR" >/dev/null 2>&1 )

n=0
# shellcheck disable=SC2044
for f in $(find "$TMP/repo/$ATTACK_DIR" -name '*.evtx' 2>/dev/null); do
  cp -f "$f" "$DST/" && n=$((n+1))
done
echo "[+] Copied $n sample(s) into $DST"
echo "    Provenance: EVTX-ATTACK-SAMPLES / '$ATTACK_DIR' (GPLv3, @sbousseaden)"
