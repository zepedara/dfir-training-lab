#!/usr/bin/env sh
# get-data.sh — fetch the Windows 7 memory image for this module (online host only).
#
# The image is too large to commit to the repo (~1.5 GB raw / ~342 MB compressed),
# so it is distributed by reference and downloaded here.
#
# Provenance: "NotchItUp" memory image, InCTF Internationals 2019 (team bi0s).
#   Published openly for training. Contains NO malware (benign Win7 desktop capture).
#   Write-up: https://blog.bi0s.in/2019/09/24/Forensics/InCTFi19-NotchItUp/
#   Catalogue: https://github.com/pinesol93/MemoryForensicSamples
#   See data/README.md for full origin + license notes.
#
# Offline-friendly: if there's no network (the analysis container runs --network none
# on purpose), the script prints guidance and exits 0 without failing your workflow.
#
# Usage:   sh get-data.sh
set -eu

# ---- config -----------------------------------------------------------------
GDRIVE_ID="1bER4wmHP_LAMgdB52LGkb8x2Mf8hG3V6"          # public Google Drive file id
ARCHIVE="NotchItUp.7z"                                  # downloaded archive name
IMAGE="Challenge.raw"                                   # extracted memory image
SHA256="c8f56eaadf47970c411e338a7f6f9e7dd40edfcef4eeb68a6474b527f4f35138"   # of $ARCHIVE
URL="https://drive.usercontent.google.com/download?id=${GDRIVE_ID}&export=download&confirm=t"
# -----------------------------------------------------------------------------

HERE="$(cd "$(dirname "$0")" && pwd)"
cd "$HERE"

if [ -f "$IMAGE" ]; then
  echo "[i] $IMAGE already present in $HERE — nothing to do."
  exit 0
fi

if ! command -v curl >/dev/null 2>&1 && ! command -v wget >/dev/null 2>&1; then
  echo "[i] Neither curl nor wget found. Fetch the image manually on an online host:"
  echo "      $URL"
  echo "    Save it as $ARCHIVE here, then extract $IMAGE (7z x $ARCHIVE)."
  exit 0
fi

# Probe connectivity; the analysis container runs offline by design.
if command -v curl >/dev/null 2>&1; then
  if ! curl -s -I -m 20 "https://drive.usercontent.google.com" >/dev/null 2>&1; then
    echo "[i] No network to Google Drive (expected inside the offline container)."
    echo "    Run get-data.sh on an ONLINE host, or manually fetch:"
    echo "      $URL  ->  save as $ARCHIVE here  ->  7z x $ARCHIVE"
    exit 0
  fi
fi

echo "[+] Downloading $ARCHIVE (~342 MB) from the authors' public Google Drive ..."
if command -v curl >/dev/null 2>&1; then
  curl -L --fail -o "$ARCHIVE" "$URL"
else
  wget -O "$ARCHIVE" "$URL"
fi

# Verify integrity if a checksum tool is available.
if command -v sha256sum >/dev/null 2>&1; then
  echo "[+] Verifying SHA-256 ..."
  echo "${SHA256}  ${ARCHIVE}" | sha256sum -c - || {
    echo "[!] Checksum FAILED — the download may be corrupt or the upstream file changed."
    echo "    Delete $ARCHIVE and retry, or verify provenance before using."
    exit 1
  }
else
  echo "[i] sha256sum not found; skipping integrity check (expected $SHA256)."
fi

# Extract Challenge.raw from the 7z.
if command -v 7z >/dev/null 2>&1; then EXTRACT="7z x -y";
elif command -v 7za >/dev/null 2>&1; then EXTRACT="7za x -y";
elif command -v 7zr >/dev/null 2>&1; then EXTRACT="7zr x -y";
else
  echo "[i] No 7-Zip extractor (7z/7za/7zr) on this host."
  echo "    $ARCHIVE is downloaded; extract $IMAGE with any 7-Zip tool, e.g.:"
  echo "      docker run --rm -v \"\$PWD\":/data dfir-aio:v2 7z x -y /data/$ARCHIVE -o/data"
  exit 0
fi

echo "[+] Extracting $IMAGE ..."
$EXTRACT "$ARCHIVE" >/dev/null
if [ -f "$IMAGE" ]; then
  echo "[+] Ready: $HERE/$IMAGE"
  echo "    You can delete $ARCHIVE to reclaim space:  rm $ARCHIVE"
else
  echo "[!] Extraction finished but $IMAGE not found — check the archive contents."
  exit 1
fi
