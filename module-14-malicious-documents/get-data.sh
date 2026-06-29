#!/usr/bin/env sh
# get-data.sh — (re)generate this module's samples, and point you at extra
# public practice files. Unlike the EVTX modules, this module's data is
# SELF-BUILT and committed, so there is nothing to download to run the lab.
#
# What this does:
#   1) Rebuilds the three benign samples from build/*.py (stdlib only, offline).
#   2) Prints where to get additional, clearly-legal practice maldocs/PDFs.
#
# Usage:   sh get-data.sh
set -eu

HERE="$(cd "$(dirname "$0")" && pwd)"
DST="$HERE/data"
BLD="$DST/build"

if command -v python3 >/dev/null 2>&1; then
  echo "[+] Rebuilding benign samples from $BLD ..."
  ( cd "$DST"
    python3 "$BLD/build_maldoc.py" Invoice_2024_0042.doc
    python3 "$BLD/build_pdf.py"    Invoice_2024_0042.pdf
    python3 "$BLD/build_docm.py"   Invoice_2024_0042.doc Statement_Q4.docm )
  echo "[+] Done. Samples are in $DST"
else
  echo "[i] python3 not found; the committed samples in $DST are ready to use as-is."
fi

cat <<'EOF'

[i] Want more practice files? All clearly legal, published for exactly this:
    - Didier Stevens' blog & SANS ISC diaries publish safe demo PDFs/maldocs
      and walk them through pdfid / pdf-parser / oledump:
        https://blog.didierstevens.com/   https://isc.sans.edu/
    - oletools ships benign test documents in its source tree:
        https://github.com/decalage2/oletools  (tests/test-data/)
    Analyse any sample OFFLINE in the lab container:
        docker run -it --rm --network none -v "$PWD/data":/data dfir-aio:v2
EOF
