#!/usr/bin/env python3
# Wrap the hand-built VBA project (an OLE2 file == a vbaProject.bin) inside a
# minimal OOXML (.docm) ZIP, so the lab can show the modern Office path:
#   .docm is really a ZIP -> zipdump lists members -> pipe word/vbaProject.bin
#   into oledump to read the macros, without ever unzipping to disk.
import zipfile, sys, time

vba_bin = open(sys.argv[1], "rb").read()      # the OLE2 we built (Invoice_2024_0042.doc)
out = sys.argv[2] if len(sys.argv) > 2 else "/tmp/otest/Statement_Q4.docm"

content_types = (
 '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
 '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
 '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
 '<Default Extension="xml" ContentType="application/xml"/>'
 '<Default Extension="bin" ContentType="application/vnd.ms-office.vbaProject"/>'
 '<Override PartName="/word/document.xml" ContentType="application/vnd.ms-word.document.macroEnabled.main+xml"/>'
 '</Types>')
root_rels = (
 '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
 '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
 '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/>'
 '</Relationships>')
document = (
 '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
 '<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">'
 '<w:body><w:p><w:r><w:t>Acme Q4 Statement - enable content to view.</w:t></w:r></w:p></w:body>'
 '</w:document>')
doc_rels = (
 '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
 '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
 '<Relationship Id="rId1" Type="http://schemas.microsoft.com/office/2006/relationships/vbaProject" Target="vbaProject.bin"/>'
 '</Relationships>')

zi_date = (2024, 11, 4, 9, 0, 0)
with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as z:
    for name, data in [
        ("[Content_Types].xml", content_types),
        ("_rels/.rels", root_rels),
        ("word/document.xml", document),
        ("word/_rels/document.xml.rels", doc_rels),
    ]:
        info = zipfile.ZipInfo(name, zi_date); z.writestr(info, data)
    info = zipfile.ZipInfo("word/vbaProject.bin", zi_date)
    z.writestr(info, vba_bin)
print("WROTE", out)
