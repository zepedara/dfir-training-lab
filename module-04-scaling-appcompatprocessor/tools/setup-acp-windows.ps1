<#
  setup-acp-windows.ps1 -- makes AppCompatProcessor run natively on Windows.

  ACP is Python2/Linux-origin; upstream disabled Windows support because its fork-based loader
  and multiprocessing logging deadlock under Windows 'spawn'. This script applies two minimal,
  Linux-behavior-preserving patches and installs ACP's pure-Python hive dependency, so the whole
  Module 04 showcase runs in the VM with no container.

  In the prebuilt lab VM this has already been run. Re-running is safe (both patches are idempotent).

  Usage:
    .\setup-acp-windows.ps1                       # uses defaults below
    .\setup-acp-windows.ps1 -Python "C:\Python27\python.exe" -AcpDir "C:\DFIR\tools\appcompatprocessor"
#>
param(
  [string]$Python = "C:\Python27\python.exe",
  [string]$AcpDir = "C:\DFIR\tools\appcompatprocessor"
)
$ErrorActionPreference = "Stop"
$here = Split-Path -Parent $MyInvocation.MyCommand.Path

Write-Host "[*] AppCompatProcessor Windows setup"
Write-Host "    python: $Python"
Write-Host "    acp   : $AcpDir"

if (-not (Test-Path $Python)) { throw "Python 2 not found at $Python (install Python 2.7 per-user, or pass -Python)." }
if (-not (Test-Path $AcpDir)) { throw "ACP not found at $AcpDir (clone https://github.com/mbevilacqua/appcompatprocessor, or pass -AcpDir)." }

Write-Host "[*] Installing pure-Python hive parser (python-registry)..."
& $Python -m pip install python-registry 2>&1 | Select-String -Pattern "Successfully|already satisfied" | ForEach-Object { "    $_" }

Write-Host "[*] Applying serial loader patch (appLoad.py + AppCompatProcessor.py)..."
& $Python (Join-Path $here "acp_serial_patch.py")

Write-Host "[*] Applying in-process search patch (appSearch.py)..."
& $Python (Join-Path $here "appsearch_patch.py")

Write-Host "[+] Done. Verify with:  $Python $AcpDir\AppCompatProcessor.py test.db load .\data\fleet"
