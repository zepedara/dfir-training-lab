$ErrorActionPreference = 'Continue'
# gen_m24.ps1 - capture INERT T1490 (Inhibit System Recovery) detection evidence:
# temporarily enable cmd-line 4688 auditing, run BENIGN shadow/backup-deletion
# commands (no shadows/catalog exist -> no-ops), export the 4688 evtx, then REVERT.
$base='E:\DFIR\afgen'; $out=Join-Path $base 'out24'; $log=Join-Path $base 'gen24.log'
New-Item -ItemType Directory -Force $out | Out-Null
function L($m){ Add-Content $log ("[{0}] {1}" -f (Get-Date -Format HH:mm:ss),$m); Write-Host $m }
Set-Content $log "=== module-24 T1490 evidence capture ==="

$regPath='HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit'
$prev = (Get-ItemProperty -Path $regPath -Name ProcessCreationIncludeCmdLine_Enabled -ErrorAction SilentlyContinue).ProcessCreationIncludeCmdLine_Enabled
L "prev ProcessCreationIncludeCmdLine=$prev"

L '1) ENABLE cmd-line in 4688 + Process Creation auditing (temporary)'
New-Item -Path $regPath -Force | Out-Null
Set-ItemProperty -Path $regPath -Name ProcessCreationIncludeCmdLine_Enabled -Value 1 -Type DWord
auditpol /set /subcategory:"Process Creation" /success:enable | Out-Null
Start-Sleep -Seconds 2

L '2) run BENIGN T1490 commands (no shadows/catalog -> no-op, but the command line is logged)'
$t0 = (Get-Date).AddSeconds(-2)
cmd /c "vssadmin delete shadows /all /quiet" 2>&1 | Out-Null
cmd /c "wmic shadowcopy delete /nointeractive" 2>&1 | Out-Null
cmd /c "vssadmin resize shadowstorage /for=C: /on=C: /maxsize=401MB" 2>&1 | Out-Null
cmd /c "wbadmin delete catalog -quiet" 2>&1 | Out-Null
powershell -NoProfile -Command "Get-WmiObject Win32_Shadowcopy | ForEach-Object { $_ } " 2>&1 | Out-Null
Start-Sleep -Seconds 3
L 'commands run'

L '3) REVERT auditing to previous state'
auditpol /set /subcategory:"Process Creation" /success:disable | Out-Null
if ($null -eq $prev) { Remove-ItemProperty -Path $regPath -Name ProcessCreationIncludeCmdLine_Enabled -ErrorAction SilentlyContinue } else { Set-ItemProperty -Path $regPath -Name ProcessCreationIncludeCmdLine_Enabled -Value $prev -Type DWord }
L 'audit reverted'

L '4) export the 4688 evtx (tight window) + the WMI-Activity VSS provider evtx'
# Security 4688 in the capture window
$q4688 = "*[System[(EventID=4688)]]"
wevtutil epl Security (Join-Path $out 'raw_security.evtx') /q:$q4688 /ow:true 2>&1 | Out-Null
# also the WMI-Activity 5857 (MSVSS__PROVIDER path)
wevtutil epl "Microsoft-Windows-WMI-Activity/Operational" (Join-Path $out 'wmi_activity.evtx') /q:"*[System[(EventID=5857)]]" /ow:true 2>&1 | Out-Null
L ("out24: " + ((Get-ChildItem $out).Name -join ', '))

L '5) sanity: does raw_security.evtx contain our T1490 command lines?'
try {
  $hits = Get-WinEvent -Path (Join-Path $out 'raw_security.evtx') -ErrorAction SilentlyContinue | Where-Object { $_.Message -match 'vssadmin|shadowcopy|wbadmin|shadowstorage' } | Select-Object -First 8
  foreach ($h in $hits) { L ("  HIT: " + (($h.Message -split "`n" | Where-Object { $_ -match 'New Process Name|Process Command Line|vssadmin|wbadmin|shadowcopy' } | Select-Object -First 2) -join ' | ')) }
  L ("T1490 4688 hits=" + ($hits | Measure-Object).Count)
} catch { L "sanity read failed: $_" }
L 'DONE'
