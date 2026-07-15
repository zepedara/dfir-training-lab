$ErrorActionPreference = 'Stop'
# build-usnjrnl.ps1 -- generate an INERT $UsnJrnl:$J that mirrors module-15's
# intrusion narrative (host DESKTOP-SDN1RPT / user mortysmith / coreupdater.exe).
# NO malware: files hold only an "MZ" header + a plain benign marker string. The
# journal is pure filesystem-change metadata (names, times, reason codes).
$build = 'C:\dfir\build'
New-Item -ItemType Directory -Force $build | Out-Null
$vhd = Join-Path $build 'usn.vhd'
if (Test-Path $vhd) { Remove-Item $vhd -Force }

Write-Host '=== 1) create + attach + format VHD as X: ==='
@"
create vdisk file="$vhd" maximum=64 type=fixed
select vdisk file="$vhd"
attach vdisk
convert mbr
create partition primary
format fs=ntfs quick label="OSDISK"
assign letter=X
"@ | Out-File -Encoding ascii "$build\mk.txt"
diskpart /s "$build\mk.txt" | Out-String | Write-Host

Write-Host '=== 2) enable/size the USN change journal ==='
& fsutil usn createjournal X: m=524288 a=65536 | Out-Null
& fsutil usn queryjournal X: | Out-String | Write-Host

Write-Host '=== 3) drive the narrative (real ops -> real USN records) ==='
New-Item -ItemType Directory -Force 'X:\Windows\Temp' | Out-Null
New-Item -ItemType Directory -Force 'X:\Users\mortysmith\AppData\Local\Temp' | Out-Null
New-Item -ItemType Directory -Force 'X:\Users\mortysmith\Downloads' | Out-Null
$mz = [byte[]](0x4D,0x5A,0x90,0x00)  # "MZ" header only -- inert
# attacker stages 'cu.tmp' then RENAMES it into place -> RENAME_OLD_NAME + RENAME_NEW_NAME
[IO.File]::WriteAllBytes('X:\Windows\Temp\cu.tmp', $mz)
Rename-Item 'X:\Windows\Temp\cu.tmp' 'coreupdater.exe'
Add-Content 'X:\Windows\Temp\coreupdater.exe' 'coreupdater.exe :: benign lab marker (no code)'  # DATA_EXTEND
# two more artifacts CREATED then later DELETED
Set-Content 'X:\Users\mortysmith\AppData\Local\Temp\update.ps1' 'benign lab marker -- not real script'
Set-Content 'X:\Users\mortysmith\Downloads\loot.zip'            'benign lab marker -- not a real archive'
Start-Sleep -Milliseconds 300
# TIMESTOMP coreupdater.exe -> BASIC_INFO_CHANGE record(s)
$f = Get-Item 'X:\Windows\Temp\coreupdater.exe'
$f.CreationTime   = [datetime]'2019-03-15 12:00:00'
$f.LastWriteTime  = [datetime]'2019-03-15 12:00:00'
$f.LastAccessTime = [datetime]'2019-03-15 12:00:00'
Start-Sleep -Milliseconds 300
# DELETE the two staged artifacts -> FILE_DELETE records
Remove-Item 'X:\Users\mortysmith\AppData\Local\Temp\update.ps1'
Remove-Item 'X:\Users\mortysmith\Downloads\loot.zip'
Start-Sleep -Milliseconds 300

Write-Host '=== journal record count (sanity) ==='
$n = (& fsutil usn readjournal X: csv 2>$null | Measure-Object -Line).Lines
Write-Host "usn readjournal lines: $n"

Write-Host '=== 4) detach VHD ==='
@"
select vdisk file="$vhd"
detach vdisk
"@ | Out-File -Encoding ascii "$build\dt.txt"
diskpart /s "$build\dt.txt" | Out-String | Write-Host
Write-Host "DONE vhd=$vhd size=$((Get-Item $vhd).Length)"

# --- carve the $J stream out of the detached VHD with TSK (run in Git-Bash) -----
#   OFF=128                                   # partition offset from: mmls usn.vhd
#   fls -o $OFF usn.vhd 11                    # $Extend -> shows "$UsnJrnl:$J" at 38-128-3
#   icat -o $OFF usn.vhd 38-128-3 > UsnJrnl_J # carve the raw $J (same icat-by-attribute idea as the $MFT)
#   MFTECmd -f UsnJrnl_J --csv . --csvf usnjrnl.csv   # verify: 43 USN records incl. the rename/timestomp/delete
# UsnJrnl_J (the carved stream) is what ships in data/ and what Step 8 parses.
