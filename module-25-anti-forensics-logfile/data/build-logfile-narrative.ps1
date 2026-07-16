$ErrorActionPreference = 'Stop'
# gen_m25.ps1 - generate an INERT $LogFile capturing a CLEAN create/rename/ADS/delete
# narrative on a scratch NTFS VHD. Marker strings only, no code.
$base = 'E:\DFIR\afgen'; $out = Join-Path $base 'out25'; $log = Join-Path $base 'gen25.log'
New-Item -ItemType Directory -Force $out | Out-Null
function L($m){ Add-Content $log ("[{0}] {1}" -f (Get-Date -Format HH:mm:ss),$m); Write-Host $m }
Set-Content $log "=== module-25 generation ==="
$vhd = Join-Path $base 'logfile.vhd'
if (Test-Path $vhd) { Remove-Item $vhd -Force }

L '1) create + attach + format VHD as W:'
@"
create vdisk file="$vhd" maximum=64 type=fixed
select vdisk file="$vhd"
attach vdisk
convert mbr
create partition primary
format fs=ntfs quick label="EVIDENCE"
assign letter=W
"@ | Out-File -Encoding ascii "$base\mk25.txt"
diskpart /s "$base\mk25.txt" | Out-String | ForEach-Object { L $_ }

L '2) clean narrative: create -> rename -> ADS -> delete (each = distinct $LogFile opcodes)'
New-Item -ItemType Directory -Force 'W:\case' | Out-Null          # dir create
Set-Content 'W:\case\report.txt' 'MARKER-REPORT-0001 inert'       # file CREATE
Set-Content 'W:\case\notes.txt'  'MARKER-NOTES-0002 inert'
Set-Content 'W:\case\temp.log'   'MARKER-TEMP-0003 inert'
Start-Sleep -Milliseconds 300
Rename-Item 'W:\case\report.txt' 'report_final.txt'               # RENAME
Start-Sleep -Milliseconds 200
Set-Content -Path 'W:\case\notes.txt' -Stream 'hidden' -Value 'MARKER-ADS-0004 inert'  # ADS create
Start-Sleep -Milliseconds 200
Remove-Item 'W:\case\temp.log'                                    # DELETE
Start-Sleep -Milliseconds 300
# force metadata flush
Write-VolumeCache -DriveLetter W 2>$null

L '3) detach VHD'
@"
select vdisk file="$vhd"
detach vdisk
"@ | Out-File -Encoding ascii "$base\dt25.txt"
diskpart /s "$base\dt25.txt" | Out-String | ForEach-Object { L $_ }

L '4) carve $LogFile (inode 2) + $MFT (inode 0) with TSK in WSL'
$sh = @'
set -e
cd /mnt/e/DFIR/afgen
icat -o 128 logfile.vhd 2 > out25/LogFile.bin 2>/dev/null; echo "LogFile.bin=$(stat -c %s out25/LogFile.bin)"
icat -o 128 logfile.vhd 0 > out25/MFT 2>/dev/null; echo "MFT=$(stat -c %s out25/MFT)"
'@
[IO.File]::WriteAllText("$base\carve25.sh", ($sh -replace "`r`n","`n"), (New-Object System.Text.UTF8Encoding($false)))
wsl.exe -d Ubuntu-24.04 -u root -- bash -lc "bash /mnt/e/DFIR/afgen/carve25.sh" 2>&1 | ForEach-Object { L "wsl: $_" }
L ("out25: " + ((Get-ChildItem $out).Name -join ', '))
L 'DONE'
