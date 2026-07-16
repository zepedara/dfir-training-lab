$ErrorActionPreference = 'Stop'
# gen_m26b.ps1 - INERT unallocated-carving scenario: benign files (markers + a
# FAKE BitLocker recovery key) are created then DELETED, so their content survives
# in unallocated space for blkls+grep carving. No code, marker strings only.
$base='E:\DFIR\afgen'; $out=Join-Path $base 'out26b'; $log=Join-Path $base 'gen26b.log'
New-Item -ItemType Directory -Force $out | Out-Null
function L($m){ Add-Content $log ("[{0}] {1}" -f (Get-Date -Format HH:mm:ss),$m); Write-Host $m }
Set-Content $log "=== module-26 carving generation ==="
$vhd=Join-Path $base 'carvelab.vhd'
@"
select vdisk file="$vhd"
detach vdisk
"@ | Out-File -Encoding ascii "$base\pre26b.txt"
diskpart /s "$base\pre26b.txt" 2>&1 | Out-Null
Start-Sleep -Milliseconds 400
if (Test-Path $vhd){ Remove-Item $vhd -Force -ErrorAction SilentlyContinue }

L '1) create + attach + format 20MB VHD as W:'
@"
create vdisk file="$vhd" maximum=20 type=fixed
select vdisk file="$vhd"
attach vdisk
convert mbr
create partition primary
format fs=ntfs quick label="CASE"
assign letter=W
"@ | Out-File -Encoding ascii "$base\mk26b.txt"
diskpart /s "$base\mk26b.txt" | Out-String | ForEach-Object { L $_ }

L '2) create benign decoys (markers + a FAKE BitLocker recovery key), then DELETE'
New-Item -ItemType Directory -Force 'W:\case' | Out-Null
# fake BitLocker recovery key FORMAT (8 x 6 digits) -- not a real key
$bl = '247183-556031-118924-330756-490217-661508-772349-883160'
# pad each file >1KB so it is NON-resident (content lands in data clusters, not the MFT record)
$pad = ("`r`n" + ('.lab-filler-benign-padding' * 60)) * 3
Set-Content 'W:\case\bitlocker_backup.txt' ("BitLocker Drive Encryption recovery key`r`nRecovery Key: $bl`r`nMARKER-BLKEY-9001 inert" + $pad)
Set-Content 'W:\case\exfil_manifest.txt'   ("MARKER-EXFIL-9002 :: staged files list, inert lab decoy" + $pad)
Set-Content 'W:\case\passwords.txt'        ("MARKER-CREDS-9003 :: inert lab decoy, no real secrets" + $pad)
# FLUSH the creates to disk FIRST so the data clusters are physically written
Write-VolumeCache -DriveLetter W 2>$null
Start-Sleep -Seconds 2
L 'decoys created + flushed to disk'
Remove-Item 'W:\case\bitlocker_backup.txt'
Remove-Item 'W:\case\exfil_manifest.txt'
Remove-Item 'W:\case\passwords.txt'
Write-VolumeCache -DriveLetter W 2>$null
Start-Sleep -Seconds 1
L 'decoys deleted; content now survives in unallocated'

L '3) detach VHD + stage the shippable image'
@"
select vdisk file="$vhd"
detach vdisk
"@ | Out-File -Encoding ascii "$base\dt26b.txt"
diskpart /s "$base\dt26b.txt" | Out-String | ForEach-Object { L $_ }
Copy-Item $vhd (Join-Path $out 'disk-carve-lab.raw') -Force
L ("image size MB=" + [math]::Round((Get-Item (Join-Path $out 'disk-carve-lab.raw')).Length/1MB,1))

L '4) FEASIBILITY: carve markers + BitLocker key from unallocated with blkls+grep (WSL TSK)'
$sh = @'
set -e
cd /mnt/e/DFIR/afgen/out26b
OFF=$(mmls disk-carve-lab.raw 2>/dev/null | awk "/NTFS|Basic|07/{print \$3; exit}" | sed "s/^0*//"); [ -z "$OFF" ] && OFF=128
echo "offset=$OFF"
blkls -o $OFF disk-carve-lab.raw > unalloc.raw 2>/dev/null
echo "unalloc bytes=$(stat -c %s unalloc.raw)"
echo "-- markers recovered --"; grep -aoE "MARKER-[A-Z]+-[0-9]+" unalloc.raw | sort -u
echo "-- BitLocker key recovered --"; grep -aoE "([0-9]{6}-){7}[0-9]{6}" unalloc.raw | sort -u
'@
[IO.File]::WriteAllText("$base\carve26b.sh", ($sh -replace "`r`n","`n"), (New-Object System.Text.UTF8Encoding($false)))
wsl.exe -d Ubuntu-24.04 -u root -- bash -lc "bash /mnt/e/DFIR/afgen/carve26b.sh" 2>&1 | ForEach-Object { L "wsl: $_" }
L 'DONE'
