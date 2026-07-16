$ErrorActionPreference = 'Stop'
# gen_m23.ps1 - generate INERT wiping-tool-mark artifacts on a scratch NTFS VHD.
# Wipers run ONLY against the scratch volume W:. Decoys hold marker strings only (no code).
$base = 'E:\DFIR\afgen'
$out  = Join-Path $base 'out'
$log  = Join-Path $base 'gen.log'
New-Item -ItemType Directory -Force $out | Out-Null
function L($m){ $s="[{0}] {1}" -f (Get-Date -Format HH:mm:ss),$m; Add-Content $log $s; Write-Host $s }
Set-Content $log "=== module-23 generation ==="
$vhd = Join-Path $base 'wipe.vhd'
if (Test-Path $vhd) { Remove-Item $vhd -Force }

L '1) create + attach + format VHD as W:'
@"
create vdisk file="$vhd" maximum=96 type=fixed
select vdisk file="$vhd"
attach vdisk
convert mbr
create partition primary
format fs=ntfs quick label="CASEDISK"
assign letter=W
"@ | Out-File -Encoding ascii "$base\mk.txt"
diskpart /s "$base\mk.txt" | Out-String | ForEach-Object { L $_ }

L '2) enable USN journal on W:'
& fsutil usn createjournal W: m=524288 a=65536 | Out-Null
& fsutil usn queryjournal W: | Out-String | ForEach-Object { L $_ }

L '3) create decoy sensitive files (marker strings only, inert)'
New-Item -ItemType Directory -Force 'W:\case' | Out-Null
Set-Content 'W:\case\secret_plans.txt' 'MARKER-SECRETPLANS-0001 :: benign lab decoy, no code'
Set-Content 'W:\case\payroll.csv'       'MARKER-PAYROLL-0002 :: benign lab decoy'
Set-Content 'W:\case\creds.txt'         'MARKER-CREDS-0003 :: benign lab decoy'
Start-Sleep -Milliseconds 400

L '4) SDelete the primary decoy (26-rename chain + DataOverwrite + FileDelete in USN)'
$sd = Join-Path $base 'sdelete64.exe'
& $sd -accepteula -nobanner -p 1 'W:\case\secret_plans.txt' 2>&1 | ForEach-Object { L "sdelete: $_" }
Start-Sleep -Milliseconds 400

L '5) cipher /w free-space wipe on W: (creates EFSTMPWP + fil*.tmp)'
& cipher.exe /w:W:\ 2>&1 | Select-Object -First 6 | ForEach-Object { L "cipher: $_" }
Start-Sleep -Milliseconds 400

L '6) record on-disk state before detach'
(& cmd /c dir /a W:\ 2>&1) | Out-String | ForEach-Object { L $_ }
$efs = Test-Path 'W:\EFSTMPWP'
L "EFSTMPWP present on volume: $efs"
$usnlines = (& fsutil usn readjournal W: csv 2>$null | Measure-Object -Line).Lines
L "usn readjournal lines: $usnlines"

L '7) detach VHD'
@"
select vdisk file="$vhd"
detach vdisk
"@ | Out-File -Encoding ascii "$base\dt.txt"
diskpart /s "$base\dt.txt" | Out-String | ForEach-Object { L $_ }
L "vhd size=$((Get-Item $vhd).Length)"

L '8) carve `$MFT` + `$UsnJrnl:`$J with TSK in WSL'
$wsl = @'
set -e
cd /mnt/e/DFIR/afgen
OFF=$(mmls wipe.vhd 2>/dev/null | awk '/NTFS|Basic|07/{print $3; exit}' | sed "s/^0*//")
[ -z "$OFF" ] && OFF=128
echo "offset=$OFF"
mkdir -p out
icat -o $OFF wipe.vhd 0 > out/MFT 2>/dev/null; echo "MFT bytes=$(stat -c %s out/MFT)"
JTOK=$(fls -o $OFF -a wipe.vhd 11 2>/dev/null | grep -F 'UsnJrnl:$J' | awk '{print $2}' | tr -d ':' | head -1)
echo "J token=$JTOK"
if [ -n "$JTOK" ]; then icat -o $OFF wipe.vhd "$JTOK" > out/UsnJrnl_J 2>/dev/null; echo "UsnJrnl_J bytes=$(stat -c %s out/UsnJrnl_J)"; fi
fls -o $OFF -r -p wipe.vhd 2>/dev/null | grep -iE 'EFSTMPWP|case|secret|payroll|creds' | head -20
'@
$wsl | Out-File -Encoding ascii "$base\carve.sh"
# strip CR for unix
$c = [IO.File]::ReadAllText("$base\carve.sh") -replace "`r",""
[IO.File]::WriteAllText("$base\carve.sh", $c)
& wsl.exe -d Ubuntu-24.04 -u root -- bash -lc "bash /mnt/e/DFIR/afgen/carve.sh" 2>&1 | ForEach-Object { L "wsl: $_" }

L '9) harvest SDelete/cipher prefetch from this host (inert metadata)'
Get-ChildItem 'C:\Windows\Prefetch' -Filter 'SDELETE*.pf' -ErrorAction SilentlyContinue | Copy-Item -Destination $out -Force
Get-ChildItem 'C:\Windows\Prefetch' -Filter 'CIPHER*.pf' -ErrorAction SilentlyContinue | Copy-Item -Destination $out -Force
L ("prefetch harvested: " + ((Get-ChildItem $out -Filter *.pf -ErrorAction SilentlyContinue).Name -join ', '))

L '10) stage the wipe image (shrunk copy) into out/'
Copy-Item $vhd (Join-Path $out 'disk-wipe-lab.vhd') -Force
L ("out contents: " + ((Get-ChildItem $out).Name -join ', '))
L 'DONE'
