# Module 16 — reference output

Real, captured output of **every `rip` command** in the module README, so you can read and study the lesson without running RegRipper (and so the SOFTWARE-hive steps are readable even before you fetch that hive via `../data/get-data.sh`).

Each file starts with the exact native command that produced it (`$ rip -r <hive> -p <plugin>`), generated against the hives in `../data/` with RegRipper 3.0.

| File | Command | Hive (host) |
|---|---|---|
| `01-system-compname.txt` | `rip -r SYSTEM -p compname` | SYSTEM (CITADEL-DC01) |
| `02-system-timezone.txt` | `rip -r SYSTEM -p timezone` | SYSTEM (CITADEL-DC01) |
| `03-system-services.txt` | `rip -r SYSTEM -p services` | SYSTEM (CITADEL-DC01) — **coreupdater service** |
| `04-system-usbstor.txt` | `rip -r SYSTEM -p usbstor` | SYSTEM (CITADEL-DC01) — negative result |
| `05-system-usb.txt` | `rip -r SYSTEM -p usb` | SYSTEM (CITADEL-DC01) |
| `06-system-shutdown.txt` | `rip -r SYSTEM -p shutdown` | SYSTEM (CITADEL-DC01) |
| `07-system-mountdev.txt` | `rip -r SYSTEM -p mountdev` | SYSTEM (CITADEL-DC01) |
| `08-sam-samparse.txt` | `rip -r SAM -p samparse` | SAM (CITADEL-DC01) |
| `09-software-run.txt` | `rip -r SOFTWARE -p run` | SOFTWARE (CITADEL-DC01) — **fileless coreupdate Run key** |
| `10-software-uninstall.txt` | `rip -r SOFTWARE -p uninstall` | SOFTWARE (CITADEL-DC01) |
| `11-software-networklist.txt` | `rip -r SOFTWARE -p networklist` | SOFTWARE (CITADEL-DC01) — C137.local |
| `12-software-lastloggedon.txt` | `rip -r SOFTWARE -p lastloggedon` | SOFTWARE (CITADEL-DC01) |
| `13-software-profilelist.txt` | `rip -r SOFTWARE -p profilelist` | SOFTWARE (CITADEL-DC01) |
| `14-ntuser-morty-recentdocs.txt` | `rip -r NTUSER.DAT -p recentdocs` | NTUSER (mortysmith) |
| `15-ntuser-morty-userassist.txt` | `rip -r NTUSER.DAT -p userassist` | NTUSER (mortysmith) |
| `16-ntuser-morty-run.txt` | `rip -r NTUSER.DAT -p run` | NTUSER (mortysmith) |
| `17-usrclass-morty-shellbags.txt` | `rip -r UsrClass.dat -p shellbags` | UsrClass (mortysmith) |
| `18-ntuser-admin-userassist.txt` | `rip -r Administrator_NTUSER.DAT -p userassist` | NTUSER (Administrator) — **coreupdater.exe executed** |
| `19-ntuser-admin-run.txt` | `rip -r Administrator_NTUSER.DAT -p run` | NTUSER (Administrator) |
