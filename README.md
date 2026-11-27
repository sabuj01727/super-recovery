# Super Recovery

Free, open-source data-recovery and phone-safety toolkit for **Android, iPhone and disks**.
One window, no extra Python packages, works on **Windows and Linux**.

```
python super_recovery.py
```

## Features

| Tab | What it does |
|---|---|
| **Wizard** | Asks what happened and tells you honestly how likely recovery is |
| **File Recovery** | Signature-based "carving" of deleted files from SD cards, USB drives, disk images and raw drives: JPG, PNG, GIF, BMP, WebP, **HEIC**, PDF, ZIP/DOCX/APK, MP4/**MOV**/3GP/M4A, AVI, SQLite, 7z, WAV, MP3, OGG, FLAC, RAR. Quick or deep scan, minimum size filter, ETA, stop button, duplicate skipping |
| **Find Backups** | Looks on your PC for Samsung Smart Switch, WhatsApp, Google Drive and other phone backups, plus a cloud-backup checklist |
| **Android** | One-click backup over ADB: contacts, SMS, call log, app list, DCIM / WhatsApp / Downloads, with hashes and a report |
| **iPhone** | Finds iTunes / Finder / Apple Devices backups, exports photos, messages, contacts, calls, WhatsApp, Safari history, recovers deleted message text, security-scans the backup. Live backup via libimobiledevice |
| **Forensics** | SHA-256 manifest, timeline, chain-of-custody log, deleted-text recovery from SQLite databases, HTML report |
| **Hack Scan** | Checks an Android phone (or iPhone backup) for stalkerware indicators and draws a report: risk gauge, suspicious-app chart, permission heat-map, install timeline, what to do |

Everything is **read-only** toward your source drive or phone.

## Install

**Windows:** install Python 3.8+ from python.org, then double-click `run_windows.bat`.

**Linux (Debian/Ubuntu):**
```
sudo apt install python3 python3-tk adb libimobiledevice-utils usbmuxd
./run_linux.sh          # use sudo to scan raw disks (/dev/sdX)
```

- **Android over USB:** put Google's *SDK Platform-Tools* in a `platform-tools` folder next to the scripts (or install `adb`). Enable *USB debugging* and tap *Allow* on the phone.
- **iPhone live backup (optional):** put a libimobiledevice build in a `libimobiledevice` folder, or just make a backup with iTunes / Finder / Apple Devices and use *Find backups*.

## Tests

```
python selftest.py        # file carver on a synthetic disk image
python test_security.py   # Android hack-scan on a synthetic phone
python test_ios.py        # iPhone backup export / scan / HEIC+MOV carving
python test_gui.py        # GUI smoke test
```
The tests use generated data only. The tool has not been validated on a wide range of real devices yet; please report bugs.

## Honest limits - please read

- **A factory-reset encrypted Android phone or an erased iPhone cannot be recovered by any software.**
  The encryption key is destroyed. Anything claiming otherwise is fake or malware. Your real options are a cloud or computer backup made earlier.
- **Encrypted iTunes backups** need their password removed first. This project will never crack passwords.
- File recovery is **signature carving**: no original file names/folders for deleted PC files, no filesystem-aware (NTFS / APFS) undelete, no RAID.
- Hack scans are **heuristics** (names, permissions, settings). They cannot prove a phone is clean. For state-level spyware use [Amnesty MVT](https://github.com/mvt-project/mvt) and Apple Lockdown Mode.
- Save recovered files to a **different drive** than the source.

## Responsible use

Use only on devices and data you own, or where you have the owner's **written permission**. The phone tools ask you to confirm this. Do not use them to access someone else's phone.

## License

MIT - see `LICENSE`. Provided "as is", without warranty.
