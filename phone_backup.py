#!/usr/bin/env python3
"""
One-click Android backup + forensic package via ADB (phone unlocked, USB debugging ON,
'Allow' tapped). Read-only toward the phone.

Output folder: device_info.txt, installed_apps.txt, contacts.csv/.vcf, sms.csv, call_log.csv,
files/ (DCIM, WhatsApp, ...), manifest.csv (SHA-256), timeline.csv, custody.log,
deleted_strings.txt, report.html
(iPhone: see ios_backup.py)
"""
import time
from pathlib import Path

import adb_extract
import backup_finder
import forensics
import report


def _p(msg):
    try:
        print(msg)
    except UnicodeEncodeError:
        print(str(msg).encode("ascii", "replace").decode())


def run_backup(dest_root, log=_p, folders=None, forensic=True, owner_confirmed=False):
    if not owner_confirmed:
        log("Stopped: confirm the phone is yours or you have the owner's written permission.")
        return None
    exe = backup_finder.find_adb()
    if not exe:
        log("adb not found. Download 'SDK Platform-Tools' from developer.android.com and put the "
            "platform-tools folder next to these scripts (Linux: sudo apt install adb).")
        return None
    out = backup_finder.adb(exe, "devices").stdout
    if not [l for l in out.splitlines()[1:] if l.strip().endswith("device")]:
        log("No authorized phone found. Enable USB debugging and tap 'Allow' on the phone.")
        return None

    dest = Path(dest_root) / ("phone_backup_" + time.strftime("%Y%m%d_%H%M%S"))
    dest.mkdir(parents=True)
    forensics.custody(dest, "collection started (owner/permission confirmed by operator)")

    info = {}
    for key in ("ro.product.manufacturer", "ro.product.model", "ro.build.version.release",
                "ro.build.version.sdk", "ro.crypto.state", "ro.build.fingerprint"):
        info[key] = backup_finder.adb(exe, "shell", f"getprop {key}").stdout.strip()
    (dest / "device_info.txt").write_text("\n".join(f"{k}: {v}" for k, v in info.items()), encoding="utf-8")
    log(f"Phone: {info['ro.product.manufacturer']} {info['ro.product.model']} (Android {info['ro.build.version.release']})")

    apps = backup_finder.adb(exe, "shell", "pm list packages -3").stdout
    (dest / "installed_apps.txt").write_text(apps, encoding="utf-8")

    counts = {}
    rows, _ = adb_extract.q(exe, "content://com.android.contacts/data/phones", "display_name:data1")
    if rows:
        adb_extract.write_csv(dest / "contacts.csv", rows)
        adb_extract.vcf(dest / "contacts.vcf", rows)
    counts["contacts"] = len(rows)
    rows, _ = adb_extract.q(exe, "content://sms", "address:date:body:type")
    adb_extract.write_csv(dest / "sms.csv", rows)
    counts["sms"] = len(rows)
    rows, _ = adb_extract.q(exe, "content://call_log/calls", "number:date:duration:type:name")
    adb_extract.write_csv(dest / "call_log.csv", rows)
    counts["call_log"] = len(rows)
    log(f"Contacts {counts['contacts']}, SMS {counts['sms']}, call log {counts['call_log']}")

    pulled = []
    for p in (folders or backup_finder.PHONE_DIRS):
        if backup_finder.adb(exe, "shell", f'ls -d "{p}" 2>/dev/null').stdout.strip():
            log(f"Copying: {p}")
            r = backup_finder.adb(exe, "pull", p, str(dest / "files"), timeout=6 * 3600)
            pulled.append(p)
            log("   " + (r.stdout.strip().splitlines() or [r.stderr.strip()])[-1])
    (dest / "files").mkdir(exist_ok=True)

    rows = forensics.build_manifest(dest, log)
    deleted = forensics.scan_databases(dest, log) if forensic else None
    forensics.custody(dest, f"collection finished: {len(rows)} files hashed, folders={pulled}")
    notes = []
    if info["ro.crypto.state"] == "encrypted":
        notes.append("Phone is encrypted - after a factory reset the internal data would not have been recoverable.")
    if not counts["sms"]:
        notes.append("SMS/call log empty - newer Android versions block these from ADB.")
    report.write_report(dest, "Android backup report",
                        {**info, **{f"count_{k}": v for k, v in counts.items()},
                         "copied_folders": ", ".join(pulled) or "-", "files": len(rows)},
                        forensics.type_summary(rows), notes, deleted)
    log(f"Done -> {dest}")
    return dest


def analyze_folder(folder, log=_p):
    """Forensic pass over any existing folder (e.g. a backup you already copied)."""
    folder = Path(folder)
    forensics.custody(folder, "analysis started")
    rows = forensics.build_manifest(folder, log)
    deleted = forensics.scan_databases(folder, log)
    report.write_report(folder, "Forensic analysis report", {"folder": str(folder), "files": len(rows)},
                        forensics.type_summary(rows), ["manifest.csv lists the SHA-256 of every file."], deleted)
    log(f"Report: {folder / 'report.html'}")
    return folder / "report.html"
