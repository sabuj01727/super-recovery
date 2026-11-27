#!/usr/bin/env python3
"""
ADB Extractor - pulls whatever a CONNECTED, UNLOCKED phone will give over ADB
(USB debugging on, 'Allow' tapped on the phone). Read-only toward the phone.

Exports: device info, installed apps, contacts (CSV+VCF), SMS (CSV), call log (CSV),
full /sdcard copy, screenshot. Some Android versions block SMS/call-log queries
for the shell user - those parts will just be skipped with a note.
"""
import csv
import re
import time
from pathlib import Path

from backup_finder import adb, find_adb  # reuse helpers


def q(exe, uri, projection=None):
    cmd = f"content query --uri {uri}"
    if projection:
        cmd += f" --projection {projection}"
    r = adb(exe, "shell", cmd, timeout=180)
    rows = []
    for line in r.stdout.splitlines():
        if not line.startswith("Row:"):
            continue
        body = line.split(" ", 2)[2] if line.count(" ") >= 2 else ""
        # split on ", key=" boundaries so values may contain commas
        parts = re.split(r", (?=[A-Za-z_][A-Za-z0-9_]*=)", body)
        row = {}
        for p in parts:
            if "=" in p:
                k, v = p.split("=", 1)
                row[k.strip()] = v
        rows.append(row)
    return rows, r.stderr.strip()


def write_csv(path, rows):
    if not rows:
        return False
    keys = sorted({k for r in rows for k in r})
    with open(path, "w", newline="", encoding="utf-8-sig") as f:
        w = csv.DictWriter(f, fieldnames=keys)
        w.writeheader()
        w.writerows(rows)
    return True


def vcf(path, rows):
    seen = set()
    with open(path, "w", encoding="utf-8") as f:
        for r in rows:
            name = r.get("display_name") or r.get("name") or ""
            num = r.get("data1") or r.get("number") or ""
            if (name, num) in seen or not (name or num):
                continue
            seen.add((name, num))
            f.write(f"BEGIN:VCARD\nVERSION:3.0\nFN:{name}\nTEL:{num}\nEND:VCARD\n")


def run():
    exe = find_adb()
    if not exe:
        print("ADB not found (put platform-tools next to the scripts).")
        return
    out = adb(exe, "devices").stdout
    if not [l for l in out.splitlines()[1:] if l.strip().endswith("device")]:
        print("No authorized phone detected. Enable USB debugging and tap Allow.")
        return
    dest = Path.cwd() / ("adb_export_" + time.strftime("%Y%m%d_%H%M%S"))
    dest.mkdir(parents=True)

    info = {}
    for key in ("ro.product.model", "ro.product.manufacturer", "ro.build.version.release",
                "ro.build.version.sdk", "ro.crypto.state", "ro.serialno"):
        info[key] = adb(exe, "shell", f"getprop {key}").stdout.strip()
    (dest / "device_info.txt").write_text("\n".join(f"{k}: {v}" for k, v in info.items()))
    print("Device:", info["ro.product.manufacturer"], info["ro.product.model"],
          "| Android", info["ro.build.version.release"], "| crypto:", info["ro.crypto.state"])

    pk = adb(exe, "shell", "pm list packages -3").stdout
    (dest / "installed_apps.txt").write_text(pk)
    print("Apps:", len(pk.splitlines()))

    rows, err = q(exe, "content://com.android.contacts/data/phones",
                  "display_name:data1")
    if rows:
        write_csv(dest / "contacts.csv", rows)
        vcf(dest / "contacts.vcf", rows)
    print("Contacts:", len(rows), err[:80] if not rows else "")

    rows, err = q(exe, "content://sms", "address:date:body:type")
    write_csv(dest / "sms.csv", rows)
    print("SMS:", len(rows), err[:80] if not rows else "")

    rows, err = q(exe, "content://call_log/calls", "number:date:duration:type:name")
    write_csv(dest / "call_log.csv", rows)
    print("Call log:", len(rows), err[:80] if not rows else "")

    adb(exe, "shell", "screencap -p /sdcard/_shot.png")
    adb(exe, "pull", "/sdcard/_shot.png", str(dest / "screenshot.png"))
    adb(exe, "shell", "rm /sdcard/_shot.png")

    if input("Copy whole /sdcard to PC? may be large (y/N): ").lower().startswith("y"):
        r = adb(exe, "pull", "/sdcard/", str(dest / "sdcard"), timeout=6 * 3600)
        print((r.stdout.strip().splitlines() or [r.stderr.strip()])[-1])
    print("\nSaved to:", dest)


if __name__ == "__main__":
    run()
