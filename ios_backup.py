#!/usr/bin/env python3
"""
iPhone / iPad support (Windows + Linux + macOS), read-only.

1. find_backups()      - locate iTunes / Finder / idevicebackup2 backups on this computer
2. export_backup()     - unpack a backup into real file names and export photos, messages,
                         contacts, call history, notes, WhatsApp, Safari history to CSV/files
3. scan_backup()       - security scan of the backup (apps, profiles, jailbreak/spy hints)
4. live_backup()       - make a fresh backup from a connected iPhone (libimobiledevice)
5. Deleted text        - SQLite free-page recovery on exported databases (see forensics.py)

Limits (honest):
  * Encrypted backups need the backup password - this tool does NOT crack passwords.
    (In iTunes/Finder you can turn encryption off if you know the password.)
  * Data erased by "Erase All Content and Settings" is not recoverable: iOS destroys the keys.
    The real way back is an iCloud / computer backup made earlier.
  * Backup-based scans cannot see state-level spyware (Pegasus-class); for that use Amnesty's MVT
    (github.com/mvt-project/mvt) and Apple's Lockdown Mode.
"""
import csv
import os
import plistlib
import shutil
import sqlite3
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import backup_finder
import forensics
import report
import security_scan

HOME = Path(os.path.expanduser("~"))
APPLE_EPOCH = 978307200  # 2001-01-01 in unix seconds


def _p(msg):
    try:
        print(msg)
    except UnicodeEncodeError:
        print(str(msg).encode("ascii", "replace").decode())


# ---------------- locate ----------------
def backup_roots():
    roots = []
    if os.name == "nt":
        appdata = Path(os.environ.get("APPDATA", HOME / "AppData/Roaming"))
        roots += [appdata / "Apple Computer/MobileSync/Backup", HOME / "Apple/MobileSync/Backup"]
    elif sys.platform == "darwin":
        roots.append(HOME / "Library/Application Support/MobileSync/Backup")
    else:
        roots += [HOME / ".config/idevicebackup2", HOME / "idevicebackup", HOME / "iphone_backups"]
    return [r for r in roots if r.exists()]


def find_backups(extra_dirs=()):
    """Return list of dicts describing backups (folders that contain Manifest.plist)."""
    found = []
    for root in list(backup_roots()) + [Path(x) for x in extra_dirs]:
        cands = [root] + [d for d in root.glob("*") if d.is_dir()] if root.exists() else []
        for d in cands:
            if (d / "Manifest.plist").exists():
                found.append(describe_backup(d))
    return found


def _plist(path):
    try:
        with open(path, "rb") as f:
            return plistlib.load(f)
    except Exception:  # noqa: BLE001
        return {}


def describe_backup(d):
    d = Path(d)
    man, info = _plist(d / "Manifest.plist"), _plist(d / "Info.plist")
    lock = man.get("Lockdown", {})
    date = man.get("Date") or info.get("Last Backup Date")
    return {
        "path": d,
        "name": info.get("Device Name") or lock.get("DeviceName") or d.name,
        "model": info.get("Product Type") or lock.get("ProductType", ""),
        "ios": info.get("Product Version") or lock.get("ProductVersion", ""),
        "serial": info.get("Serial Number", ""),
        "encrypted": bool(man.get("IsEncrypted")),
        "date": date.strftime("%Y-%m-%d %H:%M") if hasattr(date, "strftime") else str(date or ""),
        "apps": sorted(info.get("Installed Applications", [])),
    }


# ---------------- unpack ----------------
def _to_dt(v):
    """Apple timestamps: seconds since 2001 (old) or nanoseconds (iOS 11+)."""
    try:
        v = float(v)
    except (TypeError, ValueError):
        return ""
    if v == 0:
        return ""
    if abs(v) > 1e11:
        v /= 1e9
    return datetime.fromtimestamp(v + APPLE_EPOCH, timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


def _manifest_rows(bdir):
    con = sqlite3.connect(f"file:{bdir / 'Manifest.db'}?mode=ro", uri=True)
    try:
        return con.execute(
            "SELECT fileID, domain, relativePath, flags FROM Files").fetchall()
    finally:
        con.close()


def unpack(bdir, out, wanted=None, log=_p):
    """Copy files out of the hashed layout to out/<domain>/<relativePath>.
    wanted(domain, rel) -> bool filters what to copy. Returns {(domain, rel): path}."""
    bdir, out = Path(bdir), Path(out)
    got = {}
    for fid, dom, rel, flags in _manifest_rows(bdir):
        if flags != 1 or not rel:      # 1 = regular file
            continue
        if wanted and not wanted(dom, rel):
            continue
        src = bdir / fid[:2] / fid
        if not src.exists():
            continue
        dst = out / dom / rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, dst)
        got[(dom, rel)] = dst
    return got


def _is_media(dom, rel):
    return dom == "CameraRollDomain" and rel.startswith("Media/DCIM")


DB_TARGETS = {
    ("HomeDomain", "Library/SMS/sms.db"): "sms",
    ("HomeDomain", "Library/AddressBook/AddressBook.sqlitedb"): "contacts",
    ("HomeDomain", "Library/CallHistoryDB/CallHistory.storedata"): "calls",
    ("HomeDomain", "Library/Safari/History.db"): "safari",
    ("AppDomainGroup-group.net.whatsapp.WhatsApp.shared", "ChatStorage.sqlite"): "whatsapp",
    ("AppDomainGroup-group.com.apple.notes", "NoteStore.sqlite"): "notes",
}


def _csv(path, header, rows):
    with open(path, "w", newline="", encoding="utf-8-sig") as f:
        w = csv.writer(f)
        w.writerow(header)
        w.writerows(rows)
    return len(rows)


def _q(db, sql):
    con = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
    try:
        return con.execute(sql).fetchall()
    except sqlite3.Error:
        return []
    finally:
        con.close()


def export_sms(db, out):
    rows = _q(db, """SELECT m.ROWID, m.date, m.is_from_me, COALESCE(h.id,''), COALESCE(m.text,''), m.service
                     FROM message m LEFT JOIN handle h ON h.ROWID=m.handle_id ORDER BY m.date""")
    return _csv(out / "messages.csv", ["id", "time_utc", "from_me", "contact", "text", "service"],
                [(a, _to_dt(b), c, d, e, f) for a, b, c, d, e, f in rows])


def export_contacts(db, out):
    people = _q(db, "SELECT ROWID, COALESCE(First,''), COALESCE(Last,''), COALESCE(Organization,'') FROM ABPerson")
    vals = {}
    for rid, prop, v in _q(db, "SELECT record_id, property, value FROM ABMultiValue"):
        vals.setdefault(rid, []).append((prop, v))
    rows, vcf = [], []
    for rid, first, last, org in people:
        nums = [v for p, v in vals.get(rid, []) if p == 3 and v]
        mails = [v for p, v in vals.get(rid, []) if p == 4 and v]
        rows.append((f"{first} {last}".strip() or org, org, "; ".join(nums), "; ".join(mails)))
        vcf.append("BEGIN:VCARD\nVERSION:3.0\nFN:%s\n%sEND:VCARD\n" % (
            f"{first} {last}".strip() or org, "".join(f"TEL:{n}\n" for n in nums)))
    (out / "contacts.vcf").write_text("".join(vcf), encoding="utf-8")
    return _csv(out / "contacts.csv", ["name", "organization", "phones", "emails"], rows)


def export_calls(db, out):
    rows = _q(db, "SELECT ZDATE, ZADDRESS, ZDURATION, ZORIGINATED, ZANSWERED FROM ZCALLRECORD ORDER BY ZDATE")
    return _csv(out / "call_history.csv", ["time_utc", "number", "seconds", "outgoing", "answered"],
                [(_to_dt(a), (b.decode("utf-8", "ignore") if isinstance(b, bytes) else b), c, d, e)
                 for a, b, c, d, e in rows])


def export_whatsapp(db, out):
    rows = _q(db, """SELECT ZMESSAGEDATE, ZISFROMME, COALESCE(ZFROMJID, ZTOJID, ''), COALESCE(ZTEXT,'')
                     FROM ZWAMESSAGE ORDER BY ZMESSAGEDATE""")
    return _csv(out / "whatsapp_messages.csv", ["time_utc", "from_me", "jid", "text"],
                [(_to_dt(a), b, c, d) for a, b, c, d in rows])


def export_safari(db, out):
    rows = _q(db, """SELECT v.visit_time, i.url, COALESCE(i.title,'') FROM history_visits v
                     JOIN history_items i ON i.id=v.history_item ORDER BY v.visit_time""")
    return _csv(out / "safari_history.csv", ["time_utc", "url", "title"],
                [(_to_dt(a), b, c) for a, b, c in rows])


EXPORTERS = {"sms": export_sms, "contacts": export_contacts, "calls": export_calls,
             "whatsapp": export_whatsapp, "safari": export_safari}


def export_backup(bdir, dest_root, log=_p, forensic=True, photos=True, owner_confirmed=False):
    if not owner_confirmed:
        log("Stopped: confirm the device is yours or you have the owner's permission.")
        return None
    bdir = Path(bdir)
    info = describe_backup(bdir)
    if info["encrypted"]:
        log("This backup is ENCRYPTED. Open iTunes/Finder, turn off 'Encrypt local backup' "
            "(you need the password) and make a new backup, then try again. "
            "This tool does not crack passwords.")
        return None
    if not (bdir / "Manifest.db").exists():
        log("Manifest.db not found - not a valid backup folder.")
        return None
    out = Path(dest_root) / ("iphone_export_" + time.strftime("%Y%m%d_%H%M%S"))
    out.mkdir(parents=True)
    forensics.custody(out, f"export started from {bdir} (owner/permission confirmed by operator)")
    log(f"Device: {info['name']} ({info['model']}), iOS {info['ios']}, backup {info['date']}")

    want = lambda dom, rel: (dom, rel) in DB_TARGETS or (photos and _is_media(dom, rel)) or \
        (dom == "MediaDomain" and rel.startswith("Media/Recordings"))
    log("Unpacking files...")
    got = unpack(bdir, out / "files", want, log)
    counts = {}
    for key, kind in DB_TARGETS.items():
        if key in got and kind in EXPORTERS:
            counts[kind] = EXPORTERS[kind](got[key], out)
            log(f"  {kind}: {counts[kind]} records")
    media = [p for k, p in got.items() if _is_media(*k)]
    log(f"  photos/videos: {len(media)} files")
    (out / "installed_apps.txt").write_text("\n".join(info["apps"]), encoding="utf-8")

    rows = forensics.build_manifest(out, log)
    deleted = forensics.scan_databases(out, log) if forensic else None
    forensics.custody(out, f"export finished: {len(rows)} files hashed")
    notes = ["iPhone data comes from the backup - anything newer than the backup date is not included."]
    report.write_report(out, "iPhone backup export report",
                        {"device": info["name"], "model": info["model"], "ios": info["ios"],
                         "backup_date": info["date"], **{f"{k}_records": v for k, v in counts.items()},
                         "photos_videos": len(media), "files": len(rows)},
                        forensics.type_summary(rows), notes, deleted)
    log(f"Done -> {out}")
    return out


# ---------------- security scan of a backup ----------------
JB_WORDS = ("cydia", "sileo", "zebra", "unc0ver", "checkra1n", "palera1n", "taurine", "dopamine",
            "installer5", "filza", "trollstore")


def scan_backup(bdir, dest_root, log=_p, owner_confirmed=False):
    if not owner_confirmed:
        log("Stopped: confirm the device is yours or you have the owner's permission.")
        return None
    bdir = Path(bdir)
    info = describe_backup(bdir)
    findings = []

    def add(sev, pts, title, detail, advice):
        findings.append({"sev": sev, "pts": pts, "title": title, "detail": detail, "advice": advice})

    apps = {}
    for bid in info["apps"]:
        apps[bid] = {"name": bid, "installer": "appstore", "system": bid.startswith("com.apple."),
                     "installed": "", "perms": set()}
        low = bid.lower()
        if any(w in low for w in JB_WORDS):
            apps[bid]["installer"] = None
            add("high", 30, "Jailbreak-related app: " + bid,
                "Jailbreak tools remove iOS protections and are used to install spyware.",
                "If you did not jailbreak this iPhone, treat it as compromised: back up photos, then erase and restore.")
        elif any(w in low for w in security_scan.SPY_WORDS) and not bid.startswith("com.apple."):
            apps[bid]["installer"] = None
            add("high", 20, "Suspicious app name: " + bid,
                "Name contains spy/monitor/tracker-like words (name match only - may be a false alarm).",
                "Delete it if you do not know it.")
    if info["encrypted"]:
        add("info", 0, "Backup is encrypted", "Only metadata could be read; message/photo content was not inspected.",
            "Scan again from an unencrypted backup if you know the password.")
    elif (bdir / "Manifest.db").exists():
        try:
            profs = [(d, r) for _f, d, r, fl in _manifest_rows(bdir)
                     if "configurationprofiles" in d.lower() and fl == 1 and r.lower().endswith(".plist")]
            names = {r for _d, r in profs}
            if any("CloudConfigurationDetails" in r or "MDM" in r.upper() for r in names):
                add("high", 25, "MDM / supervision profile present",
                    "A management profile lets an organisation (or an attacker) control settings, apps and traffic.",
                    "Settings > General > VPN & Device Management: remove profiles you did not install.")
            elif profs:
                add("medium", 10, "Configuration profile files present",
                    "Profiles can route traffic through a proxy/VPN or install certificates.",
                    "Check Settings > General > VPN & Device Management.")
        except sqlite3.Error:
            pass
    try:
        major = int(str(info["ios"]).split(".")[0])
        if major and major < 16:
            add("medium", 12, f"Old iOS version ({info['ios']})",
                "Old iOS versions miss many security fixes.", "Update in Settings > General > Software Update.")
    except ValueError:
        pass

    score = min(100, sum(f["pts"] for f in findings))
    d = {"props": {"ro.product.manufacturer": "Apple", "ro.product.model": f"{info['name']} ({info['model']})",
                   "ro.build.version.release": info["ios"], "platform": "iOS",
                   "ro.build.version.security_patch": info["date"][:10]}, "launchers": set()}
    out = Path(dest_root) / ("iphone_scan_" + time.strftime("%Y%m%d_%H%M%S"))
    extra = ["Backup scans cannot see state-level spyware. If you are a journalist/activist or got an Apple "
             "threat notification: use Amnesty's MVT (github.com/mvt-project/mvt) and turn on Lockdown Mode.",
             "Change your Apple ID password from a trusted device and review Settings > [your name] > Devices."]
    rep = security_scan.write_report(out, d, findings, apps, score, extra)
    log(f"Risk score: {score}/100, findings: {len(findings)}")
    log(f"Report: {rep}")
    return rep


# ---------------- live backup (libimobiledevice) ----------------
def find_tool(name):
    exe = shutil.which(name)
    if exe:
        return exe
    suffix = ".exe" if os.name == "nt" else ""
    for base in (Path(__file__).parent / "libimobiledevice", HOME / "libimobiledevice",
                 Path("C:/libimobiledevice"), Path("/usr/local/bin"), Path("/usr/bin")):
        c = base / (name + suffix)
        if c.exists():
            return str(c)
    return None


def live_devices():
    tool = find_tool("idevice_id")
    if not tool:
        return None
    r = subprocess.run([tool, "-l"], capture_output=True, text=True, timeout=30)
    return [x for x in r.stdout.split() if x]


def live_backup(dest_root, log=_p, owner_confirmed=False):
    """Back up a connected, unlocked, 'Trust'-ed iPhone with idevicebackup2."""
    if not owner_confirmed:
        log("Stopped: confirm the device is yours or you have the owner's permission.")
        return None
    tool = find_tool("idevicebackup2")
    if not tool:
        log("libimobiledevice not found. Install: Linux `sudo apt install libimobiledevice-utils usbmuxd`; "
            "Windows: unzip a libimobiledevice build into a 'libimobiledevice' folder next to these scripts; "
            "or simply make a backup with iTunes / Apple Devices app / Finder and use 'Find backups'.")
        return None
    devs = live_devices()
    if not devs:
        log("No iPhone detected. Unlock it, connect USB, tap 'Trust This Computer' and enter the passcode.")
        return None
    dest = Path(dest_root) / ("iphone_backup_" + time.strftime("%Y%m%d_%H%M%S"))
    dest.mkdir(parents=True)
    log(f"Backing up {devs[0]} to {dest} (can take a long time; keep the phone unlocked)...")
    p = subprocess.Popen([tool, "backup", "--full", str(dest)], stdout=subprocess.PIPE,
                         stderr=subprocess.STDOUT, text=True)
    for line in p.stdout:
        if line.strip():
            log(line.rstrip())
    p.wait()
    found = [d for d in dest.glob("*") if (d / "Manifest.plist").exists()]
    if p.returncode != 0 or not found:
        log("Backup did not finish. If the phone has a backup password set, remove it in iTunes/Finder first.")
        return None
    log(f"Backup folder: {found[0]}")
    return found[0]


if __name__ == "__main__":
    for b in find_backups():
        print(b["name"], b["model"], "iOS", b["ios"], b["date"], "ENCRYPTED" if b["encrypted"] else "", b["path"])
    if not find_backups():
        print("No iPhone backups found in the standard locations.")
