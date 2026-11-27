#!/usr/bin/env python3
"""
Android Backup Finder  (Windows / Python 3.8+, no extra packages)

1. Scan your PC for phone backups (Samsung Smart Switch, WhatsApp, Google Drive,
   Android .ab backups, photo folders, etc.)
2. If a phone is connected with USB debugging + ADB, list and copy backup-able
   folders (DCIM, Pictures, Download, WhatsApp, Documents) to your PC.
3. Print a checklist of cloud backups (Samsung / Google) to check.

NOTE: This tool only FINDS and COPIES existing backups/files. It cannot
decrypt or restore data erased by a factory reset on an encrypted phone.
It is read-only toward the phone (uses only `adb pull` / `ls`).
"""
import os
import shutil
import string
import subprocess
import sys
import time
from pathlib import Path

HOME = Path(os.path.expanduser("~"))

# ---------- 1. PC scan ----------
KNOWN_DIRS = {
    "Samsung Smart Switch backup": [
        HOME / "Documents" / "Samsung" / "SmartSwitch" / "backup",
        HOME / "AppData" / "Roaming" / "Samsung" / "SmartSwitch",
    ],
    "Samsung Kies backup": [HOME / "Documents" / "Samsung" / "Kies" / "Backup"],
    "Google Drive (desktop)": [HOME / "Google Drive", Path("G:/My Drive")],
    "Phone photo/video folders": [
        HOME / "Pictures", HOME / "Videos", HOME / "Downloads", HOME / "Desktop",
    ],
    "WhatsApp Desktop data": [
        HOME / "AppData" / "Local" / "Packages",  # filtered below
    ],
}

# file patterns that usually mean "phone backup"
BACKUP_EXT = {
    ".crypt12": "WhatsApp backup", ".crypt14": "WhatsApp backup",
    ".crypt15": "WhatsApp backup", ".ab": "Android adb backup",
    ".vcf": "Contacts export", ".sbu": "Samsung backup",
    ".bk": "Backup", ".apk": "App package",
}
BACKUP_NAME_HINTS = ("smartswitch", "smart switch", "samsung", "backup",
                     "msgstore", "whatsapp", "titanium", "helium")
SKIP_DIRS = {"windows", "program files", "program files (x86)", "programdata",
             "$recycle.bin", "system volume information", "node_modules",
             ".git", "appdata", "proc", "sys", "dev", "run", "snap", "lost+found"}


def human(n):
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024:
            return f"{n:.0f} {unit}"
        n /= 1024
    return f"{n:.1f} TB"


def drives():
    out = []
    for letter in string.ascii_uppercase:
        p = Path(f"{letter}:/")
        if p.exists():
            out.append(p)
    return out


def is_windows():
    return os.name == "nt"


def scan_roots():
    """Folders to walk when searching for backups (Windows: all drives; Linux: home + mounts)."""
    if is_windows():
        return drives()
    roots = [HOME]
    for base in ("/media", "/mnt", "/run/media"):
        b = Path(base)
        if b.exists():
            roots += [x for x in b.rglob("*") if x.is_dir() and x.parent in (b, b / os.environ.get("USER", ""))] or [b]
    return [r for r in dict.fromkeys(roots) if r.exists()]


def raw_sources():
    """[(label, raw device path)] for the carver (Windows: E: drive, Linux: /dev/sdb1 ...)."""
    out = []
    if is_windows():
        for d in drives():
            out.append((f"{str(d)[0]}: drive", "\\\\.\\" + str(d)[0] + ":"))
    else:
        try:
            for line in open("/proc/partitions").read().splitlines()[2:]:
                parts = line.split()
                if len(parts) == 4 and parts[3][:2] in ("sd", "vd", "nv", "mm", "hd"):
                    gb = int(parts[2]) / 1024 / 1024
                    out.append((f"/dev/{parts[3]}  ({gb:.1f} GB)", f"/dev/{parts[3]}"))
        except OSError:
            pass
    return out


def open_path(path):
    """Open a folder in the file manager (Windows/Linux/macOS)."""
    try:
        if is_windows():
            os.startfile(path)
        elif sys.platform == "darwin":
            subprocess.run(["open", str(path)])
        else:
            subprocess.run(["xdg-open", str(path)])
    except Exception:  # noqa: BLE001
        pass


def scan_known():
    print("\n[1/2] Known backup locations")
    found = False
    for label, paths in KNOWN_DIRS.items():
        for p in paths:
            try:
                if not p.exists():
                    continue
                if "Packages" in str(p):
                    hits = [d for d in p.iterdir() if "whatsapp" in d.name.lower()]
                    for h in hits:
                        print(f"  FOUND  {label}: {h}")
                        found = True
                    continue
                size = sum(f.stat().st_size for f in p.rglob("*") if f.is_file())
                print(f"  FOUND  {label}: {p}  ({human(size)})")
                found = True
            except (PermissionError, OSError):
                pass
    if not found:
        print("  nothing found in the standard locations.")


def scan_drives(max_seconds=120):
    print("\n[2/2] Scanning all drives for backup-like files "
          f"(max {max_seconds}s, Ctrl+C to stop)")
    start = time.time()
    results = []
    try:
        for d in scan_roots():
            for root, dirs, files in os.walk(d, onerror=lambda e: None):
                if time.time() - start > max_seconds:
                    raise KeyboardInterrupt
                dirs[:] = [x for x in dirs if x.lower() not in SKIP_DIRS]
                for name in files:
                    low = name.lower()
                    ext = os.path.splitext(low)[1]
                    kind = BACKUP_EXT.get(ext)
                    if not kind and ext in (".zip", ".7z", ".rar", ".db"):
                        if any(h in low or h in root.lower() for h in BACKUP_NAME_HINTS):
                            kind = "Possible backup archive"
                    if kind:
                        fp = os.path.join(root, name)
                        try:
                            results.append((kind, fp, os.path.getsize(fp)))
                        except OSError:
                            pass
    except KeyboardInterrupt:
        print("  (scan stopped early)")
    if not results:
        print("  no backup-like files found.")
        return
    results.sort(key=lambda r: (r[0], -r[2]))
    for kind, fp, size in results[:200]:
        print(f"  {kind:24s} {human(size):>9s}  {fp}")
    if len(results) > 200:
        print(f"  ... and {len(results) - 200} more")


# ---------- 2. ADB ----------
def find_adb():
    exe = shutil.which("adb")
    if exe:
        return exe
    name = "adb.exe" if is_windows() else "adb"
    here = Path(__file__).parent
    for c in (
        here / "platform-tools" / name,
        HOME / "AppData/Local/Android/Sdk/platform-tools" / name,
        Path("C:/platform-tools") / name,
        Path("C:/adb") / name,
        HOME / "Downloads/platform-tools" / name,
        HOME / "platform-tools" / name,
        HOME / "Android/Sdk/platform-tools" / name,
        Path("/usr/bin/adb"), Path("/usr/local/bin/adb"), Path("/opt/platform-tools/adb"),
    ):
        if c.exists():
            return str(c)
    return None


def adb(adb_exe, *args, timeout=60):
    return subprocess.run([adb_exe, *args], capture_output=True, text=True,
                          timeout=timeout)


PHONE_DIRS = [
    "/sdcard/DCIM", "/sdcard/Pictures", "/sdcard/Download", "/sdcard/Documents",
    "/sdcard/WhatsApp", "/sdcard/Android/media/com.whatsapp/WhatsApp",
    "/sdcard/Movies", "/sdcard/Music", "/sdcard/Recordings",
    "/sdcard/Samsung", "/sdcard/Backup",
]


def adb_flow():
    exe = find_adb()
    if not exe:
        print("\nADB not found.")
        print("  Download 'SDK Platform-Tools' ONLY from developer.android.com,")
        print("  unzip it, and put the 'platform-tools' folder next to this script.")
        return
    try:
        out = adb(exe, "devices").stdout
    except Exception as e:  # noqa: BLE001
        print("ADB error:", e)
        return
    devs = [l.split()[0] for l in out.splitlines()[1:] if l.strip().endswith("device")]
    if not devs:
        print("\nNo phone detected. On the phone: Settings > About phone > tap")
        print("'Build number' 7 times > Developer options > USB debugging ON,")
        print("connect USB, and tap 'Allow' on the phone.")
        if "unauthorized" in out:
            print("(Phone is connected but 'unauthorized' - accept the prompt.)")
        return
    print(f"\nPhone connected: {devs[0]}")
    present = []
    for d in PHONE_DIRS:
        r = adb(exe, "shell", f'ls -d "{d}" 2>/dev/null && du -sh "{d}" 2>/dev/null')
        if r.stdout.strip():
            size = r.stdout.strip().splitlines()[-1].split()[0]
            present.append(d)
            print(f"  [{len(present)}] {d}  ({size})")
    if not present:
        print("  No standard folders found on the phone storage.")
        return
    pick = input("Copy which? numbers separated by comma, 'all', or Enter to skip: ").strip()
    if not pick:
        return
    chosen = present if pick.lower() == "all" else [
        present[int(x) - 1] for x in pick.replace(" ", "").split(",")
        if x.isdigit() and 0 < int(x) <= len(present)
    ]
    dest = Path.cwd() / ("phone_backup_" + time.strftime("%Y%m%d_%H%M%S"))
    dest.mkdir(parents=True, exist_ok=True)
    for d in chosen:
        print(f"  copying {d} ...")
        r = adb(exe, "pull", d, str(dest), timeout=3600)
        print("   ", (r.stdout.strip().splitlines() or [r.stderr.strip()])[-1])
    print(f"\nDone. Files are in: {dest}")


# ---------- 3. Cloud checklist ----------
def cloud_checklist():
    print("""
Cloud backups to check (do these in a browser / on the phone):
  [ ] Google Photos ......... https://photos.google.com  (also check Trash/Bin)
  [ ] Google Drive backups .. https://drive.google.com/drive/backups
  [ ] Gmail contacts ........ https://contacts.google.com
  [ ] Samsung Cloud ......... Settings > Accounts and backup > Restore data
  [ ] WhatsApp .............. reinstall, same number, tap 'Restore'
  [ ] Other: SD card (put it in a PC), old PC/laptop copies, Telegram saved chats
""")


MENU = """
===== Android Backup Finder =====
 1) Scan this PC for phone backups
 2) Detect phone via ADB and copy folders to PC
 3) Show cloud-backup checklist
 4) Run all
 0) Exit
"""


def main():
    while True:
        print(MENU)
        c = input("Choose: ").strip()
        if c == "1":
            scan_known(); scan_drives()
        elif c == "2":
            adb_flow()
        elif c == "3":
            cloud_checklist()
        elif c == "4":
            scan_known(); scan_drives(); adb_flow(); cloud_checklist()
        elif c == "0":
            return
        else:
            print("Invalid choice.")


if __name__ == "__main__":
    try:
        main()
    except (KeyboardInterrupt, EOFError):
        print("\nBye.")
        sys.exit(0)
