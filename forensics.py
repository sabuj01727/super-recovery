#!/usr/bin/env python3
"""
Forensics helpers (read-only, for devices you own or have written permission for):
  - SHA-256 manifest + chain-of-custody log of every collected file
  - SQLite 'deleted data' recovery: text left in freelist pages / WAL of copied
    databases (WhatsApp msgstore.db, SMS/contacts DBs, browser DBs ...)
  - file-type summary and timeline (CSV)
"""
import csv
import hashlib
import os
import re
import struct
import time
from pathlib import Path

STR_RE = re.compile(rb"[\x20-\x7e\xc2-\xf4\x80-\xbf]{6,}")  # printable / utf-8-ish runs


def sha256_file(path, block=4 * 1024 * 1024):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            b = f.read(block)
            if not b:
                break
            h.update(b)
    return h.hexdigest()


def build_manifest(root, log=print):
    """Hash every file under root; writes manifest.csv, timeline.csv. Returns rows."""
    root = Path(root)
    rows = []
    for p in sorted(root.rglob("*")):
        if p.is_file() and p.name not in ("manifest.csv", "timeline.csv", "custody.log",
                                          "report.html", "deleted_strings.txt"):
            st = p.stat()
            rows.append({
                "path": str(p.relative_to(root)),
                "size": st.st_size,
                "sha256": sha256_file(p),
                "modified": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(st.st_mtime)),
            })
    with open(root / "manifest.csv", "w", newline="", encoding="utf-8-sig") as f:
        w = csv.DictWriter(f, fieldnames=["path", "size", "sha256", "modified"])
        w.writeheader(); w.writerows(rows)
    with open(root / "timeline.csv", "w", newline="", encoding="utf-8-sig") as f:
        w = csv.writer(f); w.writerow(["modified", "path", "size"])
        for r in sorted(rows, key=lambda r: r["modified"]):
            w.writerow([r["modified"], r["path"], r["size"]])
    log(f"manifest: {len(rows)} files hashed")
    return rows


def custody(root, text):
    with open(Path(root) / "custody.log", "a", encoding="utf-8") as f:
        f.write(time.strftime("[%Y-%m-%d %H:%M:%S] ") + text + "\n")


def type_summary(rows):
    out = {}
    for r in rows:
        ext = os.path.splitext(r["path"])[1].lower() or "(none)"
        c, s = out.get(ext, (0, 0))
        out[ext] = (c + 1, s + r["size"])
    return dict(sorted(out.items(), key=lambda kv: -kv[1][1]))


def sqlite_deleted_strings(db_path, min_len=6):
    """Text found in free (deleted) pages of a SQLite file + its -wal, if any."""
    found = []
    data = Path(db_path).read_bytes()
    if data[:16] != b"SQLite format 3\x00":
        return found
    ps = struct.unpack(">H", data[16:18])[0]
    ps = 65536 if ps == 1 else ps
    npages = len(data) // ps
    trunk = struct.unpack(">I", data[32:36])[0]
    free_pages, seen = [], set()
    while trunk and trunk not in seen and trunk <= npages:
        seen.add(trunk)
        free_pages.append(trunk)
        base = (trunk - 1) * ps
        nxt, cnt = struct.unpack(">II", data[base:base + 8])
        for i in range(min(cnt, (ps // 4) - 2)):
            leaf = struct.unpack(">I", data[base + 8 + 4 * i:base + 12 + 4 * i])[0]
            if 0 < leaf <= npages:
                free_pages.append(leaf)
        trunk = nxt
    for pg in free_pages:
        chunk = data[(pg - 1) * ps:pg * ps]
        for m in STR_RE.finditer(chunk):
            s = m.group().decode("utf-8", "ignore").strip()
            if len(s) >= min_len:
                found.append(f"[page {pg}] {s}")
    wal = Path(str(db_path) + "-wal")
    if wal.exists():
        for m in STR_RE.finditer(wal.read_bytes()):
            s = m.group().decode("utf-8", "ignore").strip()
            if len(s) >= min_len:
                found.append(f"[wal] {s}")
    return found


def scan_databases(root, log=print):
    """Find *.db/*.sqlite under root, write deleted_strings.txt. Returns count of strings."""
    root = Path(root)
    total = 0
    with open(root / "deleted_strings.txt", "w", encoding="utf-8") as out:
        for p in sorted(root.rglob("*")):
            if p.is_file() and p.suffix.lower() in (".db", ".sqlite", ".sqlite3"):
                try:
                    items = sqlite_deleted_strings(p)
                except Exception as e:  # noqa: BLE001
                    log(f"skip {p.name}: {e}")
                    continue
                if items:
                    out.write(f"==== {p.relative_to(root)} ====\n")
                    out.write("\n".join(items) + "\n\n")
                    total += len(items)
                    log(f"{p.name}: {len(items)} text fragments from deleted space")
    return total
