#!/usr/bin/env python3
"""
File Carver - signature-based recovery of deleted files from raw sources:
disk images (.img/.dd/.raw), SD cards, pen drives (\\\\.\\E: or \\\\.\\PhysicalDrive1
on Windows, needs Administrator), or any large file.

Recovers: JPG, PNG, GIF, BMP, PDF, ZIP/DOCX/XLSX/PPTX/APK, MP4/MOV/3GP, SQLite
(contacts/WhatsApp/SMS databases), MP3 (ID3), WAV, 7z, RAR.

READ-ONLY on the source. Output goes to a new folder; duplicates are skipped by hash.
"""
import hashlib
import os
import struct
import sys
import time
import zipfile  # noqa: F401  (kept for potential validation)
from pathlib import Path

CHUNK = 32 * 1024 * 1024      # scan window
OVERLAP = 1024 * 1024         # bytes kept between windows so headers aren't missed
MB = 1024 * 1024


# ---------- end-of-file finders: return length of file or None ----------
def _find_end(data, start, tail, max_len, tail_extra=0):
    end = data.find(tail, start + 4, start + max_len)
    return None if end < 0 else end + len(tail) + tail_extra - start


def size_jpg(d, s):
    # walk JPEG markers so embedded thumbnails' FFD9 don't cut the file short
    i = s + 2
    n = len(d)
    while i + 4 <= n:
        if d[i] != 0xFF:
            i += 1
            continue
        m = d[i + 1]
        if m == 0xD9:
            return i + 2 - s
        if m in (0x00, 0x01) or 0xD0 <= m <= 0xD7 or m == 0xFF:
            i += 1 if m == 0xFF else 2
            continue
        if m == 0xDA:  # start of scan: entropy data, find next real marker
            i += 2 + struct.unpack(">H", d[i + 2:i + 4])[0]
            while i + 2 <= n:
                if d[i] == 0xFF and d[i + 1] not in (0x00, 0xFF) and not (0xD0 <= d[i + 1] <= 0xD7):
                    break
                i += 1
            continue
        if i + 4 > n:
            return None
        i += 2 + struct.unpack(">H", d[i + 2:i + 4])[0]
    return None


def size_png(d, s):
    e = d.find(b"IEND", s + 8, s + 100 * MB)
    return None if e < 0 else e + 8 - s


def size_gif(d, s):
    e = d.find(b"\x00\x3b", s + 10, s + 50 * MB)
    return None if e < 0 else e + 2 - s


def size_bmp(d, s):
    if s + 6 > len(d):
        return None
    n = struct.unpack("<I", d[s + 2:s + 6])[0]
    return n if 100 < n < 100 * MB else None


def size_pdf(d, s):
    e = d.rfind(b"%%EOF", s, s + 200 * MB)
    if e < 0:
        return None
    nxt = d.find(b"%PDF-", s + 5, e)   # stop before a following pdf
    if nxt > 0:
        e2 = d.rfind(b"%%EOF", s, nxt)
        if e2 > 0:
            e = e2
    end = e + 5
    if d[end:end + 2] == b"\r\n":
        end += 2
    elif d[end:end + 1] in (b"\n", b"\r"):
        end += 1
    return end - s


def size_zip(d, s):
    e = d.find(b"PK\x05\x06", s + 30, s + 500 * MB)
    if e < 0 or e + 22 > len(d):
        return None
    clen = struct.unpack("<H", d[e + 20:e + 22])[0]
    return e + 22 + clen - s


def size_mp4(d, s):
    # s points at the 4-byte size field; walk top-level boxes
    i = s
    n = len(d)
    total = 0
    seen_moov = seen_mdat = False
    seen_meta = False
    while i + 8 <= n:
        size, typ = struct.unpack(">I4s", d[i:i + 8])
        if typ not in (b"ftyp", b"moov", b"mdat", b"free", b"skip", b"wide",
                       b"uuid", b"moof", b"mfra", b"pnot", b"meta", b"sidx"):
            break
        hdr = 8
        if size == 1:
            if i + 16 > n:
                break
            size = struct.unpack(">Q", d[i + 8:i + 16])[0]
            hdr = 16
        elif size == 0:
            size = n - i
        if size < hdr or size > 4 * 1024 * MB:
            break
        seen_moov |= typ == b"moov"
        seen_meta |= typ == b"meta"
        seen_mdat |= typ == b"mdat"
        i += size
        total += size
        if i > n:        # box extends beyond current window - caller re-reads bigger
            return -total  # negative = "need more data"
    return total if ((seen_moov or seen_meta) and seen_mdat) else None


def size_sqlite(d, s):
    if s + 100 > len(d):
        return None
    ps = struct.unpack(">H", d[s + 16:s + 18])[0]
    pages = struct.unpack(">I", d[s + 28:s + 32])[0]
    ps = 65536 if ps == 1 else ps
    if ps < 512 or ps & (ps - 1) or pages == 0:
        return None
    n = ps * pages
    return n if n < 2 * 1024 * MB else None


def size_7z(d, s):
    if s + 32 > len(d):
        return None
    nho, nhs = struct.unpack("<QQ", d[s + 12:s + 28])
    n = 32 + nho + nhs
    return n if n < 2 * 1024 * MB else None


def size_riff(kind):
    def f(d, s):
        if d[s + 8:s + 12] != kind:
            return None
        n = struct.unpack("<I", d[s + 4:s + 8])[0] + 8
        return n if n < 4 * 1024 * MB else None
    return f


def size_fixed(max_len):
    return lambda d, s: min(max_len, len(d) - s)


# name, extension, header, header offset-in-file, sizer, min size
SIGS = [
    ("jpg", "jpg", b"\xff\xd8\xff", 0, size_jpg, 2048),
    ("png", "png", b"\x89PNG\r\n\x1a\n", 0, size_png, 200),
    ("gif", "gif", b"GIF89a", 0, size_gif, 100),
    ("gif", "gif", b"GIF87a", 0, size_gif, 100),
    ("bmp", "bmp", b"BM", 0, size_bmp, 1024),
    ("pdf", "pdf", b"%PDF-", 0, size_pdf, 500),
    ("zip", "zip", b"PK\x03\x04", 0, size_zip, 100),
    ("mp4", "mp4", b"ftyp", 4, size_mp4, 2000),
    ("sqlite", "db", b"SQLite format 3\x00", 0, size_sqlite, 512),
    ("7z", "7z", b"7z\xbc\xaf\x27\x1c", 0, size_7z, 64),
    ("wav", "wav", b"RIFF", 0, size_riff(b"WAVE"), 1000),
    ("webp", "webp", b"RIFF", 0, size_riff(b"WEBP"), 500),
    ("avi", "avi", b"RIFF", 0, size_riff(b"AVI "), 5000),
    ("ogg", "ogg", b"OggS", 0, size_fixed(30 * MB), 20000),
    ("flac", "flac", b"fLaC", 0, size_fixed(60 * MB), 20000),
    ("mp3", "mp3", b"ID3", 0, size_fixed(15 * MB), 50000),
    ("rar", "rar", b"Rar!\x1a\x07", 0, size_fixed(100 * MB), 1000),
]
BRAND_EXT = {b"qt  ": "mov", b"heic": "heic", b"heix": "heic", b"hevc": "heic", b"mif1": "heic",
             b"msf1": "heic", b"avif": "avif", b"3gp4": "3gp", b"3gp5": "3gp", b"3gp6": "3gp",
             b"3g2a": "3g2", b"M4A ": "m4a", b"M4V ": "m4v", b"M4B ": "m4b", b"crx ": "cr3"}
MAX_READ = {"mp4": 2 * 1024 * MB, "zip": 500 * MB, "pdf": 200 * MB,
            "sqlite": 2 * 1024 * MB, "7z": 2 * 1024 * MB}


def human(n):
    for u in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024:
            return f"{n:.1f} {u}"
        n /= 1024
    return f"{n:.1f} PB"


def source_size(f):
    f.seek(0, os.SEEK_END)
    n = f.tell()
    f.seek(0)
    return n


def carve(source, outdir, types=None, step=512, max_files=None, quiet=False,
          progress=None, stop=None, on_file=None, min_size=0, quick=False):
    """Carve files out of `source`. Returns dict(type -> count).

    quick=True  : only look at 4 KiB-aligned offsets (fast; matches most modern filesystems)
    quick=False : deep scan, every 512-byte sector
    min_size    : ignore recovered files smaller than this many bytes
    """
    if quick:
        step = max(step, 4096)
    outdir = Path(outdir)
    outdir.mkdir(parents=True, exist_ok=True)
    sigs = [s for s in SIGS if not types or s[0] in types]
    counts, seen, found_total = {}, set(), 0
    reader = open(source, "rb", buffering=0)
    try:
        total = source_size(reader)
    except OSError:
        total = 0
    t0 = time.time()
    pos = 0
    sector_hint = None
    while True:
        if stop is not None and stop.is_set():
            break
        reader.seek(pos)
        buf = reader.read(CHUNK + OVERLAP)
        if not buf:
            break
        for name, ext, hdr, off, sizer, minsz in sigs:
            i = buf.find(hdr)
            while i != -1:
                s = i - off
                abs_start = pos + s
                # only accept hits that begin in the non-overlap region (avoid dupes)
                if s >= 0 and (s < CHUNK or len(buf) < CHUNK + OVERLAP) and abs_start % step == 0:
                    got = _extract(reader, name, ext, abs_start, sizer, minsz,
                                   buf, s, outdir, seen, counts, min_size)
                    if got:
                        found_total += 1
                        if on_file:
                            on_file(name, abs_start, got)
                        if not quiet:
                            print(f"  + {name:6s} @ {abs_start:>14,d}  {human(got)}")
                        if max_files and found_total >= max_files:
                            return counts
                i = buf.find(hdr, i + 1)
        pos += CHUNK
        if progress and total:
            progress(min(100.0, pos * 100 / total), found_total)
        if not quiet and total:
            el = time.time() - t0
            pct = min(100, pos * 100 / total)
            rate = pos / el / MB if el else 0
            print(f"  scanned {pct:5.1f}%  {rate:6.1f} MB/s  files: {found_total}", end="\r")
        if len(buf) < CHUNK + OVERLAP:
            break
    reader.close()
    return counts


def _extract(reader, name, ext, abs_start, sizer, minsz, buf, s, outdir, seen, counts, min_size=0):
    # make sure we have enough bytes: use the window if file fits, else re-read
    window = buf
    ws = s
    ln = sizer(window, ws)
    if ln is None or ln < 0:
        limit = MAX_READ.get(name, 100 * MB)
        reader.seek(abs_start)
        window = reader.read(limit if ln is None or name != "mp4" else abs(ln) + 64 * MB)
        ws = 0
        ln = sizer(window, ws)
        if ln is not None and ln < 0:     # mp4 box beyond window; give up
            ln = None
    if ln is None or ln < max(minsz, min_size) or ln > len(window) - ws:
        return 0
    data = bytes(window[ws:ws + ln])
    if name == "mp4":                       # ISO-BMFF family: pick the real extension from the brand
        ext = BRAND_EXT.get(data[8:12], "mp4")
        name = ext if ext != "mp4" else name
    h = hashlib.sha1(data).hexdigest()
    if h in seen:
        return 0
    seen.add(h)
    counts[name] = counts.get(name, 0) + 1
    sub = outdir / name
    sub.mkdir(exist_ok=True)
    with open(sub / f"{name}_{counts[name]:05d}_{abs_start}.{ext}", "wb") as fh:
        fh.write(data)
    return ln


def main():
    print(__doc__)
    src = input("Source (image file, or \\\\.\\E: / \\\\.\\PhysicalDriveN as Admin): ").strip().strip('"')
    if not src:
        return
    if not os.path.exists(src) and not src.startswith("\\\\.\\"):
        print("Not found.")
        return
    out = input("Output folder [recovered_files]: ").strip() or "recovered_files"
    kinds = input("Types (comma list from jpg,png,gif,bmp,pdf,zip,mp4,sqlite,7z,wav,mp3,rar) [all]: ").strip()
    types = {k.strip() for k in kinds.split(",")} if kinds else None
    out = Path(out) / time.strftime("run_%Y%m%d_%H%M%S")
    print(f"Carving into {out} ...")
    counts = carve(src, out, types)
    print("\nDone:", counts or "nothing found", f"-> {out.resolve()}")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nStopped.")
        sys.exit(0)
