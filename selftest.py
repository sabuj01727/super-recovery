"""Builds a fake 'SD card' image with known files, carves it, checks results."""
import os, random, sqlite3, struct, tempfile, zipfile, zlib, io, shutil
from pathlib import Path
import carver

tmp = Path(tempfile.mkdtemp())
random.seed(1)

def png():
    def ch(t, d): return struct.pack(">I", len(d)) + t + d + struct.pack(">I", zlib.crc32(t + d))
    raw = b"".join(b"\x00" + bytes(random.randrange(256) for _ in range(30 * 3)) for _ in range(30))
    return b"\x89PNG\r\n\x1a\n" + ch(b"IHDR", struct.pack(">IIBBBBB", 30, 30, 8, 2, 0, 0, 0)) + ch(b"IDAT", zlib.compress(raw)) + ch(b"IEND", b"")

def jpg():  # SOI, APP0, SOS + entropy (with FF00 stuffing), EOI
    body = bytes(random.choice([1, 2, 3, 4]) for _ in range(4000))
    return b"\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00" + b"\xff\xda\x00\x08\x01\x01\x00\x00?\x00" + body + b"\xff\x00" + body + b"\xff\xd9"

def pdf(): return b"%PDF-1.4\n" + b"x" * 1500 + b"\n%%EOF\n"

def db():
    p = tmp / "t.db"; c = sqlite3.connect(p)
    c.execute("create table a(x)"); c.executemany("insert into a values(?)", [("v" * 50,)] * 200); c.commit(); c.close()
    return p.read_bytes()

def zp():
    b = io.BytesIO()
    with zipfile.ZipFile(b, "w") as z: z.writestr("a.txt", "hello" * 200)
    return b.getvalue()

def mp4():
    ftyp = struct.pack(">I4s", 24, b"ftyp") + b"isom\x00\x00\x02\x00isomiso2"
    moov = struct.pack(">I4s", 1008, b"moov") + b"m" * 1000
    mdat = struct.pack(">I4s", 6008, b"mdat") + b"d" * 6000
    return ftyp + moov + mdat

files = {"png": png(), "jpg": jpg(), "pdf": pdf(), "sqlite": db(), "zip": zp(), "mp4": mp4()}
img = bytearray(os.urandom(64 * 1024))
for name, data in files.items():
    img += bytes(random.getrandbits(8) for _ in range(random.randrange(1, 4) * 512))
    while len(img) % 512: img += b"\x00"
    img += data
    while len(img) % 512: img += b"\x00"
img += os.urandom(8192)
(tmp / "sd.img").write_bytes(img)

counts = carver.carve(str(tmp / "sd.img"), tmp / "out", quiet=True)
print("found:", counts)
ok = True
for name, data in files.items():
    got = [f.read_bytes() for f in (tmp / "out" / name).glob("*")] if (tmp / "out" / name).exists() else []
    match = data in got
    ok &= match
    print(f"  {name:7s} {'OK' if match else 'FAIL'}")
print("ALL PASS" if ok else "SOME FAILED")
shutil.rmtree(tmp)
