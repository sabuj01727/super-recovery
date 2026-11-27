"""Synthetic iPhone backup -> export + scan. Also tests HEIC/MOV carving. No real device."""
import hashlib, os, plistlib, sqlite3, struct, tempfile
from datetime import datetime, timezone
from pathlib import Path
import carver, ios_backup as ib

tmp = Path(tempfile.mkdtemp())
b = tmp / "backup" / "00008030-TEST"
b.mkdir(parents=True)


def put(domain, rel, data):
    fid = hashlib.sha1(f"{domain}-{rel}".encode()).hexdigest()
    (b / fid[:2]).mkdir(exist_ok=True)
    (b / fid[:2] / fid).write_bytes(data)
    return fid, domain, rel, 1


files = []
# sms.db with messages (some deleted afterwards -> freelist text)
sms = tmp / "sms.db"
c = sqlite3.connect(sms)
c.execute("create table handle(ROWID integer primary key, id text)")
c.execute("create table message(ROWID integer primary key, date integer, is_from_me int, handle_id int, text text, service text)")
c.execute("insert into handle values(1,'+8801700000000')")
t0 = int((datetime(2026, 5, 1, tzinfo=timezone.utc).timestamp() - ib.APPLE_EPOCH) * 1e9)
c.executemany("insert into message(date,is_from_me,handle_id,text,service) values(?,?,?,?,?)",
              [(t0 + i, i % 2, 1, f"keep message {i}", "iMessage") for i in range(3)] +
              [(t0, 0, 1, "SECRET deleted chat line %d " % i + "pad " * 20, "SMS") for i in range(400)])
c.commit(); c.execute("delete from message where text like 'SECRET%'"); c.commit(); c.close()
files.append(put("HomeDomain", "Library/SMS/sms.db", sms.read_bytes()))
ab = tmp / "ab.db"
c = sqlite3.connect(ab)
c.execute("create table ABPerson(ROWID integer primary key, First text, Last text, Organization text)")
c.execute("create table ABMultiValue(UID integer primary key, record_id int, property int, value text)")
c.execute("insert into ABPerson values(1,'Rahim','Uddin','')"); c.execute("insert into ABMultiValue values(1,1,3,'+8801811111111')")
c.commit(); c.close()
files.append(put("HomeDomain", "Library/AddressBook/AddressBook.sqlitedb", ab.read_bytes()))
files.append(put("CameraRollDomain", "Media/DCIM/100APPLE/IMG_0001.JPG", b"\xff\xd8\xff\xe0" + b"x" * 3000 + b"\xff\xd9"))

m = sqlite3.connect(b / "Manifest.db")
m.execute("create table Files(fileID text, domain text, relativePath text, flags integer, file blob)")
m.executemany("insert into Files(fileID,domain,relativePath,flags) values(?,?,?,?)", files)
m.execute("insert into Files(fileID,domain,relativePath,flags) values('dir1','HomeDomain','Library',2)")
m.commit(); m.close()
(b / "Manifest.plist").write_bytes(plistlib.dumps({"IsEncrypted": False, "Date": datetime(2026, 6, 1),
                                                    "Lockdown": {"ProductVersion": "15.1", "ProductType": "iPhone12,1"}}))
(b / "Info.plist").write_bytes(plistlib.dumps({"Device Name": "Test iPhone", "Product Type": "iPhone12,1", "Product Version": "15.1",
                                                "Installed Applications": ["com.apple.mobilesafari", "com.whatsapp.WhatsApp",
                                                                           "org.coolstar.sileo", "com.hidden.spymonitor"]}))

found = ib.find_backups([tmp / "backup"])
print("found backups:", [(x["name"], x["ios"], x["encrypted"]) for x in found])
assert found and found[0]["name"] == "Test iPhone"

assert ib.export_backup(b, tmp, owner_confirmed=False) is None          # consent gate
out = ib.export_backup(b, tmp, owner_confirmed=True, log=lambda m: None)
names = sorted(p.name for p in out.iterdir())
print("export files:", names)
msgs = (out / "messages.csv").read_text(encoding="utf-8-sig")
assert "keep message 1" in msgs and "2026-05-01" in msgs
assert "Rahim Uddin" in (out / "contacts.csv").read_text(encoding="utf-8-sig")
assert (out / "contacts.vcf").exists()
assert list((out / "files" / "CameraRollDomain").rglob("IMG_0001.JPG"))
deleted = (out / "deleted_strings.txt").read_text(encoding="utf-8")
print("deleted chat fragments recovered:", deleted.count("SECRET deleted chat line"))
assert deleted.count("SECRET deleted chat line") > 100

rep = ib.scan_backup(b, tmp, owner_confirmed=True, log=lambda m: None)
h = rep.read_text(encoding="utf-8")
print({k: (k in h) for k in ["sileo","spymonitor","Old iOS","iOS 15.1"]}, h.count("<svg"))
assert "sileo" in h and "spymonitor" in h and "Old iOS" in h and "iOS 15.1" in h and h.count("<svg") >= 3
print("scan report ok, svg:", h.count("<svg"))

# encrypted backup must be refused politely
plistlib.dump({"IsEncrypted": True}, open(b / "Manifest.plist", "wb"))
assert ib.export_backup(b, tmp, owner_confirmed=True, log=lambda m: None) is None
print("encrypted backup refused: OK")

# ---- carver: HEIC + MOV by brand ----
def box(t, payload): return struct.pack(">I4s", 8 + len(payload), t) + payload
heic = box(b"ftyp", b"heic\x00\x00\x00\x00mif1heic") + box(b"meta", b"m" * 600) + box(b"mdat", b"d" * 4000)
mov = box(b"ftyp", b"qt  \x00\x00\x00\x00qt  ") + box(b"moov", b"m" * 900) + box(b"mdat", b"d" * 5000)
img = bytearray(os.urandom(2048))
for blob in (heic, mov):
    img += blob
    img += b"\0" * (-len(img) % 512)
img += os.urandom(4096)
(tmp / "x.img").write_bytes(img)
counts = carver.carve(str(tmp / "x.img"), tmp / "cv", quiet=True)
print("carver:", counts)
assert counts.get("heic") == 1 and counts.get("mov") == 1, counts
assert carver.carve(str(tmp / "x.img"), tmp / "cv2", quiet=True, min_size=10_000) == {}
assert carver.carve(str(tmp / "x.img"), tmp / "cv3", quiet=True, quick=True) == {}   # offset 2048 is not 4K-aligned
al = bytearray(os.urandom(4096)) + heic
al += bytes(-len(al) % 512) + os.urandom(4096)
(tmp / "y.img").write_bytes(al)
assert carver.carve(str(tmp / "y.img"), tmp / "cv4", quiet=True, quick=True).get("heic") == 1
print("min_size filter + quick/deep modes: OK")
print("ALL PASS")
