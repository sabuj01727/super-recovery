import os, tempfile
from pathlib import Path
import super_recovery as sr

tmp = Path(tempfile.mkdtemp())
img = bytearray(os.urandom(4096))
img += b"%PDF-1.4\n" + b"Z" * 2000 + b"\n%%EOF\n"
img += bytes(-len(img) % 512) + os.urandom(4096)
(tmp / "a.img").write_bytes(img)
app = sr.App()
tabs = [app.nb.tab(i, "text").strip() for i in range(app.nb.index("end"))]
print("tabs:", tabs)
app.w_var.set(5); app._wiz_pick(); app._wiz_go()
print("wizard (iPhone erased) -> tab:", tabs[app.nb.index("current")])
app.nb.select(1)
app.src.set(str(tmp / "a.img")); app.out.set(str(tmp / "out")); app.mode.set("deep"); app._carve()
app.after(3000, app.quit); app.mainloop()
print("pdf carved:", "+ pdf" in app.c_log.get("1.0", "end"), "| button:", app.b_go["state"])
app.destroy()
