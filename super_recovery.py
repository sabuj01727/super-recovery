#!/usr/bin/env python3
"""
SUPER RECOVERY - one window, Android + iPhone + disks (tkinter, no extra packages).
Windows and Linux.   Run:  python super_recovery.py

Tabs: Wizard | File Recovery | Find Backups | Android | iPhone | Forensics | Hack Scan
Everything is READ-ONLY toward your source drive / phone.
Raw drives need an Administrator terminal (Windows) or sudo (Linux).
"""
import io
import queue
import threading
import time
import tkinter as tk
import webbrowser
from contextlib import redirect_stdout
from pathlib import Path
from tkinter import filedialog, messagebox, ttk

import backup_finder
import carver
import ios_backup
import phone_backup
import security_scan

TYPES = ["jpg", "png", "gif", "bmp", "webp", "heic", "pdf", "zip", "mp4", "mov", "3gp", "avi",
         "sqlite", "7z", "wav", "mp3", "m4a", "ogg", "flac", "rar"]
# carver "name" values: ISO-BMFF family (mp4/mov/3gp/heic/m4a) is one signature called "mp4"
SIG_ALIAS = {"heic": "mp4", "mov": "mp4", "3gp": "mp4", "m4a": "mp4"}

WIZARD = [
    ("Files deleted or formatted from an SD card / USB drive", "Good",
     "Deep file recovery can often find deleted photos, videos and documents. Do not save new files to "
     "that card, and save recovered files to a DIFFERENT drive.", 1),
    ("Files deleted from my PC / laptop disk", "Good",
     "Stop writing to that drive. Use the File Recovery tab and pick the drive (run as Administrator / sudo).", 1),
    ("Photos/files deleted on my Android phone (no factory reset)", "Partial",
     "First check the Gallery Trash, Google Photos and Samsung Cloud. Then the Find Backups tab.", 2),
    ("Android phone was factory reset", "Almost none",
     "Modern phones are encrypted and a reset destroys the key - no software can bring that data back. "
     "Your only hope is a cloud backup (Google / Samsung / WhatsApp) or copies on an SD card or PC. "
     "Use Find Backups.", 2),
    ("iPhone: I need data from a backup (iTunes / Finder / Apple Devices)", "Good",
     "The iPhone tab finds backups on this computer and exports photos, messages, contacts, calls, "
     "WhatsApp and recovers deleted message text from them.", 4),
    ("iPhone was erased / reset", "Almost none",
     "'Erase All Content and Settings' destroys the encryption keys. Only an iCloud backup "
     "(Settings > Apple ID > iCloud > Backup) or a computer backup can restore it. Check the iPhone tab for local backups.", 4),
    ("Back up my phone now, before something goes wrong", "Best",
     "Android tab: one-click backup over USB. iPhone tab: live backup (libimobiledevice) or make an "
     "iTunes/Finder backup and export it.", 3),
    ("I suspect my phone is hacked / has stalkerware (Android or iPhone)", "Can check",
     "The Hack Scan tab inspects the phone (Android) or an iPhone backup and draws a risk report with "
     "charts. Finding nothing does not prove it is safe.", 6),
    ("Forensic analysis of data I already copied (my own / with permission)", "Depends",
     "The Forensics tab hashes every file (SHA-256), builds a timeline and recovers deleted text from "
     "SQLite databases, then writes a report.", 5),
]


class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Super Recovery")
        self.geometry("940x700")
        self.stop_ev = threading.Event()
        self.q = queue.Queue()
        self.after(100, self._pump)
        self.report_path = None
        self.ios_list = []
        self.nb = ttk.Notebook(self)
        self.nb.pack(fill="both", expand=True, padx=8, pady=8)
        for fn in (self._wizard_tab, self._carver_tab, self._find_tab, self._android_tab,
                   self._iphone_tab, self._forensic_tab, self._scan_tab):
            fn()

    # ---------- thread-safe helpers ----------
    def post(self, fn):
        self.q.put(fn)

    def _pump(self):
        try:
            while True:
                self.q.get_nowait()()
        except queue.Empty:
            pass
        self.after(100, self._pump)

    def mklog(self, parent):
        t = tk.Text(parent, height=14, wrap="word", state="disabled", font=("Consolas", 9))
        sb = ttk.Scrollbar(parent, command=t.yview)
        t.configure(yscrollcommand=sb.set)
        sb.pack(side="right", fill="y")
        t.pack(fill="both", expand=True, padx=8, pady=6)
        return t

    def log(self, w, msg):
        def d():
            w.configure(state="normal")
            w.insert("end", str(msg) + "\n")
            w.see("end")
            w.configure(state="disabled")
        self.post(d)

    def bg(self, w, fn, *a):
        def work():
            class W(io.TextIOBase):
                def write(s, t):
                    if t.strip():
                        self.log(w, t.rstrip("\n"))
                    return len(t)
            try:
                with redirect_stdout(W()):
                    fn(*a)
            except Exception as e:  # noqa: BLE001
                self.log(w, f"ERROR: {e}")
        threading.Thread(target=work, daemon=True).start()

    def consent(self, var):
        if not var.get():
            messagebox.showwarning("Permission", "Tick the box confirming the device/data is yours "
                                                 "or you have the owner's written permission.")
            return False
        return True

    def open_report(self, path):
        if path and Path(path).exists():
            webbrowser.open(Path(path).resolve().as_uri())

    # ---------- 1 wizard ----------
    def _wizard_tab(self):
        f = ttk.Frame(self.nb)
        self.nb.add(f, text=" 1. Wizard ")
        ttk.Label(f, text="What happened? Pick one:", font=("Segoe UI", 12, "bold")).pack(anchor="w", padx=10, pady=8)
        self.w_var = tk.IntVar(value=-1)
        for i, item in enumerate(WIZARD):
            ttk.Radiobutton(f, text=item[0], variable=self.w_var, value=i,
                            command=self._wiz_pick).pack(anchor="w", padx=18, pady=2)
        self.w_out = tk.Label(f, wraplength=860, justify="left", anchor="w", bg="#f4f4f4", padx=10, pady=10)
        self.w_out.pack(fill="x", padx=10, pady=12)
        self.w_btn = ttk.Button(f, text="Go to the right tab", command=self._wiz_go, state="disabled")
        self.w_btn.pack(anchor="w", padx=10)

    def _wiz_pick(self):
        _t, chance, expl, _tab = WIZARD[self.w_var.get()]
        self.w_out.config(text=f"Chance of getting data back: {chance}\n\n{expl}")
        self.w_btn.config(state="normal")

    def _wiz_go(self):
        self.nb.select(WIZARD[self.w_var.get()][3])

    # ---------- 2 file recovery ----------
    def _carver_tab(self):
        f = ttk.Frame(self.nb)
        self.nb.add(f, text=" 2. File Recovery ")
        r = ttk.Frame(f)
        r.pack(fill="x", padx=8, pady=6)
        ttk.Label(r, text="Source:").pack(side="left")
        self.src = tk.StringVar()
        ttk.Entry(r, textvariable=self.src, width=46).pack(side="left", padx=4)
        ttk.Button(r, text="Image file...", command=lambda: self.src.set(
            filedialog.askopenfilename() or self.src.get())).pack(side="left")
        self._drv = dict(backup_finder.raw_sources())
        cb = ttk.Combobox(r, width=22, state="readonly", values=list(self._drv))
        cb.pack(side="left", padx=4)
        cb.bind("<<ComboboxSelected>>", lambda e: self.src.set(self._drv[cb.get()]))
        r2 = ttk.Frame(f)
        r2.pack(fill="x", padx=8)
        ttk.Label(r2, text="Save to:").pack(side="left")
        self.out = tk.StringVar(value=str(Path.cwd() / "recovered_files"))
        ttk.Entry(r2, textvariable=self.out, width=46).pack(side="left", padx=4)
        ttk.Button(r2, text="Browse...", command=lambda: self.out.set(
            filedialog.askdirectory() or self.out.get())).pack(side="left")
        ttk.Label(f, text="Save to a DIFFERENT drive than the source.", foreground="#a60").pack(anchor="w", padx=8)

        o = ttk.LabelFrame(f, text="Scan options")
        o.pack(fill="x", padx=8, pady=4)
        self.mode = tk.StringVar(value="deep")
        ttk.Radiobutton(o, text="Deep scan (every 512-byte sector, slower, most complete)",
                        variable=self.mode, value="deep").grid(row=0, column=0, sticky="w", padx=6)
        ttk.Radiobutton(o, text="Quick scan (4 KB-aligned only, much faster)",
                        variable=self.mode, value="quick").grid(row=0, column=1, sticky="w", padx=6)
        ttk.Label(o, text="Ignore files smaller than (KB):").grid(row=1, column=0, sticky="w", padx=6)
        self.minkb = tk.StringVar(value="0")
        ttk.Entry(o, textvariable=self.minkb, width=8).grid(row=1, column=1, sticky="w", padx=6)

        tf = ttk.LabelFrame(f, text="File types")
        tf.pack(fill="x", padx=8, pady=4)
        self.tv = {}
        for i, t in enumerate(TYPES):
            v = tk.BooleanVar(value=True)
            self.tv[t] = v
            ttk.Checkbutton(tf, text=t, variable=v).grid(row=i // 10, column=i % 10, sticky="w", padx=6)
        bf = ttk.Frame(f)
        bf.pack(fill="x", padx=8, pady=4)
        self.b_go = ttk.Button(bf, text="Start scan", command=self._carve)
        self.b_go.pack(side="left")
        self.b_stop = ttk.Button(bf, text="Stop", command=self.stop_ev.set, state="disabled")
        self.b_stop.pack(side="left", padx=6)
        ttk.Button(bf, text="Open output folder", command=lambda: backup_finder.open_path(self.out.get())
                   if Path(self.out.get()).exists() else None).pack(side="left")
        self.pb = ttk.Progressbar(f, maximum=100)
        self.pb.pack(fill="x", padx=8, pady=4)
        self.st = ttk.Label(f, text="Idle")
        self.st.pack(anchor="w", padx=8)
        self.c_log = self.mklog(f)

    def _carve(self):
        src = self.src.get().strip().strip('"')
        types = {SIG_ALIAS.get(t, t) for t, v in self.tv.items() if v.get()}
        if not src or not types:
            messagebox.showwarning("Missing info", "Choose a source and at least one file type.")
            return
        try:
            min_size = int(float(self.minkb.get() or 0) * 1024)
        except ValueError:
            min_size = 0
        out = Path(self.out.get()) / time.strftime("run_%Y%m%d_%H%M%S")
        self.stop_ev.clear()
        self.b_go.config(state="disabled")
        self.b_stop.config(state="normal")
        self.log(self.c_log, f"Scanning {src} -> {out}  ({self.mode.get()} mode)")
        t0 = time.time()

        def prog(p, n):
            el = time.time() - t0
            eta = f"  ETA {int(el * (100 - p) / p)}s" if p > 1 else ""
            self.post(lambda: (self.pb.config(value=p),
                               self.st.config(text=f"{p:.1f}%  files found: {n}{eta}")))

        def work():
            try:
                c = carver.carve(src, out, types, quiet=True, stop=self.stop_ev, progress=prog,
                                 min_size=min_size, quick=self.mode.get() == "quick",
                                 on_file=lambda n, o, s: self.log(self.c_log, f"+ {n:6s} @ {o:,d}  {carver.human(s)}"))
                self.log(self.c_log, f"\nFinished: {c or 'nothing found'}")
            except PermissionError:
                self.log(self.c_log, "Permission denied - run as Administrator (Windows) or with sudo (Linux) for raw drives.")
            except Exception as e:  # noqa: BLE001
                self.log(self.c_log, f"ERROR: {e}")
            finally:
                self.post(lambda: (self.b_go.config(state="normal"), self.b_stop.config(state="disabled")))
        threading.Thread(target=work, daemon=True).start()

    # ---------- 3 find backups ----------
    def _find_tab(self):
        f = ttk.Frame(self.nb)
        self.nb.add(f, text=" 3. Find Backups ")
        bf = ttk.Frame(f)
        bf.pack(fill="x", padx=8, pady=8)
        ttk.Button(bf, text="Scan this computer", command=lambda: self.bg(
            self.f_log, lambda: (backup_finder.scan_known(), backup_finder.scan_drives(90)))).pack(side="left")
        ttk.Button(bf, text="Cloud backup checklist", command=lambda: self.bg(
            self.f_log, backup_finder.cloud_checklist)).pack(side="left", padx=6)
        self.f_log = self.mklog(f)

    # ---------- 4 android ----------
    def _android_tab(self):
        f = ttk.Frame(self.nb)
        self.nb.add(f, text=" 4. Android ")
        ttk.Label(f, justify="left", text=(
            "Unlock the phone > Settings > Developer options > USB debugging ON > connect USB > tap Allow.\n"
            "adb (platform-tools) must be in PATH or in a platform-tools folder next to these scripts.")
        ).pack(anchor="w", padx=8, pady=6)
        self.own = tk.BooleanVar()
        ttk.Checkbutton(f, variable=self.own, text="This phone is mine, or I have the owner's written permission"
                        ).pack(anchor="w", padx=8)
        self.fx = tk.BooleanVar(value=True)
        ttk.Checkbutton(f, variable=self.fx, text="Also run forensic analysis (hashes + deleted text)"
                        ).pack(anchor="w", padx=8)
        bf = ttk.Frame(f)
        bf.pack(fill="x", padx=8, pady=6)
        ttk.Button(bf, text="Check phone", command=self._adb_check).pack(side="left")
        ttk.Button(bf, text="One-click backup", command=self._android_backup).pack(side="left", padx=6)
        self.p_log = self.mklog(f)

    def _adb_check(self):
        def fn():
            exe = backup_finder.find_adb()
            print(backup_finder.adb(exe, "devices").stdout if exe else "adb not found.")
        self.bg(self.p_log, fn)

    def _android_backup(self):
        if not self.consent(self.own):
            return
        d = filedialog.askdirectory(title="Where to save the backup?")
        if d:
            self.bg(self.p_log, lambda: phone_backup.run_backup(
                d, print, forensic=self.fx.get(), owner_confirmed=True))

    # ---------- 5 iphone ----------
    def _iphone_tab(self):
        f = ttk.Frame(self.nb)
        self.nb.add(f, text=" 5. iPhone ")
        ttk.Label(f, justify="left", wraplength=880, text=(
            "iPhone / iPad: works on iTunes / Finder / Apple Devices backups already on this computer, or "
            "makes a fresh one with libimobiledevice (unlock, connect, tap Trust). Encrypted backups need "
            "their password to be removed first - this tool never cracks passwords. An iPhone that was erased "
            "cannot be recovered except from an iCloud/computer backup.")).pack(anchor="w", padx=8, pady=6)
        self.own_i = tk.BooleanVar()
        ttk.Checkbutton(f, variable=self.own_i, text="This device is mine, or I have the owner's written permission"
                        ).pack(anchor="w", padx=8)
        bf = ttk.Frame(f)
        bf.pack(fill="x", padx=8, pady=6)
        ttk.Button(bf, text="Find backups", command=self._ios_find).pack(side="left")
        ttk.Button(bf, text="Choose backup folder...", command=self._ios_pick).pack(side="left", padx=6)
        ttk.Button(bf, text="Make live backup (USB)", command=self._ios_live).pack(side="left")
        ttk.Button(bf, text="Export data", command=self._ios_export).pack(side="left", padx=6)
        ttk.Button(bf, text="Security scan", command=self._ios_scan).pack(side="left")
        self.ios_cb = ttk.Combobox(f, state="readonly", width=110)
        self.ios_cb.pack(anchor="w", padx=8, pady=2)
        self.i_log = self.mklog(f)

    def _ios_set(self, items):
        self.ios_list = items
        self.ios_cb["values"] = [f"{b['name']} | {b['model']} | iOS {b['ios']} | {b['date']} | "
                                 f"{'ENCRYPTED' if b['encrypted'] else 'ok'} | {b['path']}" for b in items]
        if items:
            self.ios_cb.current(0)

    def _ios_find(self):
        items = ios_backup.find_backups()
        self._ios_set(items)
        self.log(self.i_log, f"Found {len(items)} backup(s)." if items else
                 "No backups in the standard locations. Make one with iTunes/Finder/Apple Devices, "
                 "use 'Make live backup', or 'Choose backup folder'.")

    def _ios_pick(self):
        d = filedialog.askdirectory(title="Backup folder (contains Manifest.plist)")
        if d:
            if (Path(d) / "Manifest.plist").exists():
                self._ios_set([ios_backup.describe_backup(d)])
            else:
                items = ios_backup.find_backups([d])
                self._ios_set(items)
                if not items:
                    self.log(self.i_log, "No Manifest.plist found there.")

    def _ios_selected(self):
        i = self.ios_cb.current()
        if i < 0 or i >= len(self.ios_list):
            messagebox.showinfo("iPhone", "Find or choose a backup first.")
            return None
        return self.ios_list[i]["path"]

    def _ios_live(self):
        if not self.consent(self.own_i):
            return
        d = filedialog.askdirectory(title="Where to save the iPhone backup?")
        if not d:
            return

        def fn():
            p = ios_backup.live_backup(d, print, owner_confirmed=True)
            if p:
                self.post(lambda: self._ios_set([ios_backup.describe_backup(p)]))
        self.bg(self.i_log, fn)

    def _ios_export(self):
        b = self._ios_selected()
        if b and self.consent(self.own_i):
            d = filedialog.askdirectory(title="Where to save the exported data?")
            if d:
                self.bg(self.i_log, lambda: ios_backup.export_backup(b, d, print, owner_confirmed=True))

    def _ios_scan(self):
        b = self._ios_selected()
        if b and self.consent(self.own_i):
            d = filedialog.askdirectory(title="Where to save the scan report?")
            if d:
                def fn():
                    self.report_path = ios_backup.scan_backup(b, d, print, owner_confirmed=True)
                    if self.report_path:
                        self.post(lambda: self.open_report(self.report_path))
                self.bg(self.i_log, fn)

    # ---------- 6 forensics ----------
    def _forensic_tab(self):
        f = ttk.Frame(self.nb)
        self.nb.add(f, text=" 6. Forensics ")
        ttk.Label(f, justify="left", text=(
            "Analyse any copied folder (backup, WhatsApp databases, ...):\n"
            "  - SHA-256 hash of every file (manifest.csv) and timeline.csv\n"
            "  - text recovered from deleted space in SQLite databases (deleted_strings.txt)\n"
            "  - report.html and custody.log\n"
            "Only use on your own data or with written permission.")).pack(anchor="w", padx=8, pady=6)
        self.own2 = tk.BooleanVar()
        ttk.Checkbutton(f, variable=self.own2, text="This data is mine, or I have written permission"
                        ).pack(anchor="w", padx=8)
        ttk.Button(f, text="Choose folder and analyse", command=self._analyze).pack(anchor="w", padx=8, pady=6)
        self.z_log = self.mklog(f)

    def _analyze(self):
        if not self.consent(self.own2):
            return
        d = filedialog.askdirectory(title="Folder to analyse")
        if d:
            self.bg(self.z_log, phone_backup.analyze_folder, d, print)

    # ---------- 7 hack scan ----------
    def _scan_tab(self):
        f = ttk.Frame(self.nb)
        self.nb.add(f, text=" 7. Hack Scan ")
        ttk.Label(f, justify="left", wraplength=880, text=(
            "Android: unlock + USB debugging + Allow; the scan changes nothing. iPhone: use the iPhone tab > "
            "Security scan on a backup.\nResult: risk gauge, suspicious-app chart, permission map, install "
            "timeline and what to do (HTML report).")).pack(anchor="w", padx=8, pady=6)
        self.own3 = tk.BooleanVar()
        ttk.Checkbutton(f, variable=self.own3, text="This phone is mine, or I have the owner's written permission"
                        ).pack(anchor="w", padx=8)
        bf = ttk.Frame(f)
        bf.pack(fill="x", padx=8, pady=6)
        ttk.Button(bf, text="Scan connected Android phone", command=self._hack_scan).pack(side="left")
        ttk.Button(bf, text="Open last report", command=lambda: self.open_report(self.report_path)).pack(side="left", padx=6)
        self.h_log = self.mklog(f)

    def _hack_scan(self):
        if not self.consent(self.own3):
            return
        d = filedialog.askdirectory(title="Where to save the report?")
        if not d:
            return

        def fn():
            self.report_path = security_scan.run_scan(d, print, owner_confirmed=True)
            if self.report_path:
                self.post(lambda: self.open_report(self.report_path))
        self.bg(self.h_log, fn)


if __name__ == "__main__":
    App().mainloop()
