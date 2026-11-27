#!/usr/bin/env python3
"""
Phone hack / spyware scan (Windows + Linux)

Checks a connected, unlocked Android phone over ADB (USB debugging on) and builds an
HTML report with charts (security_report.html). Read-only: changes nothing on the phone.
The same report engine is reused by ios_backup.py for iPhone backups.

What it checks:
  - Apps with Accessibility service / Device admin / Notification access
  - Sideloaded apps (not from the official store)
  - Hidden third-party apps (no launcher icon)
  - Sensitive permissions (SMS, mic, camera, location, call log ...)
  - Spy/stalkerware-like app names (name match only - verify by hand)
  - Root, unlocked bootloader, old security patch, proxy settings

Limits: not a full malware detector. "Nothing found" does not mean safe.
If you have serious concerns, get expert help.
"""
import html
import json
import math
import re
import time
from datetime import date, datetime
from pathlib import Path

import backup_finder

SENSITIVE = {
    "android.permission.READ_SMS": "Read SMS",
    "android.permission.RECEIVE_SMS": "Receive SMS",
    "android.permission.SEND_SMS": "Send SMS",
    "android.permission.RECORD_AUDIO": "Microphone",
    "android.permission.CAMERA": "Camera",
    "android.permission.ACCESS_FINE_LOCATION": "Location",
    "android.permission.READ_CALL_LOG": "Call log",
    "android.permission.READ_CONTACTS": "Contacts",
    "android.permission.SYSTEM_ALERT_WINDOW": "Overlay",
    "android.permission.REQUEST_INSTALL_PACKAGES": "Install apps",
    "android.permission.PACKAGE_USAGE_STATS": "Usage stats",
}
SPY_WORDS = ("spy", "stalk", "keylog", "flexispy", "mspy", "hoverwatch", "cocospy", "spyic",
             "spyera", "truthspy", "highster", "xnspy", "spyzie", "eyezy", "webwatcher",
             "catwatchful", "phonetracker", "hidden", "monitor", "parental", "snoop")
TRUSTED_PREFIX = ("com.google.", "com.android.", "com.samsung.", "com.sec.", "android.",
                  "com.qualcomm.", "com.microsoft.", "com.whatsapp", "org.mozilla.", "com.apple.")
PLAY_INSTALLERS = {"com.android.vending", "com.sec.android.app.samsungapps",
                   "com.google.android.packageinstaller_play", "appstore"}


# ---------------- collection (Android over ADB) ----------------
def collect(log=print):
    exe = backup_finder.find_adb()
    if not exe:
        raise RuntimeError("adb not found (install Android platform-tools)")
    out = backup_finder.adb(exe, "devices").stdout
    if not [l for l in out.splitlines()[1:] if l.strip().endswith("device")]:
        raise RuntimeError("No authorized phone found - enable USB debugging and tap Allow on the phone")

    def sh(cmd, t=300):
        return backup_finder.adb(exe, "shell", cmd, timeout=t).stdout

    log("Collecting app data (may take a few minutes)...")
    d = {"packages_txt": sh("dumpsys package packages"), "settings": {}, "props": {}}
    for k in ("enabled_accessibility_services", "enabled_notification_listeners",
              "enabled_input_methods", "install_non_market_apps"):
        d["settings"][k] = sh(f"settings get secure {k}").strip()
    for k in ("adb_enabled", "development_settings_enabled", "http_proxy", "private_dns_mode",
              "private_dns_specifier"):
        d["settings"][k] = sh(f"settings get global {k}").strip()
    for k in ("ro.product.model", "ro.product.manufacturer", "ro.build.version.release",
              "ro.build.version.security_patch", "ro.boot.verifiedbootstate", "ro.debuggable",
              "ro.crypto.state"):
        d["props"][k] = sh(f"getprop {k}").strip()
    d["device_policy_txt"] = sh("dumpsys device_policy")
    d["launchers"] = set(re.findall(r"([A-Za-z0-9_.]+)/", sh(
        "cmd package query-activities --brief -a android.intent.action.MAIN "
        "-c android.intent.category.LAUNCHER")))
    d["overlay"] = set(re.findall(r"package:?\s*([\w.]+)", sh(
        "cmd appops query-op SYSTEM_ALERT_WINDOW allow")))
    d["root"] = bool(sh("ls /system/xbin/su /system/bin/su /sbin/su /su/bin/su 2>/dev/null").strip())
    return d


# ---------------- parsing / analysis ----------------
def parse_packages(txt):
    apps = {}
    for b in re.split(r"\n  Package \[", "\n" + txt)[1:]:
        name = b.split("]")[0]
        if name in apps:
            continue
        m = re.search(r"installerPackageName=(\S+)", b)
        installer = m.group(1) if m and m.group(1) != "null" else None
        fl = re.search(r"\n\s+flags=\[(.*?)\]", b)
        system = bool(fl and "SYSTEM" in fl.group(1))
        first = re.search(r"firstInstallTime=([\d\-]+)", b)
        perms = set(re.findall(r"([\w.]+\.permission\.[A-Z_]+): granted=true", b))
        apps[name] = {"name": name, "installer": installer, "system": system,
                      "installed": first.group(1) if first else "", "perms": perms}
    return apps


def _split_services(s):
    if not s or s in ("null", "None"):
        return []
    return [x.strip() for x in s.split(":") if x.strip()]


def analyze(d):
    """data dict -> (findings, apps, score)."""
    apps = parse_packages(d["packages_txt"])
    third = {k: v for k, v in apps.items() if not v["system"]}
    F = []

    def add(sev, pts, title, detail, advice):
        F.append({"sev": sev, "pts": pts, "title": title, "detail": detail, "advice": advice})

    def untrusted(pkg):
        return not pkg.startswith(TRUSTED_PREFIX)

    for s in [s for s in _split_services(d["settings"].get("enabled_accessibility_services"))
              if untrusted(s.split("/")[0])]:
        add("high", 25, "Accessibility service enabled: " + s.split("/")[0],
            "Lets an app read the screen, see keystrokes and tap for you. The most common stalkerware route.",
            "If you do not recognise it, turn it off in Settings > Accessibility and uninstall the app.")
    for p in re.findall(r"admin=ComponentInfo\{([^/}]+)", d.get("device_policy_txt", "")):
        if untrusted(p):
            add("high", 25, "Device admin app: " + p,
                "A device admin can block uninstalling and lock or wipe the phone.",
                "Turn it off in Settings > Security > Device admin apps, then uninstall.")
    for s in _split_services(d["settings"].get("enabled_notification_listeners")):
        p = s.split("/")[0]
        if untrusted(p):
            add("medium", 12, "Notification access: " + p,
                "Can read all your notifications (including OTP codes).",
                "Check Settings > Notifications > Device & app notifications; turn off if unknown.")

    sideload = [a for a in third.values() if a["installer"] not in PLAY_INSTALLERS]
    if sideload:
        add("low" if len(sideload) < 4 else "medium", min(15, 3 * len(sideload)),
            f"Apps installed outside the official store: {len(sideload)}",
            ", ".join(a["name"] for a in sideload[:12]) + (" ..." if len(sideload) > 12 else ""),
            "Uninstall any you did not install yourself.")

    hidden = [a for a in third.values() if a["name"] not in d["launchers"] and untrusted(a["name"])
              and len(a["perms"] & set(SENSITIVE)) >= 2] if d["launchers"] else []
    for a in hidden:
        add("high", 20, "Hidden app (no icon): " + a["name"],
            "No launcher icon, yet has sensitive permissions: " + ", ".join(
                SENSITIVE[p] for p in a["perms"] if p in SENSITIVE),
            "Find it in Settings > Apps > all apps; uninstall if unknown.")

    for a in third.values():
        if any(w in a["name"].lower() for w in SPY_WORDS) and untrusted(a["name"]):
            add("high", 20, "Suspicious name: " + a["name"],
                "Name contains spy/monitor/tracker-like words (name match only - may be a false alarm).",
                "Fine if you know the app; otherwise uninstall it.")
    for a in third.values():
        n = len(a["perms"] & set(SENSITIVE))
        if n >= 5 and a["installer"] not in PLAY_INSTALLERS and untrusted(a["name"]):
            add("high", 15, "Sideloaded app with many permissions: " + a["name"],
                f"{n} sensitive permissions: " + ", ".join(SENSITIVE[p] for p in a["perms"] if p in SENSITIVE),
                "Uninstall if you do not need it.")

    ov = [p for p in d.get("overlay", ()) if p in third and untrusted(p)]
    if ov:
        add("low", 5, f"Draw-over-other-apps permission: {len(ov)} apps", ", ".join(ov[:10]),
            "Overlays can show fake login screens; turn off if unnecessary.")

    pr = d["props"]
    if d.get("root"):
        add("high", 25, "Phone is rooted", "An su binary was found - any app can take full control.",
            "If you did not root it, treat the phone as compromised; back up and flash official firmware.")
    if pr.get("ro.boot.verifiedbootstate") in ("orange", "yellow"):
        add("medium", 12, "Bootloader unlocked", "The system may have been modified.",
            "Be careful if you did not unlock it.")
    sp = pr.get("ro.build.version.security_patch", "")
    try:
        age = (date.today() - datetime.strptime(sp, "%Y-%m-%d").date()).days
        if age > 365:
            add("medium", 10, f"Security patch is {age // 30} months old ({sp})",
                "Old patches leave known vulnerabilities open.", "Update in Settings > Software update.")
    except ValueError:
        pass
    if d["settings"].get("http_proxy") not in ("", "null", ":0", None):
        add("medium", 15, "Proxy configured: " + d["settings"]["http_proxy"],
            "Your traffic may be routed through another server.",
            "If you did not set it, remove it in Wi-Fi/APN settings.")
    if d["settings"].get("install_non_market_apps") == "1":
        add("low", 5, "Install from unknown sources is on", "", "Turn it off if not needed.")
    if d["settings"].get("adb_enabled") == "1":
        add("info", 0, "USB debugging is on", "Needed for this scan.",
            "Turn it off in Developer options afterwards.")

    return F, apps, min(100, sum(f["pts"] for f in F))


def app_rows(apps, d):
    rows = []
    for a in apps.values():
        if a["system"]:
            continue
        sens = a["perms"] & set(SENSITIVE)
        s = len(sens) * 4
        if a["installer"] not in PLAY_INSTALLERS:
            s += 8
        if d.get("launchers") and a["name"] not in d["launchers"]:
            s += 10
        if any(w in a["name"].lower() for w in SPY_WORDS):
            s += 15
        rows.append({**a, "score": s, "sens": sens})
    return sorted(rows, key=lambda r: -r["score"])


# ---------------- drawing (inline SVG) ----------------
COL = {"high": "#d93025", "medium": "#f29900", "low": "#e8c200", "info": "#5f6368", "ok": "#188038"}
FONT = "font-family:'Segoe UI','Helvetica Neue',Arial,sans-serif"


def svg_gauge(score):
    lvl, c = ("Low risk", COL["ok"]) if score < 20 else (
        ("Medium risk", COL["medium"]) if score < 50 else ("High risk", COL["high"]))
    r, cx, cy = 90, 120, 115
    ang = math.pi * (1 - score / 100)
    x, y = cx + r * math.cos(ang), cy - r * math.sin(ang)
    big = 1 if score > 50 else 0
    return (f'<svg viewBox="0 0 240 150" width="260" style="{FONT}">'
            f'<path d="M30 115 A90 90 0 0 1 210 115" fill="none" stroke="#e0e0e0" stroke-width="18"/>'
            f'<path d="M30 115 A90 90 0 {big} 1 {x:.1f} {y:.1f}" fill="none" stroke="{c}" stroke-width="18"/>'
            f'<text x="120" y="108" text-anchor="middle" font-size="34" font-weight="bold" fill="{c}">{score}</text>'
            f'<text x="120" y="135" text-anchor="middle" font-size="14" fill="#333">{lvl}</text></svg>')


def svg_bars(rows, n=10):
    rows = rows[:n]
    if not rows or rows[0]["score"] == 0:
        return "<p>No suspicious app scores.</p>"
    mx = max(r["score"] for r in rows)
    h = 26 * len(rows) + 10
    out = [f'<svg viewBox="0 0 640 {h}" width="100%" style="{FONT}">']
    for i, r in enumerate(rows):
        y = 8 + i * 26
        w = 330 * r["score"] / mx
        c = COL["high"] if r["score"] >= 30 else COL["medium"] if r["score"] >= 15 else COL["low"]
        out.append(f'<text x="0" y="{y + 14}" font-size="11" fill="#222">{html.escape(r["name"][:34])}</text>'
                   f'<rect x="250" y="{y}" width="{w:.0f}" height="18" rx="3" fill="{c}"/>'
                   f'<text x="{256 + w:.0f}" y="{y + 13}" font-size="11" fill="#222">{r["score"]}</text>')
    out.append("</svg>")
    return "".join(out)


def svg_heatmap(rows, n=12):
    rows = [r for r in rows[:n]]
    perms = list(SENSITIVE)
    if not rows or not any(r["perms"] & set(perms) for r in rows):
        return "<p>No permission data.</p>"
    cw, rh, lx, top = 46, 22, 230, 70
    w, h = lx + cw * len(perms) + 10, top + rh * len(rows) + 10
    o = [f'<svg viewBox="0 0 {w} {h}" width="100%" style="{FONT}">']
    for j, p in enumerate(perms):
        o.append(f'<text transform="translate({lx + j * cw + cw / 2:.0f},{top - 6}) rotate(-45)" '
                 f'font-size="10" fill="#222">{html.escape(SENSITIVE[p])}</text>')
    for i, r in enumerate(rows):
        y = top + i * rh
        o.append(f'<text x="0" y="{y + 15}" font-size="11" fill="#222">{html.escape(r["name"][:36])}</text>')
        for j, p in enumerate(perms):
            on = p in r["perms"]
            o.append(f'<rect x="{lx + j * cw}" y="{y}" width="{cw - 3}" height="{rh - 3}" rx="3" '
                     f'fill="{COL["high"] if on else "#eceff1"}" opacity="{0.9 if on else 1}"/>')
    o.append("</svg>")
    return "".join(o)


def svg_donut(apps):
    third = [a for a in apps.values() if not a["system"]]
    play = sum(1 for a in third if a["installer"] in PLAY_INSTALLERS)
    other = len(third) - play
    tot = max(1, play + other)
    r, cx, cy = 60, 80, 80
    circ = 2 * math.pi * r
    pl = circ * play / tot
    return (f'<svg viewBox="0 0 320 160" width="320" style="{FONT}">'
            f'<circle cx="{cx}" cy="{cy}" r="{r}" fill="none" stroke="{COL["high"]}" stroke-width="22"/>'
            f'<circle cx="{cx}" cy="{cy}" r="{r}" fill="none" stroke="{COL["ok"]}" stroke-width="22" '
            f'stroke-dasharray="{pl:.1f} {circ:.1f}" transform="rotate(-90 {cx} {cy})"/>'
            f'<text x="{cx}" y="{cy + 5}" text-anchor="middle" font-size="16" font-weight="bold">{len(third)}</text>'
            f'<rect x="170" y="50" width="14" height="14" fill="{COL["ok"]}"/>'
            f'<text x="190" y="62" font-size="13">Official store ({play})</text>'
            f'<rect x="170" y="80" width="14" height="14" fill="{COL["high"]}"/>'
            f'<text x="190" y="92" font-size="13">Other source ({other})</text></svg>')


def svg_timeline(rows):
    pts = []
    for r in rows:
        try:
            pts.append((datetime.strptime(r["installed"], "%Y-%m-%d"), r))
        except ValueError:
            pass
    if len(pts) < 2:
        return "<p>Not enough install-date data.</p>"
    t0, t1 = min(p[0] for p in pts), max(p[0] for p in pts)
    span = max(1, (t1 - t0).days)
    o = [f'<svg viewBox="0 0 640 110" width="100%" style="{FONT}"><line x1="20" y1="70" x2="620" y2="70" stroke="#aaa"/>']
    for dt, r in pts:
        x = 20 + 600 * (dt - t0).days / span
        c = COL["high"] if r["score"] >= 30 else COL["medium"] if r["score"] >= 15 else "#5f6368"
        o.append(f'<circle cx="{x:.0f}" cy="70" r="{3 + min(6, r["score"] / 8):.0f}" fill="{c}" opacity=".7"/>')
    o.append(f'<text x="20" y="100" font-size="11">{t0:%Y-%m-%d}</text>'
             f'<text x="620" y="100" font-size="11" text-anchor="end">{t1:%Y-%m-%d}</text>'
             f'<text x="320" y="20" font-size="12" text-anchor="middle">App install timeline (big/red dot = more suspicious)</text></svg>')
    return "".join(o)


# ---------------- report ----------------
def write_report(outdir, d, findings, apps, score, extra_advice=None):
    outdir = Path(outdir)
    outdir.mkdir(parents=True, exist_ok=True)
    rows = app_rows(apps, d)
    e = html.escape
    order = {"high": 0, "medium": 1, "low": 2, "info": 3}
    names = {"high": "HIGH", "medium": "MEDIUM", "low": "LOW", "info": "INFO"}
    fl = "".join(
        f'<div class="f" style="border-left:6px solid {COL[f["sev"]]}"><b>{e(f["title"])}</b>'
        f'<span class="tag" style="background:{COL[f["sev"]]}">{names[f["sev"]]}</span>'
        f'<p>{e(f["detail"])}</p><p class="adv">&rarr; {e(f["advice"])}</p></div>'
        for f in sorted(findings, key=lambda f: order[f["sev"]])) or \
        '<p style="color:#188038"><b>Nothing notable found.</b> (This is not a guarantee of safety.)</p>'
    tbl = "".join(
        f'<tr><td>{e(r["name"])}</td><td>{e(r["installer"] or "unknown/sideload")}</td>'
        f'<td>{e(r["installed"])}</td><td>{", ".join(SENSITIVE.get(p, p) for p in sorted(r["sens"]))}</td>'
        f'<td>{r["score"]}</td></tr>' for r in rows[:40])
    pr = d["props"]
    adv = "".join(f"<li>{e(a)}</li>" for a in (extra_advice or []))
    doc = f"""<!doctype html><html lang="en"><meta charset="utf-8"><title>Phone Security Scan Report</title>
<style>body{{{FONT};max-width:960px;margin:2em auto;padding:0 1em;color:#222}}
.f{{background:#fafafa;padding:8px 12px;margin:10px 0;border-radius:4px}}
.tag{{color:#fff;font-size:12px;padding:2px 8px;border-radius:10px;margin-left:8px}}
.adv{{color:#0b57d0}}table{{border-collapse:collapse;width:100%;font-size:13px}}
td,th{{border:1px solid #ddd;padding:5px;text-align:left}}th{{background:#f1f3f4}}
.row{{display:flex;flex-wrap:wrap;gap:24px;align-items:center}}.warn{{background:#fff4d6;border:1px solid #e0b800;padding:10px;border-radius:6px}}
</style><h1>Phone Security Scan Report</h1>
<p>{e(pr.get('ro.product.manufacturer', ''))} {e(pr.get('ro.product.model', ''))} &middot; {e(pr.get('platform', 'Android'))} {e(pr.get('ro.build.version.release', ''))}
&middot; patch {e(pr.get('ro.build.version.security_patch', ''))} &middot; generated {time.strftime('%Y-%m-%d %H:%M')}</p>
<div class="row"><div>{svg_gauge(score)}</div><div>{svg_donut(apps)}</div></div>
<h2>Findings ({len(findings)})</h2>{fl}
<h2>Most suspicious apps (by score)</h2>{svg_bars(rows)}
<h2>Permission map (red = granted)</h2>{svg_heatmap(rows)}
<h2>Install timeline</h2>{svg_timeline(rows)}
<h2>Third-party apps (top 40)</h2>
<table><tr><th>App</th><th>Installer</th><th>Installed</th><th>Sensitive permissions</th><th>Score</th></tr>{tbl}</table>
<h2>What to do now</h2><ol>
<li><b>From another device</b>, change your Google/Apple/WhatsApp/bank passwords and enable 2-step verification.</li>
<li>For red items, first disable Accessibility/Device admin access, then uninstall the app.</li>
<li>Back up what you need (photos/files only, not apps), then factory reset if needed.</li>
<li>If someone may be stalking or harassing you: get help from a safe place; removing spyware can alert them.</li>{adv}</ol>
<div class="warn"><b>Limits:</b> this tool estimates risk from names, permissions and settings. Advanced or system-level
spyware may be missed, and legitimate apps can be flagged by mistake. It is not proof.</div></html>"""
    (outdir / "security_report.html").write_text(doc, encoding="utf-8")
    (outdir / "findings.json").write_text(json.dumps(
        {"score": score, "findings": findings, "device": pr}, ensure_ascii=False, indent=2), encoding="utf-8")
    return outdir / "security_report.html"


def run_scan(dest_root, log=print, owner_confirmed=False):
    if not owner_confirmed:
        log("Stopped: confirm the phone is yours or you have the owner's permission.")
        return None
    d = collect(log)
    findings, apps, score = analyze(d)
    out = Path(dest_root) / ("security_scan_" + time.strftime("%Y%m%d_%H%M%S"))
    rep = write_report(out, d, findings, apps, score)
    log(f"Risk score: {score}/100, findings: {len(findings)}")
    log(f"Report: {rep}")
    return rep


if __name__ == "__main__":
    import sys
    if "--yes" in sys.argv:
        run_scan(Path.cwd(), owner_confirmed=True)
    else:
        print("Run: python security_scan.py --yes   (only if the phone is yours / you have permission)")
