"""Synthetic phone (no real device): one clean app, one fake stalkerware, one system app."""
import tempfile, re
from pathlib import Path
import security_scan as ss


def pkg(name, installer, flags, perms, first="2026-03-01"):
    p = "\n".join(f"        {x}: granted=true" for x in perms)
    return (f"\n  Package [{name}] (abc123):\n    installerPackageName={installer}\n"
            f"    flags=[ {flags} ]\n    firstInstallTime={first} 10:00:00\n"
            f"    install permissions:\n{p}\n")


txt = "Packages:" + (
    pkg("com.google.android.gms", "null", "SYSTEM HAS_CODE", ["android.permission.CAMERA"])
    + pkg("com.whatsapp.clone2", "com.android.vending", "HAS_CODE", ["android.permission.CAMERA"], "2025-11-02")
    + pkg("com.system.service.monitor", "null", "HAS_CODE",
          ["android.permission.READ_SMS", "android.permission.RECEIVE_SMS", "android.permission.RECORD_AUDIO",
           "android.permission.CAMERA", "android.permission.ACCESS_FINE_LOCATION",
           "android.permission.READ_CALL_LOG", "android.permission.READ_CONTACTS"], "2026-09-15")
    + pkg("com.fun.game", "com.android.vending", "HAS_CODE", ["android.permission.CAMERA"], "2026-01-10"))

data = {
    "packages_txt": txt,
    "settings": {"enabled_accessibility_services": "com.system.service.monitor/.Svc",
                 "enabled_notification_listeners": "com.system.service.monitor/.Nl",
                 "enabled_input_methods": "", "install_non_market_apps": "1", "adb_enabled": "1",
                 "development_settings_enabled": "1", "http_proxy": "10.0.0.5:8080",
                 "private_dns_mode": "", "private_dns_specifier": ""},
    "props": {"ro.product.model": "SM-A135F", "ro.product.manufacturer": "samsung",
              "ro.build.version.release": "13", "ro.build.version.security_patch": "2024-01-05",
              "ro.boot.verifiedbootstate": "green", "ro.debuggable": "0", "ro.crypto.state": "encrypted"},
    "device_policy_txt": "Enabled Device Admins:\n  admin=ComponentInfo{com.system.service.monitor/.Adm}",
    "launchers": {"com.fun.game", "com.whatsapp.clone2"},
    "overlay": {"com.system.service.monitor"},
    "root": False,
}
F, apps, score = ss.analyze(data)
print("score:", score)
for f in sorted(F, key=lambda f: -f["pts"]):
    print(f'  [{f["sev"]:6s}] {f["pts"]:>2}  {f["title"].encode("ascii", "replace").decode()[:70]}')

titles = " | ".join(f["title"] for f in F)
assert score >= 50, "should be high risk"
assert "com.system.service.monitor" in titles
assert not any("com.fun.game" in f["title"] for f in F), "clean app flagged"
assert not any("com.google.android.gms" in f["title"] for f in F), "system app flagged"

# clean phone should score low
clean = dict(data, settings={**data["settings"], "enabled_accessibility_services": "", "enabled_notification_listeners": "",
                             "http_proxy": "null", "install_non_market_apps": "0"},
             device_policy_txt="", packages_txt="Packages:" + pkg("com.fun.game", "com.android.vending", "HAS_CODE", ["android.permission.CAMERA"]),
             overlay=set())
cf, _, cs = ss.analyze(clean)
print("clean phone score:", cs, [f["title"][:30].encode("ascii", "replace").decode() for f in cf])
assert cs < 25

out = Path(tempfile.mkdtemp())
rep = ss.write_report(out, data, F, apps, score)
h = rep.read_text(encoding="utf-8")
print("report bytes:", len(h), "| svg charts:", h.count("<svg"), "| findings.json:", (out / "findings.json").exists())
assert h.count("<svg") >= 5
import xml.dom.minidom as md
md.parseString(re.search(r"<svg.*?</svg>", h, re.S).group(0))   # svg well-formed
print("ALL PASS ->", rep)
