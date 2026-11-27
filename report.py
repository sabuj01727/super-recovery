"""Writes an English HTML report (report.html) into the output folder."""
import html
import time
from pathlib import Path


def human(n):
    for u in ("B", "KB", "MB", "GB"):
        if n < 1024:
            return f"{n:.1f} {u}"
        n /= 1024
    return f"{n:.1f} TB"


def write_report(root, title, facts, type_summary=None, notes=None, deleted=None):
    root = Path(root)
    e = html.escape
    rows = "".join(f"<tr><td>{e(str(k))}</td><td>{e(str(v))}</td></tr>" for k, v in facts.items())
    types = ""
    if type_summary:
        types = "<h2>File types</h2><table><tr><th>Type</th><th>Count</th><th>Size</th></tr>" + "".join(
            f"<tr><td>{e(k)}</td><td>{c}</td><td>{human(s)}</td></tr>"
            for k, (c, s) in list(type_summary.items())[:40]) + "</table>"
    nt = "".join(f"<li>{e(n)}</li>" for n in (notes or []))
    dl = (f"<p>Text fragments recovered from deleted database space: <b>{deleted}</b> "
          f"(see deleted_strings.txt)</p>") if deleted is not None else ""
    (root / "report.html").write_text(f"""<!doctype html><html lang="en"><meta charset="utf-8">
<title>{e(title)}</title><style>
body{{font-family:'Segoe UI',Arial,sans-serif;max-width:860px;margin:2em auto;padding:0 1em;color:#222}}
table{{border-collapse:collapse;width:100%}}td,th{{border:1px solid #ccc;padding:6px;text-align:left}}
th{{background:#f0f0f0}}.warn{{background:#fff4d6;border:1px solid #e0b800;padding:10px;border-radius:6px}}
</style><h1>{e(title)}</h1><p>Generated: {time.strftime('%Y-%m-%d %H:%M:%S')}</p>
<table>{rows}</table>{types}{dl}
<h2>Notes</h2><ul>{nt}</ul>
<div class="warn"><b>Limits:</b> after a factory reset, the internal data of an encrypted phone cannot be
recovered by any software. This report only shows what was collected. A SHA-256 hash of every file
is in manifest.csv.</div></html>""", encoding="utf-8")
    return root / "report.html"
