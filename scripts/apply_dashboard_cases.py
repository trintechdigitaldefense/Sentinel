#!/usr/bin/env python3
# © 2026 TrinTech Digital Defense — authorized defensive use only
"""Inject Open cases panel into modules/dashboard.html (Phase 8).

Run from repo root (also called from setup.py):
  python3 scripts/apply_dashboard_cases.py
"""
from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
HTML = ROOT / "modules" / "dashboard.html"

CASES_SECTION = '''  <div class="section"><h2>Open cases</h2>
    <div class="card">
      <div id="casesMeta" class="mono" style="margin-bottom:8px;color:var(--muted)">—</div>
      <table>
        <thead><tr><th>ID</th><th>Status</th><th>Sev</th><th>Title</th><th>Assignee</th></tr></thead>
        <tbody id="casesBody"></tbody>
      </table>
    </div>
  </div>
'''

METRIC_LINE = (
    "'<div class=\"card\"><h3>Open cases</h3><div class=\"metric\">'"
    "+(s.cases_open_count!=null?s.cases_open_count:((s.cases_open||[]).length||0))"
    "+'</div></div>'"
)

RENDER_JS = '''
    var cases = s.cases_open || [];
    var cmeta = document.getElementById('casesMeta');
    var cbody = document.getElementById('casesBody');
    if (cmeta) cmeta.textContent = (s.cases_open_count != null ? s.cases_open_count : cases.length) + ' open (new / triaging / investigating / contained)';
    if (cbody) {
      cbody.innerHTML = cases.length ? cases.map(function(c){
        return '<tr><td class="mono">'+(c.id||'')+'</td><td>'+(c.status||'')+'</td><td>'+(c.severity||'')+'</td><td>'+(c.title||'').replace(/</g,'&lt;')+'</td><td>'+(c.assignee||'—')+'</td></tr>';
      }).join('') : '<tr><td colspan=5>No open cases</td></tr>';
    }
'''


def main() -> int:
    if not HTML.exists():
        print(f"[!] missing {HTML}")
        return 1
    text = HTML.read_text(encoding="utf-8")
    original = text

    if 'id="casesBody"' not in text:
        needle = '  <div class="section"><h2>Fleet</h2>'
        if needle in text:
            text = text.replace(needle, CASES_SECTION + needle, 1)
            print("[+] inserted Open cases section")
        else:
            print("[!] Fleet section not found — skip section inject")

    if "Open cases</h3>" not in text and "cases_open_count" not in text:
        # append metric after Tripwire metric if present
        trip = "'<div class=\"card\"><h3>Tripwire</h3><div class=\"metric\">'+((s.tripwire||{}).count||0)+'</div></div>';"
        if trip in text:
            text = text.replace(
                trip,
                trip[:-1] + "+\n      " + METRIC_LINE + ";",
                1,
            )
            print("[+] open cases metric card")

    if "casesBody" in text and "casesMeta" in text and "var cases = s.cases_open" not in text:
        marker = (
            "    document.getElementById('alerts').innerHTML =\n"
            "      (s.alerts||[]).slice(-15).reverse().map(function(a){return '<li class=\"mono\">'+String(a).replace(/</g,'&lt;')+'</li>';}).join('') || '<li>None</li>';"
        )
        if marker in text:
            text = text.replace(marker, marker + RENDER_JS, 1)
            print("[+] cases table render in refresh()")
        else:
            print("[!] alerts render marker not found")

    if text == original:
        print("[=] dashboard.html already has cases UI (or markers moved)")
        return 0

    HTML.write_text(text, encoding="utf-8")
    print(f"[+] updated {HTML}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
