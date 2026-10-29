#!/usr/bin/env python3
"""Combine Gitleaks, Semgrep, Trivy and ZAP results into one report.

Writes  <dir>/report.html  and  <dir>/summary.md
Also posts the summary to the GitHub Actions run page when available.
Exit code 1 if any finding is at or above --fail-on severity.
"""
import argparse
import html
import json
import os
import sys
from datetime import datetime

LEVELS = ["critical", "high", "medium", "low", "info"]
RANK = {lvl: i for i, lvl in enumerate(LEVELS)}


def load(path):
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return None


def norm(sev):
    s = str(sev or "").lower()
    return {"error": "high", "warning": "medium", "unknown": "low",
            "informational": "info", "note": "low"}.get(s, s if s in RANK else "low")


def parse_gitleaks(data):
    out = []
    for f in data or []:
        out.append({
            "tool": "Gitleaks", "severity": "high",
            "title": f"Secret found: {f.get('Description') or f.get('RuleID', 'secret')}",
            "location": f"{f.get('File', '?')}:{f.get('StartLine', '?')}"
                        + (f" (commit {str(f.get('Commit', ''))[:8]})" if f.get("Commit") else ""),
            "fix": "Revoke/rotate this secret now, then remove it from code and git history. Use environment variables or a secrets manager.",
        })
    return out


def parse_semgrep(data):
    out = []
    for r in (data or {}).get("results", []):
        extra = r.get("extra", {})
        sev = extra.get("metadata", {}).get("impact") or extra.get("severity")
        out.append({
            "tool": "Semgrep", "severity": norm(sev),
            "title": (extra.get("message") or r.get("check_id", "")).strip().split("\n")[0][:200],
            "location": f"{r.get('path', '?')}:{r.get('start', {}).get('line', '?')}",
            "fix": f"Rule: {r.get('check_id', '')}",
        })
    return out


def parse_trivy(data):
    out = []
    for res in (data or {}).get("Results", []) or []:
        target = res.get("Target", "?")
        for v in res.get("Vulnerabilities") or []:
            fixed = v.get("FixedVersion")
            out.append({
                "tool": "Trivy", "severity": norm(v.get("Severity")),
                "title": f"{v.get('VulnerabilityID')} in {v.get('PkgName')} {v.get('InstalledVersion', '')}"
                         + (f" - {v.get('Title')}" if v.get("Title") else ""),
                "location": target,
                "fix": f"Upgrade {v.get('PkgName')} to {fixed}" if fixed else "No fixed version yet - check advisory / consider alternatives",
            })
        for m in res.get("Misconfigurations") or []:
            if m.get("Status") == "PASS":
                continue
            out.append({
                "tool": "Trivy", "severity": norm(m.get("Severity")),
                "title": f"{m.get('ID')}: {m.get('Title')}",
                "location": target,
                "fix": m.get("Resolution") or "",
            })
    return out


def parse_zap(data):
    out = []
    risk = {"3": "high", "2": "medium", "1": "low", "0": "info"}
    for site in (data or {}).get("site", []) or []:
        for a in site.get("alerts", []) or []:
            inst = a.get("instances") or [{}]
            out.append({
                "tool": "ZAP", "severity": risk.get(str(a.get("riskcode")), "low"),
                "title": a.get("alert") or a.get("name", "Alert"),
                "location": f"{inst[0].get('uri', site.get('@name', '?'))} (+{max(len(inst) - 1, 0)} more)",
                "fix": html.unescape((a.get("solution") or "").replace("<p>", "").replace("</p>", " ")).strip()[:300],
            })
    return out


def build(report_dir):
    sources = [
        ("Gitleaks", "gitleaks.json", parse_gitleaks),
        ("Semgrep", "semgrep.json", parse_semgrep),
        ("Trivy", "trivy.json", parse_trivy),
        ("ZAP", "zap.json", parse_zap),
    ]
    findings, ran = [], {}
    for name, fname, parser in sources:
        data = load(os.path.join(report_dir, fname))
        ran[name] = data is not None
        if data is not None:
            findings += parser(data)
    findings.sort(key=lambda f: (RANK[f["severity"]], f["tool"]))
    return findings, ran


def counts(findings):
    c = {lvl: 0 for lvl in LEVELS}
    for f in findings:
        c[f["severity"]] += 1
    return c


def write_markdown(path, findings, ran):
    c = counts(findings)
    lines = ["# Security Scan Summary", "",
             "| Critical | High | Medium | Low | Info |", "|---|---|---|---|---|",
             "| " + " | ".join(str(c[l]) for l in LEVELS) + " |", "",
             "**Scanners:** " + ", ".join(f"{k} {'ran' if v else 'skipped'}" for k, v in ran.items()), ""]
    top = [f for f in findings if f["severity"] in ("critical", "high")][:25]
    if top:
        lines += ["## Critical / High findings", "", "| Severity | Tool | Issue | Where |", "|---|---|---|---|"]
        for f in top:
            t = f["title"].replace("|", "/")
            lines.append(f"| {f['severity'].upper()} | {f['tool']} | {t} | `{f['location']}` |")
    else:
        lines.append("No critical or high findings.")
    lines += ["", "Full details: download the **security-reports** artifact and open `report.html`."]
    text = "\n".join(lines)
    with open(path, "w", encoding="utf-8") as f:
        f.write(text)
    return text


def write_html(path, findings, ran):
    c = counts(findings)
    e = html.escape
    rows = "\n".join(
        f'<tr data-sev="{f["severity"]}" data-tool="{f["tool"]}"><td><span class="sev {f["severity"]}">{f["severity"].upper()}</span></td>'
        f'<td>{e(f["tool"])}</td><td>{e(f["title"])}</td><td><code>{e(f["location"])}</code></td><td>{e(f["fix"])}</td></tr>'
        for f in findings)
    cards = "".join(f'<div class="card {l}"><b>{c[l]}</b><span>{l.title()}</span></div>' for l in LEVELS)
    status = " · ".join(f"{k}: {'ran' if v else 'skipped'}" for k, v in ran.items())
    tools = "".join(f'<option>{t}</option>' for t in ran)
    doc = f"""<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Security Scan Report</title><style>
:root{{--bg:#f7f7f8;--fg:#1c1c1f;--muted:#666;--card:#fff;--line:#e3e3e6}}
@media (prefers-color-scheme:dark){{:root{{--bg:#151517;--fg:#ececef;--muted:#a0a0a8;--card:#1f1f23;--line:#33333a}}}}
body{{margin:0;padding:24px 16px;font:14px/1.5 system-ui,sans-serif;background:var(--bg);color:var(--fg)}}
.wrap{{max-width:1200px;margin:auto}} h1{{margin:0 0 4px}} .muted{{color:var(--muted)}}
.cards{{display:flex;gap:10px;flex-wrap:wrap;margin:20px 0}}
.card{{background:var(--card);border:1px solid var(--line);border-left:5px solid;border-radius:8px;padding:10px 16px;min-width:90px}}
.card b{{display:block;font-size:24px}} .card span{{color:var(--muted)}}
.critical{{border-color:#b3261e}} .high{{border-color:#e8590c}} .medium{{border-color:#d4a106}} .low{{border-color:#3b82f6}} .info{{border-color:#888}}
.sev{{color:#fff;padding:2px 8px;border-radius:4px;font-size:11px;font-weight:700}}
.sev.critical{{background:#b3261e}} .sev.high{{background:#e8590c}} .sev.medium{{background:#b8890a}} .sev.low{{background:#3b82f6}} .sev.info{{background:#888}}
.filters{{display:flex;gap:8px;flex-wrap:wrap;margin-bottom:10px}}
select,input{{padding:6px 8px;border:1px solid var(--line);border-radius:6px;background:var(--card);color:var(--fg)}}
.tbl{{overflow-x:auto;background:var(--card);border:1px solid var(--line);border-radius:8px}}
table{{border-collapse:collapse;width:100%}} th,td{{text-align:left;padding:8px 10px;border-bottom:1px solid var(--line);vertical-align:top}}
code{{font-size:12px;word-break:break-all}}
</style></head><body><div class="wrap">
<h1>Security Scan Report</h1><div class="muted">Generated {datetime.now().strftime('%Y-%m-%d %H:%M')} · {status}</div>
<div class="cards">{cards}</div>
<div class="filters"><select id="sev"><option value="">All severities</option>{''.join(f'<option>{l}</option>' for l in LEVELS)}</select>
<select id="tool"><option value="">All tools</option>{tools}</select><input id="q" placeholder="Search..."></div>
<div class="tbl"><table><thead><tr><th>Severity</th><th>Tool</th><th>Issue</th><th>Where</th><th>How to fix</th></tr></thead>
<tbody>{rows or '<tr><td colspan="5">No findings. Nice.</td></tr>'}</tbody></table></div></div>
<script>
const s=document.getElementById('sev'),t=document.getElementById('tool'),q=document.getElementById('q');
function f(){{const qq=q.value.toLowerCase();document.querySelectorAll('tbody tr[data-sev]').forEach(r=>{{
r.style.display=(!s.value||r.dataset.sev===s.value)&&(!t.value||r.dataset.tool===t.value)&&(!qq||r.textContent.toLowerCase().includes(qq))?'':'none'}})}}
[s,t].forEach(x=>x.onchange=f);q.oninput=f;
</script></body></html>"""
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(doc)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dir", default="security-reports")
    ap.add_argument("--fail-on", default="high", choices=LEVELS[:3] + ["none"])
    a = ap.parse_args()

    findings, ran = build(a.dir)
    md = write_markdown(os.path.join(a.dir, "summary.md"), findings, ran)
    write_html(os.path.join(a.dir, "report.html"), findings, ran)
    print(md)

    gh = os.environ.get("GITHUB_STEP_SUMMARY")
    if gh:
        with open(gh, "a", encoding="utf-8") as f:
            f.write(md + "\n")

    if a.fail_on != "none":
        bad = [x for x in findings if RANK[x["severity"]] <= RANK[a.fail_on]]
        if bad:
            print(f"\nFAILED: {len(bad)} finding(s) at or above '{a.fail_on}'.", file=sys.stderr)
            sys.exit(1)
    print("\nPASSED")


if __name__ == "__main__":
    main()
