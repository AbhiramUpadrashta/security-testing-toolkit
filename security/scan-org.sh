#!/usr/bin/env bash
# Scan every repository in a GitHub organization (or user) with the Security Toolkit.
#
#   gh auth login                          # once: sign in with the GitHub CLI
#   ./security/scan-org.sh your-company    # scans all repos, writes org-reports/index.html
#   ./security/scan-org.sh your-company 20 # only the 20 most recently updated repos
#
# Needs Docker, Python 3, git and the GitHub CLI (https://cli.github.com).

set -uo pipefail
export MSYS_NO_PATHCONV=1   # keeps Docker paths working in Git Bash on Windows

ORG="${1:?Usage: ./security/scan-org.sh <github-org-or-user> [max-repos]}"
LIMIT="${2:-1000}"
TOOLKIT="$(cd "$(dirname "$0")" && pwd)"
OUT="$(pwd)/org-reports"
WORK="$(pwd)/.org-scan-tmp"

command -v gh >/dev/null || { echo "Install the GitHub CLI first: https://cli.github.com"; exit 2; }
gh auth status >/dev/null 2>&1 || { echo "Run 'gh auth login' first"; exit 2; }

mkdir -p "$OUT" "$WORK"
REPOS=$(gh repo list "$ORG" --limit "$LIMIT" --no-archived --json name -q '.[].name')
TOTAL=$(echo "$REPOS" | grep -c . || true)
[ "$TOTAL" -gt 0 ] || { echo "No repos found for $ORG (check the name and your access)"; exit 2; }
echo "Found $TOTAL repos in $ORG"

ROWS=""; i=0
for R in $REPOS; do
  i=$((i+1))
  rm -rf "$WORK/$R"
  if ! gh repo clone "$ORG/$R" "$WORK/$R" -- --quiet 2>/dev/null; then
    echo "[$i/$TOTAL] $R  could not clone, skipped"; continue
  fi
  ( cd "$WORK/$R" && NO_OPEN=1 SECURITY_FAIL_ON=none "$TOOLKIT/scan.sh" >/dev/null 2>&1 )
  mkdir -p "$OUT/$R" && cp -R "$WORK/$R/security-reports/." "$OUT/$R/" 2>/dev/null
  COUNTS=$(python3 - "$OUT/$R/summary.md" <<'PY'
import sys
try:
    row=[l for l in open(sys.argv[1]) if l.startswith('| ') and l[2].isdigit()][0]
    print(row.strip('| \n').replace(' | ',' '))
except Exception: print('? ? ? ? ?')
PY
)
  read -r CR HI ME LO IN <<< "$COUNTS"
  echo "[$i/$TOTAL] $R  ${CR} critical  ${HI} high  ${ME} medium"
  ROWS="$ROWS<tr><td><a href=\"$R/report.html\">$R</a></td><td class=c>$CR</td><td class=h>$HI</td><td>$ME</td><td>$LO</td></tr>"
  rm -rf "$WORK/$R"
done
rm -rf "$WORK"

cat > "$OUT/index.html" <<HTML
<!doctype html><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>$ORG security report</title>
<style>body{font:15px/1.5 system-ui,sans-serif;margin:0;padding:32px 16px;background:#f6f7fb;color:#0f172a}main{max-width:900px;margin:auto}
table{width:100%;border-collapse:collapse;background:#fff;border-radius:10px;overflow:hidden}th,td{padding:10px 12px;border-bottom:1px solid #e2e5ea;text-align:left}
.c{color:#b3261e;font-weight:700}.h{color:#e0590c;font-weight:700}a{color:#4f6bed}</style>
<main><h1>$ORG: security report</h1><p>$TOTAL repositories scanned on $(date '+%Y-%m-%d %H:%M'). Click a repo for its full report.</p>
<table><tr><th>Repository</th><th>Critical</th><th>High</th><th>Medium</th><th>Low</th></tr>$ROWS</table></main>
HTML
echo ""
echo "Company report: $OUT/index.html"
[ -n "${NO_OPEN:-}" ] || ( command -v open >/dev/null && open "$OUT/index.html" ) || ( command -v start >/dev/null && start "$OUT/index.html" ) || true
