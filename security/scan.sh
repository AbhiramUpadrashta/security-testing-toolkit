#!/usr/bin/env bash
# One-command local security scan. Needs Docker and Python 3.
#
#   ./security/scan.sh                          # scan code, secrets, dependencies
#   ./security/scan.sh http://localhost:3000    # + live scan of your running app
#
# Run from your project's root folder. Report opens at security-reports/report.html

set -uo pipefail
export MSYS_NO_PATHCONV=1   # keeps Docker paths working in Git Bash on Windows

TARGET_URL="${1:-${SECURITY_TARGET_URL:-}}"
FAIL_ON="${SECURITY_FAIL_ON:-high}"
REPORT_DIR="security-reports"
ROOT="$(pwd)"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

command -v docker >/dev/null || { echo "Docker is required: https://docs.docker.com/get-docker/"; exit 2; }
command -v python3 >/dev/null || { echo "Python 3 is required"; exit 2; }

mkdir -p "$REPORT_DIR"; chmod 777 "$REPORT_DIR"
rm -f "$REPORT_DIR"/*.json

step() { printf "\n\033[1;36m==> %s\033[0m\n" "$1"; }

step "1/4 Secrets scan (Gitleaks)"
if [ -d .git ]; then
  docker run --rm -v "$ROOT:/repo" \
    -e GIT_CONFIG_COUNT=1 -e GIT_CONFIG_KEY_0=safe.directory -e GIT_CONFIG_VALUE_0='*' \
    zricethezav/gitleaks:latest detect --source /repo --no-banner --redact \
    --report-format json --report-path "/repo/$REPORT_DIR/gitleaks.json" --exit-code 0
else
  docker run --rm -v "$ROOT:/repo" zricethezav/gitleaks:latest detect --source /repo --no-git \
    --no-banner --redact --report-format json --report-path "/repo/$REPORT_DIR/gitleaks.json" --exit-code 0
fi

step "2/4 Code scan (Semgrep)"
docker run --rm -v "$ROOT:/src" -w /src semgrep/semgrep:latest \
  semgrep scan --config p/default --metrics off --quiet \
  --exclude "$REPORT_DIR" --json --output "$REPORT_DIR/semgrep.json" . || true

step "3/4 Dependency & config scan (Trivy)"
docker run --rm -v "$ROOT:/src" -w /src aquasec/trivy:latest \
  fs --scanners vuln,misconfig --quiet --skip-dirs "$REPORT_DIR" \
  --format json --output "$REPORT_DIR/trivy.json" . || true

if [ -n "$TARGET_URL" ]; then
  step "4/4 Live app scan (OWASP ZAP baseline) -> $TARGET_URL"
  # Lets the container reach an app running on your machine
  ZAP_URL="${TARGET_URL/localhost/host.docker.internal}"
  ZAP_URL="${ZAP_URL/127.0.0.1/host.docker.internal}"
  docker run --rm --add-host=host.docker.internal:host-gateway \
    -v "$ROOT/$REPORT_DIR:/zap/wrk:rw" ghcr.io/zaproxy/zaproxy:stable \
    zap-baseline.py -t "$ZAP_URL" -J zap.json -r zap.html -I || true
else
  step "4/4 Live app scan skipped (pass your app URL to enable it)"
fi

step "Building report"
python3 "$SCRIPT_DIR/summarize.py" --dir "$REPORT_DIR" --fail-on "$FAIL_ON"
STATUS=$?

echo -e "\nReport: $ROOT/$REPORT_DIR/report.html"
[ -n "${NO_OPEN:-}" ] || ( command -v open >/dev/null && open "$REPORT_DIR/report.html" ) || \
( command -v xdg-open >/dev/null && xdg-open "$REPORT_DIR/report.html" >/dev/null 2>&1 ) || true
exit $STATUS
