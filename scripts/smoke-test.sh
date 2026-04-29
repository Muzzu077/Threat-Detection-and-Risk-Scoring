#!/usr/bin/env bash
#
# TrustFlow end-to-end smoke test.
# Brings up (or assumes) the docker stack, registers a fresh user, generates
# an API key, posts events, and asserts they arrive in the dashboard's API.
#
# Usage:
#   bash scripts/smoke-test.sh
#   API_BASE=https://trustflowapi.welocalhost.com bash scripts/smoke-test.sh
#
# Exits 0 on success, non-zero on any failed assertion.

set -euo pipefail

API_BASE="${API_BASE:-http://localhost:8000}"
PASSWORD="SmokePass123!"
EMAIL="smoke-$(date +%s)-$RANDOM@trustflow.test"
EVENTS=20

bold()   { printf '\033[1m%s\033[0m\n' "$*"; }
green()  { printf '\033[32m%s\033[0m\n' "$*"; }
red()    { printf '\033[31m%s\033[0m\n' "$*" >&2; }

require_jq() {
  if ! command -v jq >/dev/null 2>&1; then
    # Fall back to python; jq is nicer but optional.
    JQ_CMD='python3 -c "import sys,json; d=json.load(sys.stdin); import argparse"'
    JQ_FALLBACK=1
  else
    JQ_FALLBACK=0
  fi
}

bold "[1/5] Checking API at $API_BASE"
HEALTH=$(curl -s -w "\n%{http_code}" "$API_BASE/health" || true)
HEALTH_BODY=$(echo "$HEALTH" | head -n1)
HEALTH_CODE=$(echo "$HEALTH" | tail -n1)
if [ "$HEALTH_CODE" != "200" ]; then
  red "FAIL: $API_BASE/health returned $HEALTH_CODE"
  exit 1
fi
green "  OK ($HEALTH_BODY)"

bold "[2/5] Registering test user $EMAIL"
REG=$(curl -s -X POST "$API_BASE/api/auth/register" \
  -H 'Content-Type: application/json' \
  -d "{\"email\":\"$EMAIL\",\"password\":\"$PASSWORD\",\"display_name\":\"smoke\"}")
TOKEN=$(echo "$REG" | python3 -c "import sys,json; print(json.load(sys.stdin)['access_token'])")
green "  OK (got access_token)"

bold "[3/5] Generating API key"
KEY_RESP=$(curl -s -X POST "$API_BASE/api/keys" \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"name":"smoke-key"}')
API_KEY=$(echo "$KEY_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin)['key'])")
PREFIX=$(echo "$API_KEY" | head -c 16)
green "  OK ($PREFIX...)"

bold "[4/5] Posting $EVENTS events to /api/v1/ingest"
EVENTS_JSON=$(python3 -c "
import json, sys, time
n = $EVENTS
ts = time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())
events = [{'timestamp': ts, 'user': f'smoke-user-{i}', 'ip': '203.0.113.1',
           'action': 'GET', 'status': 'success', 'resource': '/smoke'} for i in range(n)]
print(json.dumps({'events': events}))
")
INGEST=$(curl -s -X POST "$API_BASE/api/v1/ingest" \
  -H "X-API-Key: $API_KEY" -H 'Content-Type: application/json' \
  -d "$EVENTS_JSON")
ACCEPTED=$(echo "$INGEST" | python3 -c "import sys,json; print(json.load(sys.stdin)['accepted'])")
if [ "$ACCEPTED" != "$EVENTS" ]; then
  red "FAIL: only $ACCEPTED of $EVENTS events accepted"
  exit 1
fi
green "  OK ($ACCEPTED accepted)"

bold "[5/5] Querying /api/events for the new tenant"
sleep 1
EVENTS_OUT=$(curl -s -H "Authorization: Bearer $TOKEN" "$API_BASE/api/events?limit=200")
COUNT=$(echo "$EVENTS_OUT" | python3 -c "
import sys, json
d = json.load(sys.stdin)
print(sum(1 for e in d.get('data', []) if (e.get('user') or '').startswith('smoke-user-')))
")
if [ "$COUNT" -lt "$EVENTS" ]; then
  red "FAIL: only $COUNT of $EVENTS events queryable"
  exit 1
fi
green "  OK ($COUNT queryable)"

echo
green "✓ TrustFlow smoke test PASSED"
