#!/usr/bin/env bash
# Boot smoke test against a running stack (`make up`). Exits non-zero on any failure.
set -euo pipefail
API=${OPT_API:-http://localhost:8000}
A=(-H "X-OPT-Tenant: demo-a" -H "Content-Type: application/json")
B=(-H "X-OPT-Tenant: demo-b" -H "Content-Type: application/json")
fail() { echo "SMOKE FAIL: $*" >&2; exit 1; }

curl -fsS "$API/healthz" | grep -q '"ok"' || fail healthz
curl -fsS "$API/readyz" | grep -q '"ready"' || fail "readyz (database)"

from=$(date -u -d '-1 day' +%Y-%m-%dT%H:%M:%SZ); to=$(date -u -d '+30 days' +%Y-%m-%dT%H:%M:%SZ)
eid=$(curl -fsS "${A[@]}" -X POST "$API/api/v1/engagements" -d "{\"name\":\"smoke\",\"roe_valid_from\":\"$from\",\"roe_valid_to\":\"$to\",\"rules\":[{\"kind\":\"domain\",\"value\":\"lab.example.vn\"}]}" \
  | python3 -c 'import json,sys;print(json.load(sys.stdin)["id"])')
echo "engagement $eid"

check() { curl -fsS "${A[@]}" -X POST "$API/api/v1/engagements/$eid/scope-check" -d "{\"target\":\"$1\",\"risk\":\"$2\"}"; }
check juice.lab.example.vn low | grep -q '"allowed":true' || fail "in-scope verified target denied"
check google.com passive | grep -q '"allowed":false' || fail "out-of-scope target allowed"

code=$(curl -s -o /dev/null -w '%{http_code}' "${B[@]}" -X POST "$API/api/v1/engagements/$eid/scope-check" -d '{"target":"juice.lab.example.vn","risk":"passive"}')
[ "$code" = 404 ] || fail "tenant B reached tenant A's engagement (HTTP $code)"

curl -fsS "${A[@]}" "$API/api/v1/audit/verify" | grep -q '"chain_valid":true' || fail "audit chain"
echo "SMOKE OK"
