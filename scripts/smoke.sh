#!/usr/bin/env bash
# Boot smoke test against a running stack (`make up`). Exits non-zero on any failure.
# Logs in through Keycloak, then runs recon -> findings -> report on the lab target.
set -euo pipefail
API=${OPT_API:-http://localhost:8000}
KC=${OPT_KEYCLOAK:-http://localhost:8080/realms/opt}
fail() { echo "SMOKE FAIL: $*" >&2; exit 1; }
json() { python3 -c "import json,sys;print(json.load(sys.stdin)$1)"; }

login() {  # DEV ONLY: password grant on the opt-cli client of the dev realm
  curl -fsS -X POST "$KC/protocol/openid-connect/token" \
    --data-urlencode grant_type=password --data-urlencode client_id=opt-cli \
    --data-urlencode "username=$1" --data-urlencode "password=$2" | json '["access_token"]'
}

curl -fsS "$API/healthz" | grep -q '"ok"' || fail healthz
curl -fsS "$API/readyz" | grep -q '"ready"' || fail "readyz (database)"

TA=$(login alice alice-dev) || fail "login alice"
TV=$(login victor victor-dev) || fail "login victor"
TB=$(login bob bob-dev) || fail "login bob"
A=(-H "Authorization: Bearer $TA" -H "Content-Type: application/json")
V=(-H "Authorization: Bearer $TV" -H "Content-Type: application/json")
B=(-H "Authorization: Bearer $TB" -H "Content-Type: application/json")

code=$(curl -s -o /dev/null -w '%{http_code}' -H "X-OPT-Tenant: demo-a" "$API/api/v1/whoami")
[ "$code" = 401 ] || fail "legacy X-OPT-Tenant header accepted (HTTP $code)"
curl -fsS "${A[@]}" "$API/api/v1/whoami" | grep -q '"tenant":"demo-a"' || fail "whoami alice"

from=$(date -u -d '-1 day' +%Y-%m-%dT%H:%M:%SZ); to=$(date -u -d '+30 days' +%Y-%m-%dT%H:%M:%SZ)
body="{\"name\":\"smoke\",\"roe_valid_from\":\"$from\",\"roe_valid_to\":\"$to\",\"rules\":[{\"kind\":\"domain\",\"value\":\"lab.example.vn\"}]}"
code=$(curl -s -o /dev/null -w '%{http_code}' "${V[@]}" -X POST "$API/api/v1/engagements" -d "$body")
[ "$code" = 403 ] || fail "viewer created an engagement (HTTP $code)"
eid=$(curl -fsS "${A[@]}" -X POST "$API/api/v1/engagements" -d "$body" | json '["id"]')
echo "engagement $eid"

check() { curl -fsS "${A[@]}" -X POST "$API/api/v1/engagements/$eid/scope-check" -d "{\"target\":\"$1\",\"risk\":\"$2\"}"; }
check juice.lab.example.vn low | grep -q '"allowed":true' || fail "in-scope verified target denied"
check google.com passive | grep -q '"allowed":false' || fail "out-of-scope target allowed"

code=$(curl -s -o /dev/null -w '%{http_code}' "${B[@]}" -X POST "$API/api/v1/engagements/$eid/scope-check" -d '{"target":"juice.lab.example.vn","risk":"passive"}')
[ "$code" = 404 ] || fail "tenant B reached tenant A's engagement (HTTP $code)"

code=$(curl -s -o /dev/null -w '%{http_code}' "${A[@]}" -X POST "$API/api/v1/engagements/$eid/scans" -d '{"target":"google.com"}')
[ "$code" = 403 ] || fail "scan of an out-of-scope target accepted (HTTP $code)"

sid=$(curl -fsS "${A[@]}" -X POST "$API/api/v1/engagements/$eid/scans" -d '{"target":"juice.lab.example.vn"}' | json '["id"]')
echo "scan $sid"
for _ in $(seq 1 30); do
  status=$(curl -fsS "${V[@]}" "$API/api/v1/scans/$sid" | json '["status"]')
  [ "$status" = done ] && break
  [ "$status" = failed ] && fail "scan failed"
  sleep 1
done
[ "$status" = done ] || fail "scan did not finish (status $status)"
curl -fsS "${V[@]}" "$API/api/v1/scans/$sid" | grep -q '"http_probe"' || fail "http_probe step missing"
report=$(curl -fsS "${V[@]}" "$API/api/v1/scans/$sid/report")
echo "$report" | grep -q "Báo cáo quét: juice.lab.example.vn" || fail "report header"
echo "$report" | grep -q "Dịch vụ web chỉ chạy HTTP" || fail "expected finding on the HTTP-only lab target"
echo "$report" | head -20

code=$(curl -s -o /dev/null -w '%{http_code}' "${B[@]}" "$API/api/v1/scans/$sid/report")
[ "$code" = 404 ] || fail "tenant B read tenant A's report (HTTP $code)"

curl -fsS "${A[@]}" "$API/api/v1/audit/verify" | grep -q '"chain_valid":true' || fail "audit chain"
echo "SMOKE OK"
