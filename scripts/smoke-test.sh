#!/usr/bin/env bash
# Post-deploy smoke test: the API answers, headers are set, prelogin works. Usage: smoke-test.sh https://host
set -euo pipefail
base="${1%/}"

time_json=$(curl -fsS "$base/api/v1/time")
echo "$time_json" | grep -q '"now":' || { echo "GET /time failed"; exit 1; }

headers=$(curl -fsS -D - -o /dev/null "$base/api/v1/config")
for h in content-security-policy strict-transport-security x-content-type-options referrer-policy; do
  echo "$headers" | grep -qi "^$h:" || { echo "missing header $h"; exit 1; }
done

prelogin=$(curl -fsS -X POST "$base/api/v1/auth/prelogin" -H 'content-type: application/json' \
  -d '{"email":"smoke-test@veilauth.invalid"}')
echo "$prelogin" | grep -q '"alg":"argon2id"' || { echo "prelogin failed"; exit 1; }

status=$(curl -s -o /dev/null -w '%{http_code}' "$base/api/v1/devices")
[ "$status" = "401" ] || { echo "unauthenticated /devices returned $status"; exit 1; }

echo "smoke test passed for $base"
