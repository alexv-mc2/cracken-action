#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
tmp=$(mktemp -d)
python3 tests/fake_api.py "$tmp/port" &
server=$!
trap 'kill "$server" 2>/dev/null || true; wait "$server" 2>/dev/null || true; rm -rf "$tmp"' EXIT
for ((i=0; i<100; i++)); do [[ -s "$tmp/port" ]] && break; sleep 0.05; done
port=$(cat "$tmp/port")
CRACKEN_API_KEY="crk_aaaaaaaaaaaa_$(printf '%043d' 0)"
export CRACKEN_API_KEY
export CRACKEN_PROJECT_ID=11111111-1111-4111-8111-111111111111 VERSION=1.0 WAIT=1 TIMEOUT=2
export SBOM_FILE="$tmp/bom.json" GITHUB_OUTPUT="$tmp/output" GITHUB_STEP_SUMMARY="$tmp/summary"
printf '{"bomFormat":"CycloneDX","secret-content":"do-not-log"}' > "$SBOM_FILE"
checks=0
run() {
  local mode=$1 expected=$2 actual=0
  if [[ "${3:-}" == default ]]; then
    unset CRACKEN_API_URL
  else
    export CRACKEN_API_URL="${3:-http://127.0.0.1:$port/$mode/functions/v1/api-v1}"
  fi
  : > "$GITHUB_OUTPUT"; : > "$GITHUB_STEP_SUMMARY"
  sh scripts/upload.sh > "$tmp/log" 2>&1 || actual=$?
  if [[ "$actual" != "$expected" ]]; then cat "$tmp/log"; echo "FAIL $mode: expected $expected, got $actual"; exit 1; fi
  if grep -Fq "$CRACKEN_API_KEY" "$tmp/log" "$GITHUB_OUTPUT" "$GITHUB_STEP_SUMMARY" || grep -q 'do-not-log' "$tmp/log"; then echo 'FAIL secret disclosure'; exit 1; fi
  checks=$((checks+1)); echo "ok $checks - $mode (exit $actual)"
}
run success 0
grep -q '^high=1$' "$GITHUB_OUTPUT"
grep -q '^unknown=1$' "$GITHUB_OUTPUT"
grep -q '^upload-id=' "$GITHUB_OUTPUT"
grep -Fxq 'analysis-id=11111111-1111-4111-8111-111111111111' "$GITHUB_OUTPUT"
grep -Fxq 'upload-id=11111111-1111-4111-8111-111111111111' "$GITHUB_OUTPUT"
grep -Fxq 'app-url=https://app.example/products/test/releases/test' "$GITHUB_OUTPUT"
grep -Fxq 'analysis-status=succeeded' "$GITHUB_OUTPUT"
grep -Fxq 'high: 1' "$GITHUB_STEP_SUMMARY"
# Exercise host-only and trailing-slash overrides through upload, polling and pagination.
run success 0 "http://127.0.0.1:$port/success"
run success 0 "http://127.0.0.1:$port/success/"
# Intercept the default public host locally; never contact the real API with test keys.
mkdir "$tmp/bin"
cat > "$tmp/bin/curl" <<'CURL'
#!/usr/bin/env bash
set -euo pipefail
if [[ "$1" == --version ]]; then exec "$REAL_CURL" "$@"; fi
args=("$@")
last=$(($# - 1))
url=${args[$last]}
[[ "$url" == https://api.cracken.tech/v1/* ]] || exit 99
printf '%s\n' "$url" >> "$CURL_REQUESTS"
args[$last]="$CURL_TEST_BASE${url#https://api.cracken.tech}"
exec "$REAL_CURL" "${args[@]}"
CURL
chmod +x "$tmp/bin/curl"
REAL_CURL=$(command -v curl) CURL_TEST_BASE="http://127.0.0.1:$port/success" CURL_REQUESTS="$tmp/requests" PATH="$tmp/bin:$PATH" run success 0 default
[[ $(wc -l < "$tmp/requests") -eq 4 ]]
grep -q '^https://api.cracken.tech/v1/sboms?' "$tmp/requests"
grep -Fxq "https://api.cracken.tech/v1/analyses/$CRACKEN_PROJECT_ID" "$tmp/requests"
grep -q '^https://api.cracken.tech/v1/findings?' "$tmp/requests"
for field in analysis_id sbom_upload_id status app_url; do
  for suffix in multiline cr trailing; do
    run "$field-$suffix" 1
    [[ ! -s "$GITHUB_OUTPUT" && ! -s "$GITHUB_STEP_SUMMARY" ]]
  done
done
for mode in invalid-status invalid-url; do
  run "$mode" 1
  [[ ! -s "$GITHUB_OUTPUT" && ! -s "$GITHUB_STEP_SUMMARY" ]]
done
run poll-injection 1
if grep -q 'injected' "$GITHUB_OUTPUT"; then echo 'FAIL injected output'; exit 1; fi
[[ ! -s "$GITHUB_STEP_SUMMARY" ]]
run error 1
grep -q 'insufficient_scope: Denied' "$tmp/log"
run leak 1
for severity in critical high medium low; do
  for threshold in critical high medium low; do
    case "$severity:$threshold" in
      critical:*|high:high|high:medium|high:low|medium:medium|medium:low|low:low) expected=3 ;;
      *) expected=0 ;;
    esac
    export FAIL_ON=$threshold
    run "$severity" "$expected"
  done
done
export FAIL_ON=none
run slow 4
run timeout 4
run notready 4
run failed 2
run accepted 2
run partial 5
run unknownpartial 5
run invalidpartial 5
CRACKEN_ALLOW_PARTIAL_FINDINGS=1 run partial 0
run badpage 1
run repeat 1
CRACKEN_PROJECT_ID='' CRACKEN_PRODUCT_ID=11111111-1111-4111-8111-111111111111 run success 0
CRACKEN_PRODUCT_ID=11111111-1111-4111-8111-111111111111 run success 1
WAIT=0 run success 0
[[ ! -s "$GITHUB_STEP_SUMMARY" ]]
WAIT=0 FAIL_ON=high run success 3
CRACKEN_PROJECT_ID='' CRACKEN_PROJECT_SLUG='product name' run success 0
CRACKEN_PROJECT_ID='' VERSION='' CRACKEN_RELEASE_ID=11111111-1111-4111-8111-111111111111 run success 0
SBOM_FILE="$tmp/missing" run success 1
CRACKEN_API_URL=https://example.invalid TIMEOUT=bad run success 1
# Exercise the three auto-detection names outside the repository.
script="$PWD/scripts/upload.sh"
for name in bom.json sbom.cdx.json sample.spdx.json; do
  if [[ "$name" != bom.json ]]; then mv "$tmp/previous.json" "$tmp/$name"; fi
  (cd "$tmp"; unset SBOM_FILE; sh "$script" > "$tmp/log" 2>&1)
  mv "$tmp/$name" "$tmp/previous.json"
  checks=$((checks+1)); echo "ok $checks - auto-detect $name"
done
printf 'PASS: %s scenarios\n' "$checks"
