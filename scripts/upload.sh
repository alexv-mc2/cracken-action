#!/bin/sh
# Requires curl >= 7.76, jq, and sha256sum or shasum.
# --- crAcken upload begin ---
# Disable tracing before reading credentials, including in CI shells using -x.
set +x
set -eu
umask 077
fail() { printf '%s
' "$1" >&2; exit 1; }
for tool in curl jq mktemp date; do
  command -v "$tool" >/dev/null 2>&1 || fail "Required tool is missing: $tool"
done
# Inputs are environment variables so CI expressions never become shell code.
[ -z "${CRACKEN_PRODUCT_ID:-}" ] || {
  [ -z "${CRACKEN_PROJECT_ID:-}" ] || fail 'Choose project or product, not both.'
  CRACKEN_PROJECT_ID=$CRACKEN_PRODUCT_ID
}
WAIT=${WAIT:-0}
case "$WAIT" in 1|true) WAIT=1 ;; 0|false) WAIT=0 ;; *) fail 'WAIT must be true/false or 1/0.' ;; esac
FAIL_ON=${FAIL_ON:-none}
case "$FAIL_ON" in none) ;; critical|high|medium|low) WAIT=1 ;; *) fail 'FAIL_ON must be none, critical, high, medium or low.' ;; esac
TIMEOUT=${TIMEOUT:-900}
case "$TIMEOUT" in ''|*[!0-9]*|0|0*) fail 'TIMEOUT must be a positive integer in seconds.' ;; esac
[ "${#TIMEOUT}" -le 6 ] && [ "$TIMEOUT" -le 86400 ] || fail 'TIMEOUT must be at most 86400 seconds.'
deadline=$(($(date +%s) + TIMEOUT))
timed_out() { printf '%s\n' 'The upload/analysis timeout was reached.' >&2; exit 4; }
pause() {
  remaining=$((deadline - $(date +%s)))
  [ "$remaining" -gt 0 ] || timed_out
  if [ "$remaining" -lt 5 ]; then sleep "$remaining"; timed_out; fi
  sleep 5
}
if [ -z "${SBOM_FILE:-}" ]; then
  if [ -f bom.json ]; then SBOM_FILE=bom.json
  elif [ -f sbom.cdx.json ]; then SBOM_FILE=sbom.cdx.json
  else
    for candidate in ./*.spdx.json; do
      [ -f "$candidate" ] || continue
      [ -z "${SBOM_FILE:-}" ] || fail 'Multiple SPDX files found; set SBOM_FILE explicitly.'
      SBOM_FILE=$candidate
    done
  fi
fi
[ -n "${SBOM_FILE:-}" ] || fail 'Set SBOM_FILE to a readable JSON file.'

case "$SBOM_FILE" in /*) ;; *) SBOM_FILE=./$SBOM_FILE ;; esac
[ -r "$SBOM_FILE" ] || fail 'Set SBOM_FILE to a readable JSON file.'
# Count the file's raw bytes, including any BOM and surrounding whitespace.
[ "$(wc -c < "$SBOM_FILE")" -le 10485760 ] || fail 'The SBOM exceeds the 10 MiB limit for a single JSON file, including SPDX 3.'
curl_version=$(curl --version | awk 'NR == 1 { print $2 }')
printf '%s
' "$curl_version" | awk -F. '{ exit !($1 > 7 || ($1 == 7 && $2 >= 76)) }' || fail 'curl 7.76 or later is required.'
CRACKEN_API_URL=${CRACKEN_API_URL:-https://api.cracken.tech}
[ -n "${CRACKEN_API_KEY:-}" ] || fail 'Set CRACKEN_API_KEY as a CI secret.'
[ "${#CRACKEN_API_KEY}" -eq 60 ] || fail 'The API key is not valid.'
printf '%s
' "$CRACKEN_API_KEY" | grep -Eq '^crk_[a-z2-7]{12}_[A-Za-z0-9_-]{43}$' || fail 'The API key is not valid.'
case "$CRACKEN_API_URL" in
  *'?'*|*'#'*|*'@'*|*'%'*|*' '*|*'
'*) fail 'Use an API base URL without credentials, query parameters, or fragments.' ;;
esac
printf '%s
' "$CRACKEN_API_URL" | grep -Eiq 'crk_|api_key|access_token' && fail 'Credentials must not appear in the API URL.'
[ -z "$(printf '%s' "$CRACKEN_API_URL" | LC_ALL=C tr -d '[:alnum:]:/._~[]-')" ] || fail 'The API URL contains characters that are not allowed.'
case "$CRACKEN_API_URL" in
  'https:'//*) [ -n "${CRACKEN_API_URL#https://}" ] || fail 'The API URL is not valid.' ;;
  'http:'//*) ;;
  *) fail 'Use HTTPS, or HTTP on localhost for local testing.' ;;
esac
authority=${CRACKEN_API_URL#*://}
authority=${authority%%/*}
case "$CRACKEN_API_URL" in
  'https:'//*) printf '%s
' "$authority" | grep -Eq '^[A-Za-z0-9.-]+(:[0-9]+)?$' || fail 'The API URL host is not valid.' ;;
  'http:'//*) printf '%s
' "$authority" | grep -Eq '^(localhost|127[.]0[.]0[.]1|[[]::1[]])(:[0-9]+)?$' || fail 'HTTP is allowed only on localhost.' ;;
esac
printf '%s
' "$CRACKEN_API_URL" | LC_ALL=C grep -q '[[:cntrl:]]' && fail 'The API URL is not valid.'
api_url=${CRACKEN_API_URL%/}
uuid_pattern='^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$'
validate_uuid() { [ "${#1}" -eq 36 ] || fail 'The target identifier is not valid.'; printf '%s\n' "$1" | grep -Eq "$uuid_pattern" || fail 'The target identifier is not valid.'; }
encode() { printf '%s' "$1" | jq -sRr @uri; }
if [ -n "${CRACKEN_RELEASE_ID:-}" ]; then
  [ -z "${CRACKEN_PROJECT_ID:-}${CRACKEN_PROJECT_SLUG:-}${VERSION:-}" ] || fail 'Use release_id alone, or a product with version.'
  validate_uuid "$CRACKEN_RELEASE_ID"
  target="release_id=$CRACKEN_RELEASE_ID"
else
  [ -n "${VERSION:-}" ] || fail 'Set VERSION.'
  case "$VERSION${CRACKEN_PROJECT_SLUG:-}" in *crk_*) fail 'Credentials must not appear in the target.' ;; esac
  VERSION=$(printf '%s' "$VERSION" | jq -sRr 'sub("^[[:space:]]+"; "") | sub("[[:space:]]+$"; "")')
  printf '%s' "$VERSION" | jq -sRe 'length >= 1 and length <= 100' >/dev/null || fail 'VERSION must contain 1 to 100 characters after trimming.'
  if [ -n "${CRACKEN_PROJECT_ID:-}" ]; then
    [ -z "${CRACKEN_PROJECT_SLUG:-}" ] || fail 'Choose project_id or project_slug.'
    validate_uuid "$CRACKEN_PROJECT_ID"
    target="project_id=$CRACKEN_PROJECT_ID"
  else
    [ -n "${CRACKEN_PROJECT_SLUG:-}" ] || fail 'Set CRACKEN_PROJECT_ID or CRACKEN_PROJECT_SLUG.'
    target="project_slug=$(encode "$CRACKEN_PROJECT_SLUG")"
  fi
  target="$target&version=$(encode "$VERSION")"
fi
content_type=$(jq -er 'if .bomFormat == "CycloneDX" then "application/vnd.cyclonedx+json" elif (.spdxVersion // "" | startswith("SPDX-2.")) or has("@context") then "application/spdx+json" else error("format") end' "$SBOM_FILE" 2>/dev/null) || fail 'Use a CycloneDX or SPDX JSON SBOM.'
if command -v sha256sum >/dev/null 2>&1; then
  digest() { sha256sum | awk '{ print $1 }'; }
elif command -v shasum >/dev/null 2>&1; then
  digest() { shasum -a 256 | awk '{ print $1 }'; }
else
  fail 'Install sha256sum or shasum.'
fi
sbom_digest=$(digest < "$SBOM_FILE")
idempotency_key="ci1-$(printf '%s
%s
%s' "$sbom_digest" "$target" "ci-upload/1" | digest)"
response_dir=$(mktemp -d)
trap 'rm -rf "$response_dir"' 0
trap 'exit 1' HUP INT TERM
accept_409=0
# Report the API error code and message from the JSON body (fixed text, never the key).
api_fail() {
  detail=$(jq -r 'if (.error.code | type) == "string" then .error.code + ": " + ((.error.message // "") | tostring) else empty end' "$response_dir/body" 2>/dev/null | LC_ALL=C tr -d '[:cntrl:]' | cut -c1-300) || detail=
  case "$detail" in *crk_*) detail= ;; esac
  if [ -n "$detail" ]; then fail "The API returned HTTP $http_status ($detail)."; fi
  fail "The API returned HTTP $http_status."
}
request() {
  method=$1
  request_url=$2
  remaining=$((deadline - $(date +%s)))
  [ "$remaining" -gt 0 ] || timed_out
  request_timeout=120
  [ "$remaining" -ge 120 ] || request_timeout=$remaining
  # curl's retry budget excludes the final attempt: reserve its max-time.
  retry_time=$((remaining - request_timeout))
  retries=3
  [ "$retry_time" -gt 0 ] || retries=0
  curl_exit=0
  if [ "$method" = POST ]; then
    http_status=$(printf 'Authorization: Bearer %s
' "$CRACKEN_API_KEY" | curl -q -g --silent --show-error --fail-with-body --retry "$retries" --retry-delay 2 --retry-max-time "$retry_time" --connect-timeout 15 --max-time "$request_timeout" -H @- -H "Content-Type: $content_type" -H "Idempotency-Key: $idempotency_key" -H 'X-Cracken-Client: ci-upload/1' --data-binary "@$SBOM_FILE" --output "$response_dir/body" --write-out '%{http_code}' "$request_url" 2>"$response_dir/error") || curl_exit=$?
  else
    http_status=$(printf 'Authorization: Bearer %s
' "$CRACKEN_API_KEY" | curl -q -g --silent --show-error --fail-with-body --retry "$retries" --retry-delay 2 --retry-max-time "$retry_time" --connect-timeout 15 --max-time "$request_timeout" -H @- --output "$response_dir/body" --write-out '%{http_code}' "$request_url" 2>"$response_dir/error") || curl_exit=$?
  fi
  case "$curl_exit" in
    0|22) ;;
    28) timed_out ;;
    *) fail 'The API request failed. Check the network connection and the API URL, then try again.' ;;
  esac
  case "$http_status" in 2[0-9][0-9]) ;; 409) [ "$accept_409" = 1 ] || api_fail ;; *) api_fail ;; esac
}
request POST "$api_url/v1/sboms?$target"
# Validate raw JSON strings before command substitution can strip trailing newlines.
api_string() {
  jq -er --arg field "$1" '
    .[$field] | select(type == "string") |
    select(explode | all(. >= 32 and . != 127))
  ' "$response_dir/body" 2>/dev/null || fail "The API returned an invalid $1."
}
validate_status() {
  case "$1" in queued|running|succeeded|failed|accepted) ;; *) fail 'The API returned an invalid analysis status.' ;; esac
}
analysis_id=$(api_string analysis_id)
validate_uuid "$analysis_id"
upload_id=$(api_string sbom_upload_id)
validate_uuid "$upload_id"
status=$(api_string status)
validate_status "$status"
# app_url is optional, but supplied URLs must be HTTPS and single-line.
app_url=$(jq -er '
  (if .app_url == null then "" else .app_url end) | select(type == "string") |
  select(explode | all(. >= 32 and . != 127)) | . + "."
' "$response_dir/body" 2>/dev/null) || fail 'Invalid app URL.'
app_url=${app_url%.}
case "$app_url" in
  '') ;;
  https://*)
    printf '%s\n' "$app_url" | LC_ALL=C grep -Eq '^https://[A-Za-z0-9.-]+(:[0-9]+)?([/?#][^[:space:]<>]*)?$' || fail 'Invalid app URL.'
    case "$app_url" in *crk_*) fail 'Invalid app URL.' ;; esac ;;
  *) fail 'Invalid app URL.' ;;
esac
# Validate the entire upload response before writing any GitHub output.
output() { [ -z "${GITHUB_OUTPUT:-}" ] || printf '%s=%s\n' "$1" "$2" >> "$GITHUB_OUTPUT"; }
output analysis-id "$analysis_id"
output upload-id "$upload_id"
output app-url "$app_url"
output analysis-status "$status"
printf 'Analysis: %s\n' "$analysis_id"
if [ "$WAIT" = 1 ]; then
  finished=0
  match_partial=unknown
  while [ "$(date +%s)" -lt "$deadline" ]; do
    request GET "$api_url/v1/analyses/$analysis_id"
    status=$(api_string status)
    validate_status "$status"
    case "$status" in
      succeeded) output analysis-status "$status"; finished=1; match_partial=$(jq -r 'if .match_partial == false then "false" else "unknown" end' "$response_dir/body" 2>/dev/null) || match_partial=unknown; break ;;
      failed|accepted) output analysis-status "$status"; printf '%s\n' 'Analysis failed or was archived without analysis.' >&2; exit 2 ;;
      queued|running) output analysis-status "$status"; pause ;;
      *) fail 'The API returned an invalid analysis status.' ;;
    esac
  done
  [ "$finished" = 1 ] || timed_out
  counts='{"critical":0,"high":0,"medium":0,"low":0,"none":0,"unknown":0}'
  cursor=
  : > "$response_dir/cursors"
  while :; do
    findings_url="$api_url/v1/findings?analysis_id=$analysis_id&limit=500"
    [ -z "$cursor" ] || findings_url="$findings_url&cursor=$(encode "$cursor")"
    accept_409=1
    request GET "$findings_url"
    accept_409=0
    if [ "$http_status" = 409 ]; then
      error_code=$(jq -er '.error.code | strings' "$response_dir/body" 2>/dev/null) || fail 'The API returned an unexpected findings answer.'
      case "$error_code" in
        analysis_not_ready) pause; continue ;;
        analysis_failed) printf '%s\n' 'Analysis failed, so there are no findings to read.' >&2; exit 2 ;;
        *) api_fail ;;
      esac
    fi
    jq -e --arg id "$analysis_id" '
      .analysis_id == $id and (.data | type == "array") and
      (has("next_cursor")) and (.next_cursor == null or (.next_cursor | type == "string" and length > 0)) and
      all(.data[]; .severity.label as $s | ["critical","high","medium","low","none","unknown"] | index($s) != null)
    ' "$response_dir/body" >/dev/null 2>&1 || fail 'The API response did not contain valid findings.'
    counts=$(jq -c --argjson counts "$counts" 'reduce .data[] as $f ($counts; .[$f.severity.label] += 1)' "$response_dir/body")
    cursor=$(jq -r '.next_cursor // empty' "$response_dir/body")
    [ -n "$cursor" ] || break
    # Store encoded cursors: opaque values may contain line breaks.
    encoded_cursor=$(encode "$cursor")
    grep -Fxq "$encoded_cursor" "$response_dir/cursors" && fail 'The API repeated a findings cursor.'
    printf '%s\n' "$encoded_cursor" >> "$response_dir/cursors"
  done
  for severity in critical high medium low none unknown; do
    count=$(printf '%s' "$counts" | jq -r --arg severity "$severity" '.[$severity]')
    case "$count" in ''|*[!0-9]*) fail 'The API returned an invalid findings count.' ;; esac
    output "$severity" "$count"
    [ -z "${GITHUB_STEP_SUMMARY:-}" ] || printf '%s: %s\n\n' "$severity" "$count" >> "$GITHUB_STEP_SUMMARY"
  done
  if [ "$match_partial" != false ]; then
    printf '%s\n' 'Matching coverage is incomplete or not confirmed. An empty or short findings list does not mean the product is clean.' >&2
    if [ "${CRACKEN_ALLOW_PARTIAL_FINDINGS:-0}" != 1 ]; then
      printf '%s\n' 'The build is stopped. Set CRACKEN_ALLOW_PARTIAL_FINDINGS=1 to accept incomplete coverage.' >&2
      exit 5
    fi
  fi
  if [ "$FAIL_ON" != none ]; then
    triggered=$(printf '%s' "$counts" | jq -r --arg threshold "$FAIL_ON" '
      ["critical","high","medium","low"] as $levels |
      ($levels | index($threshold)) as $rank |
      . as $counts | [$levels[:$rank+1][] | $counts[.]] | add > 0')
    if [ "$triggered" = true ]; then printf '%s\n' 'Findings reached the configured severity threshold.' >&2; exit 3; fi
  fi
  printf '%s\n' 'Analysis succeeded and findings are readable.'
fi
# --- crAcken upload end ---
