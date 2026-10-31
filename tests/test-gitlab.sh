#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
mkdir "$tmp/bin" "$tmp/fixtures"
# Extract the actual YAML literal block without requiring a YAML package.
python3 - "$tmp/job.sh" <<'PY'
from pathlib import Path
import sys
source = Path('gitlab/cracken.gitlab-ci.yml').read_text()
block = source.split('  script:\n    - |\n', 1)[1]
assert all(not line.strip() or line.startswith('      ') for line in block.splitlines())
Path(sys.argv[1]).write_text('\n'.join(line[6:] for line in block.splitlines()) + '\n')
PY
for name in upload generate-syft; do
  printf '#!/bin/sh\nprintf "%%s\\n" "%s" >> "$EXECUTED"\n' "$name" > "$tmp/fixtures/$name.sh"
done
cat > "$tmp/bin/curl" <<'CURL'
#!/usr/bin/env bash
set -euo pipefail
auth=0 output= url= accept=0
while (($#)); do
  case "$1" in
    -q|--fail|--silent|--show-error) shift ;;
    --max-time) [[ "$2" == 60 ]]; shift 2 ;;
    -H)
      case "$2" in
        @-)
          [[ "$auth" == 0 && -n "${CRACKEN_REPO_TOKEN:-}" ]]
          [[ "$(cat)" == "Authorization: Bearer $CRACKEN_REPO_TOKEN" ]]
          auth=1 ;;
        'Accept: application/vnd.github.raw+json') accept=1 ;;
        *) exit 99 ;;
      esac
      shift 2 ;;
    -o) output=$2; shift 2 ;;
    https://api.github.com/*) url=$1; shift ;;
    *) exit 99 ;;
  esac
done
[[ "$accept" == 1 && -n "$output" ]]
if [[ -n "${CRACKEN_REPO_TOKEN:-}" ]]; then [[ "$auth" == 1 ]]; else [[ "$auth" == 0 ]]; fi
prefix=https://api.github.com/repos/alexv-mc2/cracken-action/contents/scripts/
case "$url" in
  "${prefix}upload.sh?ref=$CRACKEN_ACTION_SHA") name=upload.sh ;;
  "${prefix}generate-syft.sh?ref=$CRACKEN_ACTION_SHA") name=generate-syft.sh ;;
  *) exit 99 ;;
esac
printf '%s\n' "$name" >> "$REQUESTS"
cp "$FIXTURES/$name" "$output"
CURL
chmod +x "$tmp/bin/curl"
export PATH="$tmp/bin:$PATH" FIXTURES="$tmp/fixtures"
export EXECUTED="$tmp/executed" REQUESTS="$tmp/requests"
export CRACKEN_ACTION_SHA=1111111111111111111111111111111111111111
export VERSION=1.0 CRACKEN_RELEASE_ID=''
upload_hash=$(shasum -a 256 "$FIXTURES/upload.sh" | awk '{print $1}')
generate_hash=$(shasum -a 256 "$FIXTURES/generate-syft.sh" | awk '{print $1}')
checks=0
run() {
  local label=$1 expected=$2 executed=$3 requests=$4 actual=0
  : > "$EXECUTED"
  : > "$REQUESTS"
  sh "$tmp/job.sh" > "$tmp/log" 2>&1 || actual=$?
  if [[ "$actual" != "$expected" ]]; then cat "$tmp/log"; echo "FAIL $label: expected $expected, got $actual"; exit 1; fi
  [[ "$(cat "$EXECUTED")" == "$executed" && "$(cat "$REQUESTS")" == "$requests" ]]
  if [[ -n "${CRACKEN_REPO_TOKEN:-}" ]] && grep -Fq "$CRACKEN_REPO_TOKEN" "$tmp/log"; then echo 'FAIL secret disclosure'; exit 1; fi
  checks=$((checks+1))
  echo "ok $checks - $label (exit $actual)"
}
for token in unset empty set; do
  unset CRACKEN_REPO_TOKEN
  case "$token" in empty) export CRACKEN_REPO_TOKEN='' ;; set) export CRACKEN_REPO_TOKEN=fixture-repo-token ;; esac
  export CRACKEN_SCRIPT_SHA256=$upload_hash CRACKEN_GENERATE_SCRIPT_SHA256=$generate_hash
  CRACKEN_GENERATE=none run "$token token: upload" 0 upload upload.sh
  export CRACKEN_GENERATE=syft
  run "$token token: generation" 0 generate-syft $'upload.sh\ngenerate-syft.sh'
  CRACKEN_ACTION_SHA=invalid run "$token token: invalid commit pin" 1 '' ''
  for bad_hash in '' invalid "$(printf '%064d' 0)"; do
    upload_requests=''
    generate_requests=upload.sh
    # A mismatched digest is detected after download, before execution.
    if [[ ${#bad_hash} == 64 ]]; then
      upload_requests=upload.sh
      generate_requests=$'upload.sh\ngenerate-syft.sh'
    fi
    CRACKEN_SCRIPT_SHA256=$bad_hash run "$token token: bad upload hash [$bad_hash]" 1 '' "$upload_requests"
    CRACKEN_GENERATE_SCRIPT_SHA256=$bad_hash run "$token token: bad generator hash [$bad_hash]" 1 '' "$generate_requests"
  done
done
printf 'PASS: %s GitLab template scenarios\n' "$checks"
