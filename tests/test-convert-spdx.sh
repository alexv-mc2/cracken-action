#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
mkdir "$tmp/bin"
printf 'fixture' > "$tmp/input file.yaml"
cat > "$tmp/bin/pyspdxtools" <<'TOOL'
#!/bin/sh
[ "$1" = '-i' ] && [ "$3" = '-o' ] || exit 2
printf '{"spdxVersion":"%s","name":"fixture"}\n' "${FAKE_VERSION:-SPDX-2.3}" > "$4"
TOOL
chmod +x "$tmp/bin/pyspdxtools"
export PATH="$tmp/bin:$PATH"
sh scripts/convert-spdx.sh "$tmp/input file.yaml" "$tmp/output.spdx.json"
python3 - "$tmp/output.spdx.json" <<'PY'
import json, sys
assert json.load(open(sys.argv[1]))['spdxVersion'] == 'SPDX-2.3'
PY
if FAKE_VERSION=SPDX-3.0.1 sh scripts/convert-spdx.sh "$tmp/input file.yaml" "$tmp/rejected.json" > "$tmp/log" 2>&1; then echo 'FAIL: SPDX 3 accepted'; exit 1; fi
grep -q '2.2 or 2.3' "$tmp/log"
[ ! -e "$tmp/rejected.json" ]
rm "$tmp/bin/pyspdxtools"
if PATH="$tmp/bin:/usr/bin:/bin" sh scripts/convert-spdx.sh "$tmp/input file.yaml" "$tmp/missing.json" > "$tmp/log" 2>&1; then echo 'FAIL: missing tool accepted'; exit 1; fi
grep -q pyspdxtools "$tmp/log"
printf 'PASS: 3 SPDX conversion scenarios\n'
