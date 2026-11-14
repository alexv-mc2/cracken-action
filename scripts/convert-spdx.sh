#!/bin/sh
# Convert an SPDX 2.2/2.3 document with the external SPDX tools CLI.
set -eu

fail() { printf '%s\n' "convert-spdx: $*" >&2; exit 1; }
[ "$#" -eq 2 ] || fail 'Usage: convert-spdx.sh INPUT OUTPUT.json'
input=$1
output=$2
[ -f "$input" ] && [ -r "$input" ] || fail 'Input must be a readable file.'
[ "$input" != "$output" ] || fail 'Input and output paths must differ.'
command -v pyspdxtools >/dev/null 2>&1 || fail 'pyspdxtools is required; install the external spdx-tools package.'
command -v jq >/dev/null 2>&1 || fail 'jq is required to check the converted SPDX version.'
tmp=$(mktemp -d "${TMPDIR:-/tmp}/cracken-convert.XXXXXXXX") || fail 'Cannot create temporary directory.'
trap 'rm -rf "$tmp"' EXIT HUP INT TERM
# The extension determines the output format for pyspdxtools.
if ! pyspdxtools -i "$input" -o "$tmp/converted.spdx.json"; then
  fail 'Conversion failed. Only valid SPDX 2.2 or 2.3 input is supported; SPDX 3 is not supported.'
fi
if ! jq -e 'type == "object" and (.spdxVersion == "SPDX-2.2" or .spdxVersion == "SPDX-2.3")' "$tmp/converted.spdx.json" >/dev/null 2>&1; then
  fail 'Converted document must be SPDX 2.2 or 2.3; SPDX 3 is not supported.'
fi
cp "$tmp/converted.spdx.json" "$output" || fail 'Cannot write output file.'
