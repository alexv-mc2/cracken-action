#!/bin/sh
# Optional local generation, followed by the unchanged public API uploader.
set +x
set -eu
umask 077
fail() { printf '%s\n' "$1" >&2; exit 1; }
script_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
case "${CRACKEN_GENERATE:-none}" in
  none) exec sh "$script_dir/upload.sh" ;;
  syft) ;;
  *) fail 'CRACKEN_GENERATE must be none or syft.' ;;
esac
[ -z "${SBOM_FILE:-}" ] || fail 'Do not combine SBOM_FILE (sbom-file) with generate: syft.'
default_version=1.55.0
# Official release asset fetched and hashed on 2026-10-29; also matches GitHub asset digest.
pinned_checksums_sha256=aba5ac8ee870bb93fd3b2058471ffe7e57492ba673b5e0bcbfca92006c2f4dc7
version=${SYFT_VERSION:-$default_version}
printf '%s\n' "$version" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+$' || fail 'SYFT_VERSION must be an exact stable version, e.g. 1.55.0 (without v).'
case "${SYFT_INSECURE_SKIP_PIN:-false}" in
  true|false) ;; *) fail 'SYFT_INSECURE_SKIP_PIN must be true or false.' ;;
esac
if [ "$version" != "$default_version" ]; then
  [ "${SYFT_INSECURE_SKIP_PIN:-false}" = true ] || fail 'No pinned checksums digest for this SYFT_VERSION. Use the default or explicitly set SYFT_INSECURE_SKIP_PIN=true (insecure).'
  printf '%s\n' 'WARNING: custom syft version has no repository-pinned checksums digest.' >&2
fi
case "$(uname -s)" in
  Linux) os=linux ;; Darwin) os=darwin ;; *) fail 'syft generation supports only linux/darwin on amd64/arm64.' ;;
esac
case "$(uname -m)" in
  x86_64|amd64) arch=amd64 ;; arm64|aarch64) arch=arm64 ;; *) fail 'syft generation supports only linux/darwin on amd64/arm64.' ;;
esac
for tool in jq mktemp; do
  command -v "$tool" >/dev/null 2>&1 || fail "Required tool is missing: $tool"
done
scan_path=${SCAN_PATH:-.}
[ -d "$scan_path" ] || fail 'SCAN_PATH must be a readable directory.'
tmp=$(mktemp -d "${TMPDIR:-/tmp}/cracken-syft.XXXXXXXX")
tmp=$(CDPATH='' cd -- "$tmp" && pwd)
# Keep the SBOM for subsequent archive steps; remove downloads and partial results.
complete=false
cleanup() {
  rm -rf "$tmp/download"
  if [ "$complete" != true ]; then rm -rf "$tmp"; fi
}
trap cleanup 0
trap 'exit 1' HUP INT TERM
syft_bin=
if command -v syft >/dev/null 2>&1; then
  installed_version=$(syft version -o json 2>/dev/null | jq -er '.version | strings' 2>/dev/null) || installed_version=
  if [ "$installed_version" = "$version" ]; then syft_bin=$(command -v syft); fi
fi
if [ -z "$syft_bin" ]; then
  for tool in curl tar; do
    command -v "$tool" >/dev/null 2>&1 || fail "Required tool is missing: $tool"
  done
  if command -v sha256sum >/dev/null 2>&1; then
    digest() { sha256sum "$1" | awk '{print $1}'; }
  elif command -v shasum >/dev/null 2>&1; then
    digest() { shasum -a 256 "$1" | awk '{print $1}'; }
  else
    fail 'Install sha256sum or shasum.'
  fi
  base=https://github.com/anchore/syft/releases/download
  if [ -n "${SYFT_DOWNLOAD_BASE:-}" ]; then
    # Offline fixture mirror only: never allow a CI variable to redirect production downloads.
    [ "${CRACKEN_SYFT_TEST_MODE:-}" = 1 ] || fail 'SYFT_DOWNLOAD_BASE is only available in offline tests.'
    case "$SYFT_DOWNLOAD_BASE" in file:///*) base=${SYFT_DOWNLOAD_BASE%/} ;; *) fail 'The test mirror must be an absolute file:// URL.' ;; esac
  fi
  mkdir "$tmp/download"
  checksums="syft_${version}_checksums.txt"
  archive="syft_${version}_${os}_${arch}.tar.gz"
  curl -q --fail --silent --show-error --location --proto '=https,file' --proto-redir '=https' --connect-timeout 15 --max-time 120 \
    "$base/v$version/$checksums" -o "$tmp/download/checksums.txt"
  if [ "$version" = "$default_version" ]; then
    [ "$(digest "$tmp/download/checksums.txt")" = "$pinned_checksums_sha256" ] || fail 'Pinned syft checksums-file SHA-256 mismatch.'
  fi
  expected=$(awk -v name="$archive" '$2 == name {print $1}' "$tmp/download/checksums.txt")
  printf '%s\n' "$expected" | grep -Eq '^[0-9a-f]{64}$' && [ "${#expected}" -eq 64 ] || fail 'Missing or invalid syft archive checksum.'
  curl -q --fail --silent --show-error --location --proto '=https,file' --proto-redir '=https' --connect-timeout 15 --max-time 120 \
    "$base/v$version/$archive" -o "$tmp/download/syft.tar.gz"
  [ "$(digest "$tmp/download/syft.tar.gz")" = "$expected" ] || fail 'syft archive SHA-256 mismatch.'
  # Extract only the executable, never arbitrary archive paths.
  tar -xzf "$tmp/download/syft.tar.gz" -C "$tmp/download" syft
  syft_bin=$tmp/download/syft
  installed_version=$("$syft_bin" version -o json 2>/dev/null | jq -er '.version | strings' 2>/dev/null) || installed_version=
  [ "$installed_version" = "$version" ] || fail 'Downloaded syft does not report the pinned version.'
fi
sbom_path=$tmp/cracken-sbom.cdx.json
# Ignore repository/user syft configuration that could enable source-content capture.
printf '{}\n' > "$tmp/syft.yaml"
set -- scan "dir:$scan_path" -o "cyclonedx-json=$sbom_path" --exclude './.git' --config "$tmp/syft.yaml" --enrich none
source_name=${GITHUB_REPOSITORY:-${CI_PROJECT_PATH:-}}
source_version=${GITHUB_SHA:-${CI_COMMIT_SHA:-}}
[ -z "$source_name" ] || set -- "$@" --source-name "$source_name"
[ -z "$source_version" ] || set -- "$@" --source-version "$source_version"
# Disable update checks and remote enrichment; package metadata licences only.
SYFT_CHECK_FOR_APP_UPDATE=false SYFT_GOLANG_SEARCH_REMOTE_LICENSES=false \
  SYFT_JAVA_USE_NETWORK=false SYFT_JAVASCRIPT_SEARCH_REMOTE_LICENSES=false \
  SYFT_PYTHON_SEARCH_REMOTE_LICENSES=false SYFT_FILE_CONTENT_GLOBS='' \
  SYFT_LICENSE_CONTENT=none "$syft_bin" "$@" > "$tmp/generation.log" 2>&1 || fail 'syft generation failed. Check the scan path and package metadata.'
rm -f "$tmp/generation.log" "$tmp/syft.yaml"
[ -s "$sbom_path" ] || fail 'syft did not produce an SBOM.'
# mktemp paths must be single-line before writing GitHub's line-based output.
case "$sbom_path" in *'
'*|*''*) fail 'The temporary SBOM path must be single-line.' ;; esac
[ -z "${GITHUB_OUTPUT:-}" ] || printf 'sbom-path=%s\n' "$sbom_path" >> "$GITHUB_OUTPUT"
[ -z "${CRACKEN_SBOM_PATH_FILE:-}" ] || printf '%s\n' "$sbom_path" > "$CRACKEN_SBOM_PATH_FILE"
complete=true
SBOM_FILE=$sbom_path sh "$script_dir/upload.sh"
