#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
mkdir -p "$tmp/v2/recipes" "$tmp/v3" "$tmp/mixed" "$tmp/v31"
printf '%s' '{"spdxVersion":"SPDX-2.2","externalDocumentRefs":[]}' > "$tmp/v2/image.spdx.json"
printf '%s' '{"spdxVersion":"SPDX-2.2"}' > "$tmp/v2/image.spdx.index.json"
printf '%s' '{"spdxVersion":"SPDX-2.2"}' > "$tmp/v2/recipes/recipe-a.spdx.json"
printf '%s' '{"spdxVersion":"SPDX-2.2"}' > "$tmp/v2/recipes/package-a.spdx.json"
printf '%s' '{"@graph":[{"type":"CreationInfo","specVersion":"3.0.1"}]}' > "$tmp/v3/image.rootfs.spdx.json"
printf '%s' '{"@graph":[{"type":"CreationInfo","specVersion":"3.1.0"}]}' > "$tmp/v31/image.rootfs.spdx.json"
cp "$tmp/v2/image.spdx.json" "$tmp/mixed/"
cp "$tmp/v3/image.rootfs.spdx.json" "$tmp/mixed/"
bash scripts/yocto-pack.sh "$tmp/v2" "$tmp/v2.zip"
python3 - "$tmp/v2.zip" <<'PY'
import sys, zipfile
with zipfile.ZipFile(sys.argv[1]) as z:
    assert set(z.namelist()) == {'image.spdx.json', 'image.spdx.index.json', 'recipes/recipe-a.spdx.json', 'recipes/package-a.spdx.json'}
    assert sum(i.file_size for i in z.infolist()) <= 16*1024*1024
PY
bash scripts/yocto-pack.sh "$tmp/v3" "$tmp/v3.zip"
python3 - "$tmp/v3.zip" <<'PY'
import sys,zipfile
with zipfile.ZipFile(sys.argv[1]) as z: assert z.namelist() == ['image.rootfs.spdx.json']
PY
for case in v31 mixed; do
  if bash scripts/yocto-pack.sh "$tmp/$case" "$tmp/fail.zip" >"$tmp/log" 2>&1; then echo "FAIL: $case accepted"; exit 1; fi
done
python3 - "$tmp/unsafe.tar" <<'PY'
import io,sys,tarfile
with tarfile.open(sys.argv[1],'w') as t:
    data=b'bad'; i=tarfile.TarInfo('../escape'); i.size=len(data); t.addfile(i,io.BytesIO(data))
PY
zstd -q "$tmp/unsafe.tar" -o "$tmp/unsafe.spdx.tar.zst"
if bash scripts/yocto-pack.sh "$tmp/unsafe.spdx.tar.zst" "$tmp/fail.zip" >"$tmp/log" 2>&1; then echo 'FAIL: traversal accepted'; exit 1; fi
grep -qi 'unsafe' "$tmp/log"
# A valid compressed archive follows the same selection rules.
python3 - "$tmp/v2" "$tmp/valid.tar" <<'PYTAR'
import pathlib,sys,tarfile
root=pathlib.Path(sys.argv[1])
with tarfile.open(sys.argv[2], 'w') as t:
    for p in root.rglob('*'):
        if p.is_file(): t.add(p, arcname=str(p.relative_to(root)))
PYTAR
zstd -q "$tmp/valid.tar" -o "$tmp/valid.spdx.tar.zst"
bash scripts/yocto-pack.sh "$tmp/valid.spdx.tar.zst" "$tmp/from-tar.zip"
python3 - "$tmp/from-tar.zip" <<'PY'
import sys,zipfile
with zipfile.ZipFile(sys.argv[1]) as z: assert len(z.namelist()) == 4
PY
printf 'PASS: 6 Yocto packaging scenarios\n'
