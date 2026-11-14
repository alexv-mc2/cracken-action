#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
checks=0
pack() {
  local label=$1 input=$2 output=$3 count=$4
  if ! bash scripts/yocto-pack.sh "$input" "$output" >"$tmp/log" 2>&1; then
    cat "$tmp/log"; echo "FAIL: $label"; exit 1
  fi
  grep -Fxq "Packaged $count SPDX document(s) into $output" "$tmp/log"
  checks=$((checks+1)); echo "ok $checks - $label"
}
refuse() {
  local label=$1 input=$2 message=$3
  if bash scripts/yocto-pack.sh "$input" "$tmp/refused.zip" >"$tmp/log" 2>&1; then
    echo "FAIL: $label accepted"; exit 1
  fi
  if ! grep -Fq "yocto-pack: $message" "$tmp/log"; then
    cat "$tmp/log"; echo "FAIL: $label diagnostic"; exit 1
  fi
  [[ ! -e "$tmp/refused.zip" ]]
  checks=$((checks+1)); echo "ok $checks - $label"
}
mkdir -p "$tmp/v2/recipes" "$tmp/v3" "$tmp/mixed" "$tmp/v31" "$tmp/deploy" "$tmp/outside" "$tmp/two-roots"
printf '%s' '{"spdxVersion":"SPDX-2.2","externalDocumentRefs":[]}' > "$tmp/v2/image.spdx.json"
printf '%s' '{"spdxVersion":"SPDX-2.2"}' > "$tmp/v2/image.spdx.index.json"
printf '%s' '{"spdxVersion":"SPDX-2.2"}' > "$tmp/v2/recipes/recipe-a.spdx.json"
printf '%s' '{"spdxVersion":"SPDX-2.2"}' > "$tmp/v2/recipes/package-a.spdx.json"
printf '%s' '{"@context":"https://spdx.org/rdf/3.0.1/spdx-context.jsonld","@graph":[{"type":"CreationInfo","specVersion":"3.0.1"}]}' > "$tmp/v3/image.rootfs.spdx.json"
printf '%s' '{"@context":"https://spdx.org/rdf/3.1.0/spdx-context.jsonld","@graph":[{"type":"CreationInfo","specVersion":"3.1.0"}]}' > "$tmp/v31/image.rootfs.spdx.json"
cp "$tmp/v2/image.spdx.json" "$tmp/mixed/"
cp "$tmp/v3/image.rootfs.spdx.json" "$tmp/mixed/"
pack 'SPDX 2 directory includes the document set' "$tmp/v2" "$tmp/v2.zip" 4
python3 - "$tmp/v2.zip" <<'PY'
import sys, zipfile
with zipfile.ZipFile(sys.argv[1]) as z:
    assert set(z.namelist()) == {'image.spdx.json', 'image.spdx.index.json', 'recipes/recipe-a.spdx.json', 'recipes/package-a.spdx.json'}
    assert sum(i.file_size for i in z.infolist()) <= 16*1024*1024
PY
pack 'SPDX 3 directory selects one root' "$tmp/v3" "$tmp/v3.zip" 1
python3 - "$tmp/v3.zip" <<'PY'
import sys,zipfile
with zipfile.ZipFile(sys.argv[1]) as z: assert z.namelist() == ['image.rootfs.spdx.json']
PY
refuse 'SPDX 3.1' "$tmp/v31" 'SPDX 3.1.0 is not supported; use SPDX 3.0.0 or 3.0.1'
refuse 'mixed SPDX versions' "$tmp/mixed" 'mixed SPDX 2 and SPDX 3 documents are not supported'

# The timestamped root and IMAGE_LINK_NAME refer to the same document.
cp "$tmp/v3/image.rootfs.spdx.json" "$tmp/deploy/image-20261114.rootfs.spdx.json"
ln -s image-20261114.rootfs.spdx.json "$tmp/deploy/image.rootfs.spdx.json"
pack 'deploy root plus IMAGE_LINK_NAME counts once' "$tmp/deploy" "$tmp/deploy.zip" 1
python3 - "$tmp/deploy.zip" "$tmp/v3/image.rootfs.spdx.json" <<'PY'
from pathlib import Path
import sys, zipfile
with zipfile.ZipFile(sys.argv[1]) as archive:
    assert len(archive.namelist()) == 1
    assert archive.read(archive.namelist()[0]) == Path(sys.argv[2]).read_bytes()
PY
ln -s ../v3/image.rootfs.spdx.json "$tmp/outside/image.rootfs.spdx.json"
refuse 'directory symlink outside input' "$tmp/outside" 'unsafe symlink in input:'
cp "$tmp/v3/image.rootfs.spdx.json" "$tmp/two-roots/first.rootfs.spdx.json"
cp "$tmp/v3/image.rootfs.spdx.json" "$tmp/two-roots/second.rootfs.spdx.json"
refuse 'two different real rootfs files' "$tmp/two-roots" 'SPDX 3 requires exactly one complete *.rootfs.spdx.json'

python3 - "$tmp" <<'PY'
import io, pathlib, sys, tarfile
root = pathlib.Path(sys.argv[1])
for label, name in [('parent', '../escape.spdx.json'), ('absolute', '/escape.spdx.json')]:
    with tarfile.open(root / (label + '.tar'), 'w') as archive:
        data = b'{"spdxVersion":"SPDX-2.2"}'
        entry = tarfile.TarInfo(name)
        entry.size = len(data)
        archive.addfile(entry, io.BytesIO(data))
for label, kind in [('symlink', tarfile.SYMTYPE), ('hardlink', tarfile.LNKTYPE)]:
    with tarfile.open(root / (label + '.tar'), 'w') as archive:
        entry = tarfile.TarInfo('image.spdx.json')
        entry.type = kind
        entry.linkname = 'target.spdx.json'
        archive.addfile(entry)
PY
for case in parent absolute symlink hardlink; do
  zstd -q "$tmp/$case.tar" -o "$tmp/$case.spdx.tar.zst"
done
refuse 'parent traversal tar path' "$tmp/parent.spdx.tar.zst" 'unsafe archive path: ../escape.spdx.json'
refuse 'absolute tar path' "$tmp/absolute.spdx.tar.zst" 'unsafe archive path: /escape.spdx.json'
refuse 'symlink in tar' "$tmp/symlink.spdx.tar.zst" 'unsafe archive link: image.spdx.json'
refuse 'hardlink in tar' "$tmp/hardlink.spdx.tar.zst" 'unsafe archive link: image.spdx.json'
# A valid compressed archive follows the same selection rules.
python3 - "$tmp/v2" "$tmp/valid.tar" <<'PYTAR'
import pathlib,sys,tarfile
root=pathlib.Path(sys.argv[1])
with tarfile.open(sys.argv[2], 'w') as t:
    for p in root.rglob('*'):
        if p.is_file(): t.add(p, arcname=str(p.relative_to(root)))
PYTAR
zstd -q "$tmp/valid.tar" -o "$tmp/valid.spdx.tar.zst"
pack 'compressed SPDX archive' "$tmp/valid.spdx.tar.zst" "$tmp/from-tar.zip" 4
ln -s valid.spdx.tar.zst "$tmp/image.spdx.tar.zst"
pack 'top-level archive symlink' "$tmp/image.spdx.tar.zst" "$tmp/from-link.zip" 4
python3 - "$tmp/from-tar.zip" "$tmp/from-link.zip" <<'PY'
import sys,zipfile
with zipfile.ZipFile(sys.argv[1]) as original, zipfile.ZipFile(sys.argv[2]) as linked:
    assert len(original.namelist()) == 4
    assert original.namelist() == linked.namelist()
    assert all(original.read(name) == linked.read(name) for name in original.namelist())
PY

# Exercise the packed limit independently of the uncompressed and entry limits:
# long tar member names are repeated in ZIP headers, even for tiny SPDX bodies.
python3 - "$tmp/packed.tar" <<'PY'
import io, sys, tarfile
data = b'{"spdxVersion":"SPDX-2.2"}'
with tarfile.open(sys.argv[1], 'w') as archive:
    for index in range(150):
        entry = tarfile.TarInfo(str(index) + 'x' * 60000 + '.spdx.json')
        entry.size = len(data)
        archive.addfile(entry, io.BytesIO(data))
assert 150 * len(data) < 16 * 1024 * 1024
PY
zstd -q "$tmp/packed.tar" -o "$tmp/packed.spdx.tar.zst"
refuse 'packed ZIP over 16 MiB' "$tmp/packed.spdx.tar.zst" 'ZIP exceeds the 16 MiB packed limit'

# Match the server's context handling: strings, arrays and object values, with
# an exact supported URL, no unsupported SPDX contexts and a depth bound of four.
python3 - "$tmp" <<'PY'
import json, pathlib, sys
root = pathlib.Path(sys.argv[1])
url = 'https://spdx.org/rdf/3.0.1/spdx-context.jsonld'
contexts = {
    'context-300': 'http://spdx.org/rdf/3.0.0/spdx-context.jsonld',
    'context-array': ['https://example.org/context', url],
    'context-object': {'@vocab': url.upper()},
    'context-depth4': [[[[url]]]],
    'context-missing': None,
    'context-unrelated': 'https://example.org/context',
    'context-31': 'https://spdx.org/rdf/3.1.0/spdx-context.jsonld',
    'context-mixed': [url, 'https://spdx.org/rdf/3.1.0/spdx-context.jsonld'],
    'context-suffix': url + '/extra',
    'context-depth5': [[[[[url]]]]],
}
for label, context in contexts.items():
    folder = root / label
    folder.mkdir()
    version = '3.0.0' if label == 'context-300' else '3.0.1'
    doc = {'@graph': [{'type': 'CreationInfo', 'specVersion': version}]}
    if context is not None:
        doc['@context'] = context
    (folder / 'image.rootfs.spdx.json').write_text(json.dumps(doc))
PY
for case in context-300 context-array context-object context-depth4; do
  pack "$case" "$tmp/$case" "$tmp/$case.zip" 1
done
for case in context-missing context-unrelated context-31 context-mixed context-suffix context-depth5; do
  refuse "$case" "$tmp/$case" 'SPDX 3 requires a supported 3.0.0 or 3.0.1 @context:'
done
printf 'PASS: %s Yocto packaging scenarios\n' "$checks"
