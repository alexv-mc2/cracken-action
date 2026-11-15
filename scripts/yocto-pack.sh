#!/usr/bin/env bash
# Package a native Yocto SPDX document set for the crAcken ZIP endpoint.
set -euo pipefail
if [[ $# != 2 ]]; then
  echo 'Usage: yocto-pack.sh <deploy/images/MACHINE directory | .spdx.tar.zst> <output.zip>' >&2
  exit 1
fi
command -v python3 >/dev/null || { echo 'python3 is required' >&2; exit 1; }
python3 - "$1" "$2" <<'PY'
import json
import os
from pathlib import Path, PurePosixPath
import re
import subprocess
import sys
import tarfile
import tempfile
import zipfile

LIMIT = 16 * 1024 * 1024
READ_LIMIT = 8 * LIMIT
source, output = Path(sys.argv[1]), Path(sys.argv[2])

def fail(message):
    raise ValueError(message)

def safe_name(name):
    if '\\' in name or '\x00' in name or name.startswith('/'):
        fail('unsafe archive path: ' + name)
    parts = name.split('/')
    if '..' in parts or (parts and ':' in parts[0]):
        fail('unsafe archive path: ' + name)
    clean = PurePosixPath(name).as_posix()
    return clean

def candidate(name):
    return name.endswith('.spdx.json') or name.endswith('.spdx.index.json')

def supported_spdx3_context(context):
    # Match the server's spdx3Context traversal and supported URL allowlist.
    entries = []
    pending = [(context, 0)]
    while pending:
        value, depth = pending.pop()
        if depth > 4:
            return False
        if isinstance(value, str):
            entries.append(value)
        elif isinstance(value, (dict, list)):
            values = value.values() if isinstance(value, dict) else value
            pending.extend((entry, depth + 1) for entry in values)
    contexts = [entry for entry in entries if re.search(r'spdx\.org/rdf/3', entry, re.I)]
    return bool(contexts) and all(
        re.fullmatch(r'https?://spdx\.org/rdf/3\.0\.[01]/spdx-context\.jsonld', entry, re.I)
        for entry in contexts
    )

entries = []
seen = set()
bytes_read = 0
def reserve_read(size):
    global bytes_read
    if size > READ_LIMIT - bytes_read:
        fail('SPDX candidate files exceed the 128 MiB read limit; pass the image SPDX archive or a directory with only the image documents')
    bytes_read += size

def add(name, data):
    name = safe_name(name)
    if not candidate(name):
        return
    if name in seen:
        fail('duplicate SPDX archive path: ' + name)
    seen.add(name)
    entries.append((name, data))

try:
    source = source.resolve(strict=True)
    if source.is_dir():
        archives = sorted(source.glob('*.spdx.tar.zst'))
        if len(archives) > 1:
            fail('multiple .spdx.tar.zst candidates: ' + ', '.join(str(path) for path in archives))
        if archives:
            try:
                archive_path = archives[0].resolve(strict=True)
                archive_path.relative_to(source)
            except (ValueError, OSError, RuntimeError):
                fail('unsafe symlink in input: ' + str(archives[0]))
            source = archive_path
    if source.is_dir():
        paths = {}
        for root, dirs, files in os.walk(source, followlinks=False):
            # Do not follow directory symlinks. Deploy directories commonly contain
            # unrelated symlinks; SPDX file symlinks must stay within the input.
            dirs[:] = [item for item in dirs if not (Path(root) / item).is_symlink()]
            for item in files:
                path = Path(root) / item
                name = path.relative_to(source).as_posix()
                if candidate(name):
                    try:
                        real_path = path.resolve(strict=True)
                        real_path.relative_to(source)
                    except (ValueError, OSError, RuntimeError):
                        fail('unsafe symlink in input: ' + str(path))
                    # Prefer the real file's name when both it and IMAGE_LINK_NAME
                    # are collected, independently of directory traversal order.
                    if real_path not in paths or not path.is_symlink():
                        paths[real_path] = name
        for path, name in paths.items():
            with path.open('rb') as stream:
                size = os.fstat(stream.fileno()).st_size
                reserve_read(size)
                data = stream.read(size)
                if len(data) != size:
                    fail('SPDX candidate file changed while reading: ' + str(path))
                add(name, data)
    elif source.is_file() and str(source).endswith('.spdx.tar.zst'):
        try:
            proc = subprocess.Popen(['zstd', '-q', '-d', '-c', '--', str(source)], stdout=subprocess.PIPE)
        except FileNotFoundError:
            fail('zstd is required to unpack archives; pass the .spdx.tar.zst file when zstd is unavailable')
        try:
            with tarfile.open(fileobj=proc.stdout, mode='r|') as archive:
                for member in archive:
                    name = safe_name(member.name)
                    if member.issym() or member.islnk():
                        fail('unsafe archive link: ' + name)
                    if not (member.isfile() or member.isdir()):
                        fail('unsafe archive entry: ' + name)
                    if member.isfile() and candidate(name):
                        reserve_read(member.size)
                        stream = archive.extractfile(member)
                        add(name, stream.read(member.size))
            proc.stdout.close()
            if proc.wait() != 0:
                fail('zstd could not decompress the archive')
        finally:
            if proc.poll() is None:
                proc.kill()
                proc.wait()
    else:
        fail('input must be a directory or a .spdx.tar.zst archive')
    if not entries:
        fail('no SPDX JSON documents found')

    versions = set()
    roots = []
    for name, data in entries:
        try:
            doc = json.loads(data)
        except (ValueError, UnicodeDecodeError):
            fail('invalid SPDX JSON: ' + name)
        if not isinstance(doc, (dict, list)):
            fail('invalid SPDX JSON: ' + name)
        found = set()
        def visit(value):
            if isinstance(value, dict):
                for key, v in value.items():
                    if key in ('spdxVersion', 'specVersion') and isinstance(v, str):
                        found.add(v[5:] if v.startswith('SPDX-') else v)
                    if isinstance(v, (dict, list)):
                        visit(v)
            elif isinstance(value, list):
                for v in value:
                    visit(v)
        visit(doc)
        for version in found:
            if version.startswith('2.'):
                versions.add('2')
            elif version in ('3.0.0', '3.0.1'):
                versions.add('3')
            elif version.startswith('3.'):
                fail('SPDX ' + version + ' is not supported; use SPDX 3.0.0 or 3.0.1')
        is_spdx3 = any(v in found for v in ('3.0.0', '3.0.1'))
        if is_spdx3 and not supported_spdx3_context(doc.get('@context') if isinstance(doc, dict) else None):
            fail('SPDX 3 requires a supported 3.0.0 or 3.0.1 @context: ' + name)
        if name.endswith('.rootfs.spdx.json') and is_spdx3:
            roots.append((name, data))
    if len(versions) > 1:
        fail('mixed SPDX 2 and SPDX 3 documents are not supported')
    if versions == {'3'}:
        if len(roots) != 1:
            fail('SPDX 3 requires exactly one complete *.rootfs.spdx.json')
        entries = roots
    elif versions != {'2'}:
        fail('no supported SPDX 2 or SPDX 3 version found')
    if sum(len(data) for _, data in entries) > LIMIT:
        fail('SPDX files exceed the 16 MiB uncompressed ZIP limit')
    if len(entries) > 10000:
        fail('ZIP exceeds the 10,000 entry limit')
    output.parent.mkdir(parents=True, exist_ok=True)
    fd, temp = tempfile.mkstemp(prefix='.yocto-pack-', suffix='.zip', dir=str(output.parent))
    os.close(fd)
    try:
        with zipfile.ZipFile(temp, 'w', compression=zipfile.ZIP_DEFLATED) as archive:
            for name, data in sorted(entries):
                info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
                info.create_system = 3
                info.external_attr = 0o100644 << 16
                info.compress_type = zipfile.ZIP_DEFLATED
                archive.writestr(info, data)
        if os.path.getsize(temp) > LIMIT:
            fail('ZIP exceeds the 16 MiB packed limit')
        os.replace(temp, output)
    finally:
        if os.path.exists(temp):
            os.unlink(temp)
    print('Packaged %d SPDX document(s) into %s' % (len(entries), output))
except (ValueError, OSError, tarfile.TarError) as exc:
    print('yocto-pack: ' + str(exc), file=sys.stderr)
    sys.exit(1)
PY
