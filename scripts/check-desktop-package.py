#!/usr/bin/env python3
"""Inspect a packaged macOS .app or Windows win-unpacked without executing it."""
import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import stat
import struct
import sys


class PackageError(ValueError):
    """Stable errors deliberately omit private filenames and file contents."""


RUNTIME_FILES = {
    'darwin': {
        'bin/mihomo', 'bin/openconnect',
        'lib/libcrypto.3.dylib', 'lib/libssl.3.dylib',
    },
    'windows': {
        'bin/iconv.dll', 'bin/libgcc_s_seh-1.dll', 'bin/libgmp-10.dll',
        'bin/libgnutls-30.dll', 'bin/libhogweed-6.dll', 'bin/libintl-8.dll',
        'bin/liblz4.dll', 'bin/libnettle-8.dll', 'bin/libopenconnect-5.dll',
        'bin/libstoken-1.dll', 'bin/libtasn1-6.dll', 'bin/libwinpthread-1.dll',
        'bin/libxml2-2.dll', 'bin/mihomo.exe', 'bin/openconnect.exe',
        'bin/wintun.dll', 'bin/zlib1.dll', 'certs/ca-bundle.crt',
    },
}
COMMON_NOTICES = {
    'notices/Go-LICENSE', 'notices/mihomo-LICENSE', 'notices/yaml-LICENSE',
    'notices/openconnect/COPYING.LGPL',
}
NOTICES = {
    'darwin': COMMON_NOTICES | {'notices/openssl@3/LICENSE.txt'},
    'windows': COMMON_NOTICES | {'notices/windows-components.txt'},
}
ASAR_REQUIRED = {
    'package.json', 'out/main/index.js', 'out/preload/index.js',
    'out/renderer/index.html',
}
PRODUCTION_MODULES = {'react', 'react-dom', 'scheduler', 'lucide-react'}
LEGAL_FILES = {'THIRD_PARTY.md', 'golang-x-sys.txt'}
MAX_JSON = 16 << 20
RUNTIME_MANIFEST_KEYS = {
    'version', 'os', 'arch', 'mihomo_version', 'openconnect_version', 'files',
}
WINDOWS_OFFLINE_RECOVERY = (
    b'@echo off\n'
    b'setlocal DisableDelayedExpansion\n'
    b'echo LuminaVPN read-only preview: network recovery is unavailable.\n'
    b'echo This bundled offline backend cannot stop or recover a network run.\n'
    b'echo Use the original NetLaunch CLI that created the run, or its frozen recovery entry.\n'
    b'echo Keep that run directory until recovery is confirmed.\n'
    b'pause\n'
    b'exit /b 1\n'
)


def require(condition, code):
    if not condition:
        raise PackageError(code)


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, 'DUPLICATE_JSON_KEY')
        result[key] = value
    return result


def parse_json(raw):
    try:
        return json.loads(raw.decode('utf-8'), object_pairs_hook=unique_object)
    except (UnicodeError, json.JSONDecodeError, RecursionError):
        raise PackageError('INVALID_JSON') from None


def regular(path):
    try:
        mode = path.lstat().st_mode
    except OSError:
        raise PackageError('REQUIRED_FILE_MISSING') from None
    require(stat.S_ISREG(mode), 'NON_REGULAR_PACKAGE_FILE')


def private_artifact(name):
    p = PurePosixPath(name)
    if any(part.lower() in {'private', 'profiles', 'profile', 'test-results',
                             'test_results', 'reports', 'results', 'acceptance',
                             'playwright-report', 'coverage'} for part in p.parts):
        return True
    return (any(part.startswith('.') for part in p.parts)
            or '.private.' in p.name.lower()
            or p.suffix.lower() in {'.map', '.log', '.key', '.p12', '.pfx', '.sqlite', '.sqlite3'}
            or re.match(r'^(acceptance|验收|test[-_](results?|reports?))', p.name, re.I) is not None)


def tree_files(root):
    require(root.is_dir() and not root.is_symlink(), 'PACKAGE_DIRECTORY_MISSING_OR_LINKED')
    found = set()
    stack = [(root, '')]
    while stack:
        directory, prefix = stack.pop()
        children = list(directory.iterdir())
        require(children or directory == root, 'EMPTY_CUSTOM_RESOURCE_DIRECTORY')
        for path in children:
            name = prefix + path.name
            require(not path.is_symlink(), 'PACKAGE_SYMLINK')
            require(not private_artifact(name), 'PRIVATE_OR_DEVELOPMENT_ARTIFACT')
            if path.is_dir():
                stack.append((path, name + '/'))
            else:
                regular(path)
                found.add(name)
            require(len(found) + len(stack) <= 1000, 'CUSTOM_RESOURCE_TREE_TOO_LARGE')
    return found


def sha256_file(path):
    digest = hashlib.sha256()
    with path.open('rb') as source:
        for chunk in iter(lambda: source.read(1 << 20), b''):
            digest.update(chunk)
    return digest.hexdigest()


def verify_legal(root):
    require(tree_files(root) == LEGAL_FILES, 'UNEXPECTED_OR_MISSING_LEGAL_FILE')
    for name in LEGAL_FILES:
        path = root / name
        require(0 < path.stat().st_size <= 4 << 20, 'INVALID_LEGAL_NOTICE')
        raw = path.read_bytes()
        require(b'\0' not in raw and not re.search(rb'-----BEGIN (?:[A-Z]+ )?PRIVATE KEY-----', raw),
                'INVALID_LEGAL_NOTICE')
        try:
            raw.decode('utf-8')
        except UnicodeError:
            raise PackageError('INVALID_LEGAL_NOTICE') from None


def fixed_runtime_manifest(goos):
    """Use the repository's reviewed manifest, never the package as its trust root."""
    name = 'runtime-manifest.macos-arm64.json' if goos == 'darwin' else 'runtime-manifest.windows-amd64.json'
    path = Path(__file__).resolve().parent / name
    regular(path)
    require(path.stat().st_size <= 1 << 20, 'FIXED_RUNTIME_MANIFEST_TOO_LARGE')
    reference = parse_json(path.read_bytes())
    require(isinstance(reference, dict) and set(reference) == RUNTIME_MANIFEST_KEYS,
            'INVALID_FIXED_RUNTIME_MANIFEST')
    entries = reference['files']
    require(isinstance(entries, list) and len(entries) == len(RUNTIME_FILES[goos]),
            'INVALID_FIXED_RUNTIME_MANIFEST')
    seen = set()
    for entry in entries:
        require(isinstance(entry, dict) and set(entry) == {'path', 'sha256'},
                'INVALID_FIXED_RUNTIME_MANIFEST')
        name, checksum = entry['path'], entry['sha256']
        require(isinstance(name, str) and name in RUNTIME_FILES[goos] and name not in seen
                and isinstance(checksum, str) and re.fullmatch(r'[0-9a-f]{64}', checksum),
                'INVALID_FIXED_RUNTIME_MANIFEST')
        seen.add(name)
    require(type(reference['version']) is int and reference['version'] == 1
            and reference['os'] == goos and reference['arch'] == ('arm64' if goos == 'darwin' else 'amd64'),
            'INVALID_FIXED_RUNTIME_MANIFEST')
    return reference


def verify_runtime(root, goos):
    found = tree_files(root)
    expected = RUNTIME_FILES[goos] | NOTICES[goos] | {'manifest.json'}
    require(found == expected, 'UNEXPECTED_OR_MISSING_RUNTIME_FILE')
    manifest_path = root / 'manifest.json'
    require(manifest_path.stat().st_size <= 1 << 20, 'MANIFEST_TOO_LARGE')
    manifest = parse_json(manifest_path.read_bytes())
    require(isinstance(manifest, dict) and set(manifest) == RUNTIME_MANIFEST_KEYS,
            'INVALID_RUNTIME_MANIFEST')
    arch = 'arm64' if goos == 'darwin' else 'amd64'
    require(type(manifest['version']) is int and manifest['version'] == 1 and manifest['os'] == goos and manifest['arch'] == arch,
            'RUNTIME_PLATFORM_MISMATCH')
    for key in ('mihomo_version', 'openconnect_version'):
        require(isinstance(manifest[key], str) and re.fullmatch(r'[A-Za-z0-9._+-]{1,128}', manifest[key]),
                'INVALID_RUNTIME_VERSION')
    entries = manifest['files']
    require(isinstance(entries, list) and len(entries) == len(RUNTIME_FILES[goos]), 'RUNTIME_COMPONENT_SET_MISMATCH')
    reference = fixed_runtime_manifest(goos)
    require(all(manifest[key] == reference[key] for key in RUNTIME_MANIFEST_KEYS - {'files'}),
            'RUNTIME_FIXED_METADATA_MISMATCH')
    fixed_hashes = {entry['path']: entry['sha256'] for entry in reference['files']}
    seen = set()
    for entry in entries:
        require(isinstance(entry, dict) and set(entry) == {'path', 'sha256'}, 'INVALID_RUNTIME_ENTRY')
        name, checksum = entry['path'], entry['sha256']
        require(isinstance(name, str) and name in RUNTIME_FILES[goos] and name not in seen,
                'UNSAFE_OR_DUPLICATE_RUNTIME_ENTRY')
        require(isinstance(checksum, str) and re.fullmatch(r'[0-9a-f]{64}', checksum), 'INVALID_RUNTIME_HASH')
        require(checksum == fixed_hashes[name], 'RUNTIME_FIXED_CHECKSUM_MISMATCH')
        seen.add(name)
        require(sha256_file(root / name) == checksum, 'RUNTIME_CHECKSUM_MISMATCH')
    require(seen == RUNTIME_FILES[goos], 'RUNTIME_COMPONENT_SET_MISMATCH')
    for name in NOTICES[goos]:
        path = root / name
        require(0 < path.stat().st_size <= 4 << 20, 'INVALID_UPSTREAM_NOTICE')
        require(b'\0' not in path.read_bytes(), 'INVALID_UPSTREAM_NOTICE')
    if goos == 'darwin':
        for name in ('bin/mihomo', 'bin/openconnect'):
            require((root / name).stat().st_mode & 0o111, 'RUNTIME_EXECUTABLE_MODE_MISSING')
    return len(entries)


def verify_backend(root, goos):
    binary = 'netlaunch' if goos == 'darwin' else 'netlaunch.exe'
    require(tree_files(root) == {binary}, 'UNEXPECTED_OR_MISSING_BACKEND_FILE')
    path = root / binary
    with path.open('rb') as source:
        prefix = source.read(64)
        if goos == 'darwin':
            require(len(prefix) >= 32 and prefix[:4] == b'\xcf\xfa\xed\xfe'
                    and struct.unpack_from('<I', prefix, 4)[0] == 0x0100000c,
                    'BACKEND_ARCHITECTURE_MISMATCH')
            require(path.stat().st_mode & 0o111, 'BACKEND_EXECUTABLE_MODE_MISSING')
        else:
            require(len(prefix) == 64 and prefix[:2] == b'MZ', 'BACKEND_ARCHITECTURE_MISMATCH')
            offset = struct.unpack_from('<I', prefix, 60)[0]
            require(64 <= offset < 1 << 20, 'BACKEND_ARCHITECTURE_MISMATCH')
            source.seek(offset)
            pe = source.read(6)
            require(pe == b'PE\0\0\x64\x86', 'BACKEND_ARCHITECTURE_MISMATCH')


def asar_entries(path):
    """Read Chromium-pickle ASAR metadata with bounded allocations, no extraction."""
    regular(path)
    size = path.stat().st_size
    with path.open('rb') as archive:
        prefix = archive.read(8)
        require(len(prefix) == 8 and struct.unpack_from('<I', prefix)[0] == 4, 'INVALID_ASAR_HEADER')
        header_size = struct.unpack_from('<I', prefix, 4)[0]
        require(8 <= header_size <= MAX_JSON and header_size % 4 == 0 and header_size + 8 <= size, 'INVALID_ASAR_HEADER')
        raw = archive.read(header_size)
        payload_size, string_size = struct.unpack_from('<II', raw)
        require(payload_size + 4 == header_size and 0 < string_size <= payload_size - 4, 'INVALID_ASAR_HEADER')
        header = parse_json(raw[8:8 + string_size])
    entries = {}
    stack = [('', header)]
    while stack:
        prefix, directory = stack.pop()
        require(isinstance(directory, dict) and isinstance(directory.get('files'), dict)
                and not directory.get('unpacked') and 'link' not in directory, 'INVALID_ASAR_DIRECTORY')
        for leaf, value in directory['files'].items():
            require(isinstance(leaf, str) and leaf not in {'', '.', '..'}
                    and not any(c in leaf for c in '/\\:\0'), 'UNSAFE_ASAR_PATH')
            name = prefix + leaf
            require(isinstance(value, dict) and not value.get('unpacked') and 'link' not in value,
                    'ASAR_LINK_OR_UNPACKED_FILE')
            if 'files' in value:
                stack.append((name + '/', value))
            else:
                length, offset = value.get('size'), value.get('offset')
                require(type(length) is int and length >= 0 and isinstance(offset, str)
                        and re.fullmatch(r'[0-9]{1,20}', offset), 'INVALID_ASAR_FILE_RANGE')
                position = 8 + header_size + int(offset)
                require(position <= size and length <= size - position, 'INVALID_ASAR_FILE_RANGE')
                entries[name] = (position, length, value.get('integrity'))
            require(len(entries) + len(stack) <= 20000, 'ASAR_TREE_TOO_LARGE')
    return entries


def allowed_asar_path(name):
    if private_artifact(name):
        return False
    if name in ASAR_REQUIRED:
        return True
    p = PurePosixPath(name)
    if p.parts[:3] == ('out', 'renderer', 'assets'):
        return len(p.parts) == 4 and p.suffix in {'.js', '.css'}
    if len(p.parts) >= 3 and p.parts[0] == 'node_modules' and p.parts[1] in PRODUCTION_MODULES:
        return p.suffix.lower() in {'.js', '.cjs', '.mjs', '.json', '.md', '.txt', '.ts', '.mts'} or p.name in {'LICENSE', 'COPYING'}
    return False


def verify_asar(path):
    entries = asar_entries(path)
    require(ASAR_REQUIRED <= entries.keys(), 'ASAR_REQUIRED_SOURCE_MISSING')
    require(any(name.startswith('out/renderer/assets/') and name.endswith('.js') for name in entries), 'ASAR_RENDERER_SCRIPT_MISSING')
    require(any(name.startswith('out/renderer/assets/') and name.endswith('.css') for name in entries), 'ASAR_RENDERER_STYLE_MISSING')
    require(all(allowed_asar_path(name) for name in entries), 'ASAR_UNEXPECTED_OR_PRIVATE_PAYLOAD')
    package = None
    with path.open('rb') as archive:
        for name, (offset, length, integrity) in entries.items():
            archive.seek(offset)
            digest = hashlib.sha256()
            remaining = length
            content = bytearray() if name == 'package.json' else None
            require(content is None or length <= 1 << 20, 'ASAR_PACKAGE_JSON_TOO_LARGE')
            while remaining:
                chunk = archive.read(min(remaining, 1 << 20))
                require(bool(chunk), 'ASAR_TRUNCATED_FILE')
                digest.update(chunk)
                if content is not None:
                    content.extend(chunk)
                remaining -= len(chunk)
            if integrity is not None:
                require(isinstance(integrity, dict) and integrity.get('algorithm') == 'SHA256'
                        and integrity.get('hash') == digest.hexdigest(), 'ASAR_INTEGRITY_MISMATCH')
            if content is not None:
                package = parse_json(bytes(content))
    require(isinstance(package, dict) and package.get('name') == 'luminavpn-desktop'
            and package.get('main') == 'out/main/index.js', 'ASAR_PACKAGE_IDENTITY_MISMATCH')
    dependencies = package.get('dependencies', {})
    require(isinstance(dependencies, dict) and set(dependencies) <= PRODUCTION_MODULES, 'ASAR_UNEXPECTED_DEPENDENCY')
    return len(entries)


def check_package(package):
    package = Path(package)
    require(package.is_dir() and not package.is_symlink(), 'PACKAGE_DIRECTORY_MISSING_OR_LINKED')
    if (package / 'Contents').exists():
        require((package / 'Contents').is_dir() and not (package / 'Contents').is_symlink(),
                'PACKAGE_DIRECTORY_MISSING_OR_LINKED')
        goos, resources = 'darwin', package / 'Contents' / 'Resources'
        require((package / 'Contents/MacOS').is_dir() and not (package / 'Contents/MacOS').is_symlink(),
                'PACKAGE_DIRECTORY_MISSING_OR_LINKED')
        regular(package / 'Contents' / 'MacOS' / 'LuminaVPN')
    else:
        goos, resources = 'windows', package / 'resources'
        regular(package / 'LuminaVPN.exe')
    require(resources.is_dir() and not resources.is_symlink(), 'PACKAGE_RESOURCES_MISSING_OR_LINKED')
    # Electron's platform frameworks/resources have their own layout. The
    # custom payload is checked independently rather than treated as source.
    for name in ('backend', 'runtime', 'recovery', 'legal'):
        require((resources / name).is_dir() and not (resources / name).is_symlink(), 'CUSTOM_RESOURCES_MISSING_OR_LINKED')
    verify_backend(resources / 'backend', goos)
    components = verify_runtime(resources / 'runtime', goos)
    verify_legal(resources / 'legal')
    recovery = '停止与恢复.command' if goos == 'darwin' else 'Stop-and-Recover.cmd'
    require(tree_files(resources / 'recovery') == {recovery}, 'UNEXPECTED_OR_MISSING_RECOVERY_FILE')
    recovery_path = resources / 'recovery' / recovery
    require(0 < recovery_path.stat().st_size <= 64 << 10, 'RECOVERY_ENTRY_INVALID')
    recovery_bytes = recovery_path.read_bytes()
    if goos == 'darwin':
        require(b'\0' not in recovery_bytes and b'netlaunch' in recovery_bytes and b'down' in recovery_bytes,
                'RECOVERY_ENTRY_INVALID')
        require(recovery_path.stat().st_mode & 0o111, 'RECOVERY_EXECUTABLE_MODE_MISSING')
    else:
        # The Windows desktop backend is deliberately offline. Require the
        # exact non-executing notice rather than accepting a broken down call.
        require(recovery_bytes.replace(b'\r\n', b'\n') == WINDOWS_OFFLINE_RECOVERY,
                'WINDOWS_OFFLINE_RECOVERY_ENTRY_INVALID')
    require(not (resources / 'app.asar.unpacked').exists(), 'UNEXPECTED_UNPACKED_ASAR_PAYLOAD')
    payload = verify_asar(resources / 'app.asar')
    return {'platform': goos, 'runtime_components': components, 'asar_files': payload}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('package', type=Path)
    args = parser.parse_args()
    try:
        result = check_package(args.package)
    except (PackageError, OSError, ValueError, struct.error, RecursionError) as error:
        code = str(error) if isinstance(error, PackageError) else 'PACKAGE_READ_FAILED'
        print('Desktop package check failed: ' + code, file=sys.stderr)
        return 1
    print('Desktop package contents passed: {platform}, {runtime_components} runtime components, {asar_files} ASAR files.'.format(**result))
    print('This content check does not verify platform signing, notarization or native network behavior.')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
