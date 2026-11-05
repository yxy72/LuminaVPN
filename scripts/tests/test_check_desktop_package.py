import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import struct
import subprocess
import tempfile
import unittest
from unittest.mock import patch


spec = importlib.util.spec_from_file_location('check_desktop_package', Path(__file__).parents[1] / 'check-desktop-package.py')
check = importlib.util.module_from_spec(spec)
spec.loader.exec_module(check)
real_fixed_runtime_manifest = check.fixed_runtime_manifest
DEFAULT_PLATFORM = 'windows' if os.name == 'nt' else 'darwin'


def fixture_manifest(goos):
    return {
        'version': 1, 'os': goos, 'arch': 'arm64' if goos == 'darwin' else 'amd64',
        'mihomo_version': 'v1.19.32', 'openconnect_version': '9.21',
        'files': [{'path': name, 'sha256': hashlib.sha256(('fixture:' + name).encode()).hexdigest()}
                  for name in sorted(check.RUNTIME_FILES[goos])],
    }


def write(path, data, executable=False):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    path.chmod(0o700 if executable else 0o600)


def write_asar(path, files, metadata=None):
    header = {'files': {}}
    content = bytearray()
    for name, data in files.items():
        directory = header['files']
        parts = name.split('/')
        for part in parts[:-1]:
            directory = directory.setdefault(part, {'files': {}})['files']
        node = {'size': len(data), 'offset': str(len(content)), 'integrity': {'algorithm': 'SHA256', 'hash': hashlib.sha256(data).hexdigest()}}
        if metadata and name in metadata:
            node.update(metadata[name])
        directory[parts[-1]] = node
        content.extend(data)
    encoded = json.dumps(header, separators=(',', ':')).encode()
    padding = b'\0' * ((-len(encoded)) % 4)
    payload = struct.pack('<II', len(encoded) + len(padding) + 4, len(encoded)) + encoded + padding
    write(path, struct.pack('<II', 4, len(payload)) + payload + content)


def payload_files():
    return {
        'package.json': b'{"name":"luminavpn-desktop","main":"out/main/index.js","dependencies":{"react":"19.3.1"}}',
        'out/main/index.js': b'export const preview = true;',
        'out/preload/index.js': b'const narrowAPI = {};',
        'out/renderer/index.html': b'<!doctype html><title>LuminaVPN</title>',
        'out/renderer/assets/index-fixture.js': b'const renderer = true;',
        'out/renderer/assets/index-fixture.css': b'body { color: #234; }',
        'node_modules/react/package.json': b'{"name":"react"}',
        'node_modules/react/index.js': b'module.exports = {};',
    }


def package_fixture(root, goos=DEFAULT_PLATFORM):
    if goos == 'darwin':
        package = root / 'LuminaVPN.app'
        resources = package / 'Contents/Resources'
        write(package / 'Contents/MacOS/LuminaVPN', b'electron-fixture', True)
        binary = struct.pack('<II', 0xfeedfacf, 0x0100000c) + bytes(24)
        backend = 'netlaunch'
    else:
        package = root / 'win-unpacked'
        resources = package / 'resources'
        write(package / 'LuminaVPN.exe', b'electron-fixture', True)
        binary = bytearray(128)
        binary[:2] = b'MZ'
        struct.pack_into('<I', binary, 60, 64)
        binary[64:70] = b'PE\0\0\x64\x86'
        backend = 'netlaunch.exe'
    write(resources / 'backend' / backend, binary, True)
    manifest = fixture_manifest(goos)
    for name in sorted(check.RUNTIME_FILES[goos]):
        data = ('fixture:' + name).encode()
        write(resources / 'runtime' / name, data, name.startswith('bin/'))
    write(resources / 'runtime/manifest.json', json.dumps(manifest).encode())
    for name in check.NOTICES[goos]:
        write(resources / 'runtime' / name, b'Public upstream license fixture\n')
    for name in check.LEGAL_FILES:
        write(resources / 'legal' / name, b'Public third-party license fixture\n')
    recovery = '停止与恢复.command' if goos == 'darwin' else 'Stop-and-Recover.cmd'
    recovery_entry = b'netlaunch down --runtime ../runtime\n' if goos == 'darwin' else check.WINDOWS_OFFLINE_RECOVERY
    write(resources / 'recovery' / recovery, recovery_entry, True)
    write_asar(resources / 'app.asar', payload_files())
    return package, resources


class DesktopPackageTests(unittest.TestCase):
    def setUp(self):
        # Synthetic public bytes have their own independent reviewed fixture
        # manifest. Mutation tests change only the untrusted packaged copy.
        mock_reference = patch.object(check, 'fixed_runtime_manifest', side_effect=fixture_manifest)
        mock_reference.start()
        self.addCleanup(mock_reference.stop)

    def test_windows_layout_and_asar_payload_pass(self):
        with tempfile.TemporaryDirectory() as root:
            package, _ = package_fixture(Path(root), 'windows')
            self.assertEqual(check.check_package(package),
                             {'platform': 'windows', 'runtime_components': 18, 'asar_files': 8})

    @unittest.skipIf(os.name == 'nt', 'macOS executable permission bits require a POSIX filesystem')
    def test_macos_layout_and_asar_payload_pass(self):
        with tempfile.TemporaryDirectory() as root:
            package, _ = package_fixture(Path(root), 'darwin')
            self.assertEqual(check.check_package(package),
                             {'platform': 'darwin', 'runtime_components': 4, 'asar_files': 8})

    def test_repository_fixed_manifests_have_the_exact_platform_component_sets(self):
        for goos in ('darwin', 'windows'):
            reference = real_fixed_runtime_manifest(goos)
            self.assertEqual({entry['path'] for entry in reference['files']}, check.RUNTIME_FILES[goos])

    def test_runtime_digest_corruption_is_rejected(self):
        with tempfile.TemporaryDirectory() as root:
            package, resources = package_fixture(Path(root))
            binary = 'mihomo.exe' if DEFAULT_PLATFORM == 'windows' else 'mihomo'
            write(resources / 'runtime/bin' / binary, b'corrupted', True)
            with self.assertRaisesRegex(check.PackageError, 'RUNTIME_CHECKSUM_MISMATCH'):
                check.check_package(package)

    def test_runtime_tampering_with_rewritten_manifest_is_rejected(self):
        for goos in ('darwin', 'windows'):
            with self.subTest(platform=goos), tempfile.TemporaryDirectory() as root:
                package, resources = package_fixture(Path(root), goos)
                path = resources / 'runtime/manifest.json'
                manifest = json.loads(path.read_text())
                entry = manifest['files'][0]
                replacement = b'replaced runtime with matching self-declared hash'
                write(resources / 'runtime' / entry['path'], replacement, True)
                entry['sha256'] = hashlib.sha256(replacement).hexdigest()
                path.write_text(json.dumps(manifest))
                with self.assertRaisesRegex(check.PackageError, 'RUNTIME_FIXED_CHECKSUM_MISMATCH'):
                    check.verify_runtime(resources / 'runtime', goos)

    def test_runtime_version_metadata_changes_are_rejected(self):
        for key in ('mihomo_version', 'openconnect_version'):
            with self.subTest(key=key), tempfile.TemporaryDirectory() as root:
                package, resources = package_fixture(Path(root))
                path = resources / 'runtime/manifest.json'
                manifest = json.loads(path.read_text())
                manifest[key] = 'unreviewed-version'
                path.write_text(json.dumps(manifest))
                with self.assertRaisesRegex(check.PackageError, 'RUNTIME_FIXED_METADATA_MISMATCH'):
                    check.check_package(package)

    def test_manifest_entry_order_is_not_part_of_runtime_identity(self):
        with tempfile.TemporaryDirectory() as root:
            package, resources = package_fixture(Path(root))
            path = resources / 'runtime/manifest.json'
            manifest = json.loads(path.read_text())
            manifest['files'].reverse()
            path.write_text(json.dumps(manifest))
            self.assertEqual(check.check_package(package)['runtime_components'],
                             len(check.RUNTIME_FILES[DEFAULT_PLATFORM]))

    def test_windows_offline_recovery_rejects_execution_and_success(self):
        entries = [
            b'@echo off\nnetlaunch.exe down --runtime ../runtime\npause\n',
            check.WINDOWS_OFFLINE_RECOVERY.replace(b'exit /b 1', b'exit /b 0'),
            check.WINDOWS_OFFLINE_RECOVERY + b'netlaunch.exe down\n',
        ]
        for entry in entries:
            with self.subTest(entry=entry), tempfile.TemporaryDirectory() as root:
                package, resources = package_fixture(Path(root), 'windows')
                write(resources / 'recovery/Stop-and-Recover.cmd', entry, True)
                with self.assertRaisesRegex(check.PackageError, 'WINDOWS_OFFLINE_RECOVERY_ENTRY_INVALID'):
                    check.check_package(package)

    def test_unlisted_private_and_extra_binary_files_are_rejected(self):
        for name in ['runtime/bin/extra.dylib', 'runtime/notices/local.private.json', 'backend/policy.json', 'recovery/session.log']:
            with self.subTest(name=name), tempfile.TemporaryDirectory() as root:
                package, resources = package_fixture(Path(root))
                write(resources / name, b'local-fixture')
                with self.assertRaises(check.PackageError):
                    check.check_package(package)

    def test_empty_private_or_build_directory_is_rejected(self):
        for name in ['runtime/profiles', 'backend/empty-build-cache']:
            with self.subTest(name=name), tempfile.TemporaryDirectory() as root:
                package, resources = package_fixture(Path(root))
                (resources / name).mkdir()
                with self.assertRaises(check.PackageError):
                    check.check_package(package)

    def test_legal_notices_reject_missing_extra_binary_and_key_content(self):
        for change in ['missing', 'extra', 'binary', 'key']:
            with self.subTest(change=change), tempfile.TemporaryDirectory() as root:
                package, resources = package_fixture(Path(root))
                path = resources / 'legal/golang-x-sys.txt'
                if change == 'missing':
                    path.unlink()
                elif change == 'extra':
                    write(resources / 'legal/local.txt', b'local fixture')
                elif change == 'binary':
                    path.write_bytes(b'\0binary')
                else:
                    path.write_bytes(b'-----BEGIN ' + b'PRIVATE KEY-----')
                with self.assertRaises(check.PackageError):
                    check.check_package(package)

    def test_symlink_file_or_directory_is_rejected(self):
        binary = 'mihomo.exe' if DEFAULT_PLATFORM == 'windows' else 'mihomo'
        for name in ['runtime/bin/' + binary, 'runtime/notices']:
            with self.subTest(name=name), tempfile.TemporaryDirectory() as root:
                package, resources = package_fixture(Path(root))
                original = resources / name
                outside = Path(root) / 'outside'
                original.rename(outside)
                try:
                    original.symlink_to(outside, target_is_directory=outside.is_dir())
                except OSError as error:
                    if os.name == 'nt' and error.winerror == 1314:
                        self.skipTest('Windows symlink creation requires Developer Mode or the symlink privilege')
                    raise
                with self.assertRaisesRegex(check.PackageError, 'PACKAGE_SYMLINK'):
                    check.check_package(package)

    def test_manifest_duplicate_missing_and_unsafe_entries_are_rejected(self):
        for change in ['duplicate', 'missing', 'unsafe', 'extra-field', 'wrong-arch']:
            with self.subTest(change=change), tempfile.TemporaryDirectory() as root:
                package, resources = package_fixture(Path(root))
                path = resources / 'runtime/manifest.json'
                manifest = json.loads(path.read_text())
                if change == 'duplicate':
                    manifest['files'][1] = dict(manifest['files'][0])
                elif change == 'missing':
                    manifest['files'].pop()
                elif change == 'unsafe':
                    manifest['files'][0]['path'] = '../outside'
                elif change == 'extra-field':
                    manifest['private_token'] = 'fixture-only'
                else:
                    manifest['arch'] = 'arm64' if manifest['arch'] == 'amd64' else 'amd64'
                path.write_text(json.dumps(manifest))
                with self.assertRaises(check.PackageError):
                    check.check_package(package)

    def test_backend_format_and_target_architecture_are_checked(self):
        for platform in ['darwin', 'windows']:
            with self.subTest(platform=platform), tempfile.TemporaryDirectory() as root:
                package, resources = package_fixture(Path(root), platform)
                binary = resources / 'backend' / ('netlaunch' if platform == 'darwin' else 'netlaunch.exe')
                write(binary, b'wrong architecture', True)
                with self.assertRaisesRegex(check.PackageError, 'BACKEND_ARCHITECTURE_MISMATCH'):
                    check.check_package(package)

    def test_asar_maps_private_data_and_unexpected_dependencies_are_rejected(self):
        names = [
            'out/renderer/assets/index.js.map', 'out/renderer/profiles/policy.json',
            'out/main/acceptance-report.md', 'node_modules/unknown/index.js',
            'node_modules/react/.env',
        ]
        for name in names:
            with self.subTest(name=name), tempfile.TemporaryDirectory() as root:
                package, resources = package_fixture(Path(root))
                files = payload_files()
                files[name] = b'local fixture'
                write_asar(resources / 'app.asar', files)
                with self.assertRaisesRegex(check.PackageError, 'ASAR_UNEXPECTED_OR_PRIVATE_PAYLOAD'):
                    check.check_package(package)

    def test_asar_link_unpacked_and_out_of_bounds_metadata_are_rejected(self):
        for metadata in [{'link': '../outside'}, {'unpacked': True}, {'offset': '999999999999'}, {'size': -1}]:
            with self.subTest(metadata=metadata), tempfile.TemporaryDirectory() as root:
                package, resources = package_fixture(Path(root))
                write_asar(resources / 'app.asar', payload_files(), {'out/main/index.js': metadata})
                with self.assertRaises(check.PackageError):
                    check.check_package(package)

    def test_asar_content_corruption_is_detected_by_integrity(self):
        with tempfile.TemporaryDirectory() as root:
            package, resources = package_fixture(Path(root))
            path = resources / 'app.asar'
            raw = bytearray(path.read_bytes())
            raw[-1] ^= 1
            path.write_bytes(raw)
            with self.assertRaisesRegex(check.PackageError, 'ASAR_INTEGRITY_MISMATCH'):
                check.check_package(package)

    def test_missing_code_or_recovery_entry_is_rejected(self):
        with tempfile.TemporaryDirectory() as root:
            package, resources = package_fixture(Path(root))
            recovery = 'Stop-and-Recover.cmd' if DEFAULT_PLATFORM == 'windows' else '停止与恢复.command'
            (resources / 'recovery' / recovery).unlink()
            with self.assertRaisesRegex(check.PackageError, 'UNEXPECTED_OR_MISSING_RECOVERY_FILE'):
                check.check_package(package)
        with tempfile.TemporaryDirectory() as root:
            package, resources = package_fixture(Path(root))
            files = payload_files()
            del files['out/preload/index.js']
            write_asar(resources / 'app.asar', files)
            with self.assertRaisesRegex(check.PackageError, 'ASAR_REQUIRED_SOURCE_MISSING'):
                check.check_package(package)

    def test_json_duplicate_keys_and_oversized_asar_header_are_rejected(self):
        with self.assertRaisesRegex(check.PackageError, 'DUPLICATE_JSON_KEY'):
            check.parse_json(b'{"path":"public","path":"other"}')
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / 'app.asar'
            path.write_bytes(struct.pack('<II', 4, 1 << 30) + b'{}')
            with self.assertRaisesRegex(check.PackageError, 'INVALID_ASAR_HEADER'):
                check.asar_entries(path)


@unittest.skipUnless(shutil.which('node'), 'Node.js is required to test the desktop build script')
class DesktopBuildRuntimeTests(unittest.TestCase):
    def test_build_rejects_forged_hashes_metadata_and_bytes_before_writing_resources(self):
        source = Path(__file__).resolve().parents[2]
        cases = [
            ('rewritten-hashes', 'Runtime checksum does not match the fixed desktop manifest'),
            ('mihomo_version', 'Runtime metadata does not match the fixed desktop manifest'),
            ('openconnect_version', 'Runtime metadata does not match the fixed desktop manifest'),
            ('extra-field', 'Invalid runtime manifest fields'),
            ('corrupted-bytes', 'Runtime checksum mismatch'),
            ('reordered-entries', 'Runtime checksum mismatch'),
        ]
        for change, expected in cases:
            with self.subTest(change=change), tempfile.TemporaryDirectory() as root:
                repo = Path(root)
                script = repo / 'desktop/scripts/build-backend.mjs'
                write(script, (source / 'desktop/scripts/build-backend.mjs').read_bytes())
                write(script.with_name('generate-icons.mjs'), (source / 'desktop/scripts/generate-icons.mjs').read_bytes())
                reference = real_fixed_runtime_manifest('windows')
                write(repo / 'scripts/runtime-manifest.windows-amd64.json', json.dumps(reference).encode())
                manifest = json.loads(json.dumps(reference))
                runtime = repo / 'runtime-input'
                for entry in manifest['files']:
                    data = ('untrusted:' + entry['path']).encode()
                    write(runtime / entry['path'], data)
                    if change == 'rewritten-hashes':
                        entry['sha256'] = hashlib.sha256(data).hexdigest()
                for name in check.NOTICES['windows']:
                    write(runtime / name, b'Public fixture license\n')
                if change in ('mihomo_version', 'openconnect_version'):
                    manifest[change] = 'unreviewed-version'
                elif change == 'extra-field':
                    manifest['unexpected'] = 'fixture'
                elif change == 'reordered-entries':
                    manifest['files'].reverse()
                write(runtime / 'manifest.json', json.dumps(manifest).encode())
                result = subprocess.run([shutil.which('node'), str(script), '--target', 'windows/amd64'],
                                        cwd=repo, env={**os.environ, 'LUMINA_BUILD_RUNTIME': str(runtime)},
                                        capture_output=True, text=True, timeout=15)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(expected, result.stderr)
                self.assertFalse((repo / 'desktop/resources').exists(),
                                 'Unverified runtime must not trigger backend build or resource writes')


if __name__ == '__main__':
    unittest.main()
