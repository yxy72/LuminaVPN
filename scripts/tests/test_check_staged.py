import importlib.util
from pathlib import Path
import unittest
import subprocess
import tempfile
import sys

spec = importlib.util.spec_from_file_location('check_staged', Path(__file__).parents[1] / 'check-staged.py')
check = importlib.util.module_from_spec(spec)
spec.loader.exec_module(check)


class SourceBoundaryTests(unittest.TestCase):
    def test_public_windows_entries_have_a_narrow_allowlist(self):
        for name in ['scripts/package-windows.ps1', 'scripts/entries-windows/启动.cmd', 'scripts/entries-windows/诊断导出.cmd']:
            self.assertFalse(check.scan([(name, '100644', b'public launcher')], set()))
        for name in ['scripts/home.private.ps1', 'scripts/entries-windows/private.cmd', 'scripts/entries-windows/nested/启动.cmd', 'scripts/unknown.ps1']:
            self.assertTrue(check.scan([(name, '100644', b'local setup')], set()))

    def test_private_file_cannot_be_forced_into_index(self):
        for name in ['profiles/policy.json', '.local/result.json', 'scripts/network.private.json', 'dist/preview.zip', 'acceptance-report.md']:
            self.assertTrue(check.scan([(name, '100644', b'{}')], set()))

    def test_private_values_in_source_are_blocked_without_printing_values(self):
        values = check.private_values({'company': {'domains': ['hidden.corp.example']}, 'vpn': {'server': 'https://vpn.private.example:4433', 'endpoint_ipv4': '192.0.2.77'}})
        found = check.scan([('internal/app/config.go', '100644', b'var host = "hidden.corp.example"')], values)
        self.assertEqual(len(found), 1)
        self.assertNotIn('hidden.corp.example', repr(found))

    def test_public_fixtures_and_regular_source_are_allowed(self):
        self.assertFalse(check.scan([('examples/policy.json', '100644', b'{"host":"gateway.corp.example.com"}'), ('internal/auth/auth_test.go', '100644', b'cookie := "fixture-only"')], {'hidden.corp.example'}))

    def test_bootstrap_subscription_and_cached_node_secrets_are_matched(self):
        values = check.private_values({'policy': {}, 'subscriptions': {'nodes': {'url': 'https://source.example.com/?token=private-fixture-token'}}})
        values.update(check.node_values({'result': {'nodes': [{'uuid': 'private-node-fixture'}]}}))
        for value in ['private-fixture-token', 'private-node-fixture']:
            self.assertTrue(check.scan([('internal/app/config.go', '100644', value.encode())], values))

    def test_checks_index_even_after_worktree_is_sanitized(self):
        with tempfile.TemporaryDirectory() as root:
            root = Path(root)
            def git(*args):
                subprocess.run(['git', '-C', str(root), *args], check=True, capture_output=True)
            git('init', '-b', 'main')
            (root / 'internal').mkdir()
            source = root / 'internal' / 'config.go'
            source.write_text('const host = "private-fixture.example"')
            git('add', 'internal/config.go')
            source.write_text('const host = "example.com"')
            private = root / 'policy.private.json'
            private.write_text('{"company":{"domains":["private-fixture.example"]}}')
            git('config', '--local', 'lumina.privatePolicyFile', str(private))
            result = subprocess.run([sys.executable, str(Path(check.__file__).resolve()), '--all'], cwd=root, capture_output=True)
            self.assertEqual(result.returncode, 1)
            self.assertNotIn(b'private-fixture.example', result.stdout + result.stderr)
            git('add', 'internal/config.go')
            result = subprocess.run([sys.executable, str(Path(check.__file__).resolve()), '--all'], cwd=root, capture_output=True)
            self.assertEqual(result.returncode, 0)

    def test_binary_symlink_and_actual_key_header_are_rejected(self):
        for mode, data in [('100644', b'\x00bin'), ('120000', b'/private/local-profile'), ('100644', b'-----BEGIN ' + b'PRIVATE KEY-----')]:
            self.assertTrue(check.scan([('internal/test.go', mode, data)], set()))


if __name__ == '__main__': unittest.main()
