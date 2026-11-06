#!/usr/bin/env python3
"""Check the actual Git index; optional local policy adds private-value matching."""
import argparse
import json
from pathlib import PurePosixPath
import re
import subprocess
import sys
from urllib.parse import urlsplit, parse_qsl


def git(*args, check=True):
    return subprocess.run(['git', *args], check=check, stdout=subprocess.PIPE, stderr=subprocess.PIPE).stdout


def allowed_path(name):
    p = PurePosixPath(name)
    if not p.parts:
        return False
    if any(part.startswith('.') and part not in {'.gitignore', '.gitattributes', '.githooks'} for part in p.parts):
        return False
    if any(part in {'private', 'profiles', 'runtime', 'dist', '__pycache__'} for part in p.parts):
        return False
    if '.private.' in p.name or p.name.startswith('.env'):
        return False
    if p.parts[0] == 'desktop':
        # Product source and fixed build/protocol files only. A desktop
        # subtree is not permission to commit profiles, bundles or QA output.
        excluded = {
            'node_modules', 'resources', 'out', 'cache', 'test-results',
            'test_results', 'playwright-report', 'coverage', 'reports',
            'report', 'results', 'result', 'acceptance', 'acceptance-report',
            'acceptance_report', '验收文档', '验收清单', '验收报告',
        }
        if any(part.lower() in excluded for part in p.parts):
            return False
        if re.match(r'^(?:acceptance(?:[-_.].*)?|验收.*|(?:test[-_])?(?:results?|reports?)(?:[-_.].*)?|coverage(?:[-_.].*)?)$', p.stem, re.I):
            return False
        fixed = {
            'desktop/package.json', 'desktop/package-lock.json',
            'desktop/tsconfig.json', 'desktop/electron.vite.config.ts',
            'desktop/vitest.config.ts', 'desktop/playwright.config.ts',
            'desktop/electron-builder.yml', 'desktop/scripts/build-backend.mjs',
            'desktop/scripts/generate-icons.mjs', 'desktop/assets/icon.svg',
            'desktop/scripts/windows-client-bootstrap.nsh',
            'desktop/scripts/windows-client-package.mjs',
            'desktop/scripts/windows-release-stage.mjs',
            'desktop/protocol/types.ts', 'desktop/protocol/validation.ts',
            'desktop/protocol/client.ts', 'desktop/protocol/validation-base.ts',
            'desktop/protocol/schema.json', 'desktop/protocol/fixtures.json',
            'desktop/tests/windows-client-package.test.mjs',
            'desktop/tests/windows-release-stage.test.mjs',
        }
        if name in fixed:
            return True
        if len(p.parts) >= 4 and p.parts[:3] == ('desktop', 'src', 'renderer'):
            return p.suffix in {'.ts', '.tsx', '.css', '.html'}
        if len(p.parts) >= 4 and p.parts[:3] in {
            ('desktop', 'src', 'main'), ('desktop', 'src', 'preload'),
        }:
            return p.suffix == '.ts'
        if len(p.parts) >= 3 and p.parts[:2] == ('desktop', 'tests'):
            return p.name.endswith(('.test.ts', '.electron.ts'))
        return False
    if name in {'.gitignore', '.gitattributes', 'README.md', 'THIRD_PARTY.md', 'LICENSE', 'LICENSE.md', 'AGENTS.md', 'go.mod', 'go.sum', '.githooks/pre-commit'}:
        return True
    if p.parts[0] in {'internal', 'cmd'} and p.suffix == '.go':
        return True
    if p.parts[0] == 'licenses' and p.suffix == '.txt':
        return True
    if name in {'examples/policy.json', 'examples/bootstrap.json'}:
        return True
    if name == 'scripts/package-windows.ps1':
        return True
    if name in {
        'scripts/patches/mihomo-v1.19.32-fakeip-pool-reuse.patch',
        'scripts/patches/mihomo-v1.19.32-fakeip-pool-reuse.provenance.json',
        'scripts/patches/mihomo-v1.19.32.LICENSE',
    }:
        return True
    if p.parent == PurePosixPath('scripts/entries-windows') and p.name in {
        '初始化.cmd', '检查环境.cmd', '启动.cmd', '状态.cmd', '停止与恢复.cmd',
        '公司认证.cmd', '同步订阅.cmd', '检查配置.cmd', '诊断导出.cmd', '版本信息.cmd',
    }:
        return True
    if p.parts[0] == 'scripts' and p.suffix in {'.sh', '.py', '.command'}:
        return True
    return name in {'scripts/runtime-manifest.macos-arm64.json', 'scripts/runtime-manifest.windows-amd64.json'}


def private_values(policy):
    result = set()
    sources = policy.get('subscriptions', {})
    for source in [sources.get('nodes', {})] + sources.get('rules', []):
        value = source.get('url', '')
        if value:
            result.add(value)
            result.update(v for _, v in parse_qsl(urlsplit(value).query) if len(v) >= 12)
    policy = policy.get('policy', policy)
    company = policy.get('company', {})
    for field in ('domains', 'cidrs', 'dns'):
        result.update(x for x in company.get(field, []) if isinstance(x, str) and x)
    vpn = policy.get('vpn', {})
    for value in (vpn.get('endpoint_ipv4'), urlsplit(vpn.get('server', '')).hostname):
        if value:
            result.add(value)
    return result


def node_values(data):
    if isinstance(data, dict): data = data.get('result', data).get('nodes', data.get('proxies', []))
    values = set()
    keys = {'uuid', 'password', 'obfs-password', 'private-key'}
    def visit(value):
        if isinstance(value, dict):
            for key, child in value.items():
                if key in keys and isinstance(child, str) and child: values.add(child)
                else: visit(child)
        elif isinstance(value, list):
            for child in value: visit(child)
    visit(data)
    return values

def scan(entries, private):
    failures = []
    patterns = [rb'-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----',
                rb'\bgh[pousr]_[A-Za-z0-9]{30,}\b', rb'\bAKIA[A-Z0-9]{16}\b']
    for name, mode, data in entries:
        reasons = []
        if not allowed_path(name): reasons.append('path is outside the source allowlist')
        if mode not in {'100644', '100755'}: reasons.append('non-regular Git entry')
        if b'\x00' in data: reasons.append('binary file')
        if any(re.search(pattern, data) for pattern in patterns): reasons.append('possible private key or access token')
        if any(value.encode().lower() in data.lower() for value in private): reasons.append('value from private network policy')
        if reasons: failures.append((name, reasons))
    return failures


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--all', action='store_true', help='check every indexed file')
    args = parser.parse_args()
    private = set()
    location = git('config', '--local', '--get', 'lumina.privatePolicyFile', check=False).decode().strip()
    if location:
        try:
            with open(location, encoding='utf-8') as f: private = private_values(json.load(f))
        except Exception:
            print('Cannot load configured private policy; no contents displayed.', file=sys.stderr)
            return 1
    nodes_location = git('config', '--local', '--get', 'lumina.privateNodeFile', check=False).decode().strip()
    if nodes_location:
        try:
            with open(nodes_location, encoding='utf-8') as f: private.update(node_values(json.load(f)))
        except Exception:
            print('Cannot load configured private node cache; no contents displayed.', file=sys.stderr)
            return 1
    names = git('ls-files', '-z') if args.all else git('diff', '--cached', '--name-only', '--diff-filter=ACMR', '-z')
    entries = []
    for raw in names.split(b'\x00'):
        if not raw: continue
        name = raw.decode('utf-8')
        row = git('ls-files', '--stage', '-z', '--', name).split(b'\x00')[0]
        mode, blob, stage = row.split(b'\t')[0].decode().split()
        if stage != '0':
            print('Unmerged index entry; resolve it before committing.', file=sys.stderr)
            return 1
        entries.append((name, mode, git('cat-file', 'blob', blob)))
    failures = scan(entries, private)
    for name, reasons in failures:
        print(name + ': ' + '; '.join(reasons), file=sys.stderr)
    if failures:
        print('Commit blocked. Move private data outside Git; do not bypass this check.', file=sys.stderr)
        return 1
    print('Source check passed for %d indexed files. This is not a complete secret audit.' % len(entries))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
