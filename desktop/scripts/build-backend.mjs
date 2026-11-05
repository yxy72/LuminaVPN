import { createHash } from 'node:crypto'
import { lstat, mkdir, readFile, readdir, rm, writeFile } from 'node:fs/promises'
import { existsSync } from 'node:fs'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { spawnSync } from 'node:child_process'
import { generateIcons } from './generate-icons.mjs'

const desktop = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const repo = resolve(desktop, '..')
const targetFlag = process.argv.indexOf('--target')
const target = targetFlag >= 0 ? process.argv[targetFlag + 1] : (process.platform === 'win32' ? 'windows' : process.platform) + '/' + (process.arch === 'x64' ? 'amd64' : process.arch)
if (!['darwin/arm64', 'windows/amd64'].includes(target)) throw new Error('Supported desktop targets: darwin/arm64 and windows/amd64')
const [os, arch] = target.split('/')
const runtimeSource = process.env.LUMINA_BUILD_RUNTIME ? resolve(process.env.LUMINA_BUILD_RUNTIME) : join(repo, 'runtime')
const manifest = JSON.parse(await readFile(join(runtimeSource, 'manifest.json'), 'utf8'))
if (!manifest || typeof manifest !== 'object' || manifest.os !== os || manifest.arch !== arch || manifest.version !== 1 || !Array.isArray(manifest.files)) throw new Error('Runtime does not match desktop target')
const reference = JSON.parse(await readFile(join(repo, 'scripts', os === 'darwin' ? 'runtime-manifest.macos-arm64.json' : 'runtime-manifest.windows-amd64.json'), 'utf8'))
const manifestKeys = ['version', 'os', 'arch', 'mihomo_version', 'openconnect_version', 'files']
if (Object.keys(manifest).length !== manifestKeys.length || manifestKeys.some(key => !(key in manifest))) throw new Error('Invalid runtime manifest fields')
if (manifestKeys.some(key => key !== 'files' && manifest[key] !== reference[key])) throw new Error('Runtime metadata does not match the fixed desktop manifest')
const required = new Set(reference.files.map(x => x.path))
if (manifest.files.some(entry => !entry || typeof entry !== 'object' || Object.keys(entry).length !== 2 || !Object.hasOwn(entry, 'path') || !Object.hasOwn(entry, 'sha256'))) throw new Error('Invalid runtime manifest entry')
if (manifest.files.length !== required.size || new Set(manifest.files.map(x => x.path)).size !== required.size || manifest.files.some(x => !required.has(x.path))) throw new Error('Runtime component set does not match the fixed desktop layout')
const fixedHashes = new Map(reference.files.map(entry => [entry.path, entry.sha256]))
if (manifest.files.some(entry => entry.sha256 !== fixedHashes.get(entry.path))) throw new Error('Runtime checksum does not match the fixed desktop manifest')
const notices = ['notices/Go-LICENSE', 'notices/mihomo-LICENSE', 'notices/yaml-LICENSE', 'notices/openconnect/COPYING.LGPL', os === 'darwin' ? 'notices/openssl@3/LICENSE.txt' : 'notices/windows-components.txt']
const allowed = new Set(['manifest.json', ...required, ...notices])
async function inspectTree(dir, prefix = '') {
  if (!(await lstat(dir)).isDirectory()) throw new Error('Runtime directory is not regular')
  for (const child of await readdir(dir, { withFileTypes: true })) {
    const path = prefix + child.name
    if (child.isSymbolicLink()) throw new Error('Runtime symlinks are not allowed')
    if (child.isDirectory()) await inspectTree(join(dir, child.name), path + '/')
    else if (!child.isFile() || !allowed.has(path)) throw new Error('Runtime includes an undeclared file')
  }
}
await inspectTree(runtimeSource)
const payload = new Map()
for (const entry of manifest.files) {
  if (!/^(bin|lib|certs)\/[a-zA-Z0-9._-]+$/.test(entry.path) || !/^[a-f0-9]{64}$/.test(entry.sha256) || !(await lstat(join(runtimeSource, entry.path))).isFile()) throw new Error('Invalid runtime manifest')
  const bytes = await readFile(join(runtimeSource, entry.path))
  const hash = createHash('sha256').update(bytes).digest('hex')
  if (hash !== entry.sha256) throw new Error('Runtime checksum mismatch')
  payload.set(entry.path, bytes)
}
for (const path of notices) {
  const bytes = await readFile(join(runtimeSource, path))
  if (bytes.length > 1 << 20 || bytes.includes(0)) throw new Error('Invalid runtime notice')
  payload.set(path, bytes)
}
payload.set('manifest.json', Buffer.from(JSON.stringify(manifest, null, 2) + '\n'))
const resources = join(desktop, 'resources')
for (const name of ['backend', 'recovery', 'legal']) await rm(join(resources, name), { recursive: true, force: true })
await mkdir(join(resources, 'backend'), { recursive: true })
const localGo = join(repo, '.tools', 'go', 'bin', process.platform === 'win32' ? 'go.exe' : 'go')
const go = process.env.NETLAUNCH_GO || (existsSync(localGo) ? localGo : 'go')
const binary = join(resources, 'backend', os === 'windows' ? 'netlaunch.exe' : 'netlaunch')
const build = spawnSync(go, ['build', '-trimpath', '-o', binary, './cmd/netlaunch'], { cwd: repo, env: { ...process.env, GOOS: os, GOARCH: arch }, stdio: 'inherit', shell: false })
if (build.error || build.status !== 0) throw new Error('Go backend build failed; set NETLAUNCH_GO to your Go executable')
await rm(join(resources, 'runtime'), { recursive: true, force: true })
for (const [path, bytes] of payload) {
  const destination = join(resources, 'runtime', path)
  await mkdir(dirname(destination), { recursive: true })
  await writeFile(destination, bytes, { mode: path.startsWith('bin/') ? 0o755 : 0o644 })
}
await mkdir(join(resources, 'recovery'), { recursive: true })
const entry = os === 'darwin'
  ? '#!/bin/sh\ncd "$(dirname "$0")" || exit 1\n../backend/netlaunch down --runtime ../runtime "$@"\nrc=$?\nprintf "\\n命令已结束（退出码 %s）。按回车关闭。\\n" "$rc"\nread answer\nexit "$rc"\n'
  : '@echo off\r\nsetlocal DisableDelayedExpansion\r\necho LuminaVPN read-only preview: network recovery is unavailable.\r\necho This bundled offline backend cannot stop or recover a network run.\r\necho Use the original NetLaunch CLI that created the run, or its frozen recovery entry.\r\necho Keep that run directory until recovery is confirmed.\r\npause\r\nexit /b 1\r\n'
await writeFile(join(resources, 'recovery', os === 'darwin' ? '停止与恢复.command' : 'Stop-and-Recover.cmd'), entry, { mode: 0o755 })
await mkdir(join(resources, 'legal'), { recursive: true })
for (const [source, name] of [['licenses/golang-x-sys.txt', 'golang-x-sys.txt'], ['THIRD_PARTY.md', 'THIRD_PARTY.md']]) await writeFile(join(resources, 'legal', name), await readFile(join(repo, source)))
await generateIcons(resources, os)
console.log('Built fixed backend and verified runtime for ' + target)
