import { spawnSync } from 'node:child_process'
import { createHash } from 'node:crypto'
import { lstat, mkdir, readFile, readdir, realpath, rename, rm, writeFile } from 'node:fs/promises'
import { dirname, isAbsolute, join, relative, resolve, sep } from 'node:path'
import { fileURLToPath } from 'node:url'

const MANIFEST = 'scripts/runtime-manifest.windows-amd64.json'
const MANIFEST_KEYS = ['version', 'os', 'arch', 'mihomo_version', 'openconnect_version', 'files']
const NOTICES = ['notices/Go-LICENSE', 'notices/mihomo-LICENSE', 'notices/yaml-LICENSE',
  'notices/openconnect/COPYING.LGPL', 'notices/windows-components.txt']
const LEGAL = [['licenses/golang-x-sys.txt', 'legal/golang-x-sys.txt'], ['THIRD_PARTY.md', 'legal/THIRD_PARTY.md']]
const ENTRIES = [
  { kind: 'service', path: 'lumina-service.exe', packagePath: './cmd/lumina-service' },
  { kind: 'user_worker', path: 'lumina-user-worker.exe', packagePath: './cmd/lumina-user-worker' },
  { kind: 'lifecycle', path: 'netlaunch.exe', packagePath: './cmd/netlaunch' },
]
const MODE_TAGS = { daily: ['windows_client'], validation: ['windows_client', 'windows_client_validation'] }
const MAX_FILE = 256 << 20
const MAX_TEXT = 1 << 20
const digest = bytes => createHash('sha256').update(bytes).digest('hex')
const canonicalPath = path => process.platform === 'win32' ? resolve(path).toLowerCase() : resolve(path)
const comparePath = (a, b) => a.path < b.path ? -1 : a.path > b.path ? 1 : 0

function buildTags(options, mode) {
  if (Object.hasOwn(options, 'tags')) throw new Error('Custom build tags are not accepted')
  if (typeof mode !== 'string' || !Object.hasOwn(MODE_TAGS, mode)) throw new Error('Windows release mode must be daily or validation')
  return MODE_TAGS[mode].join(',')
}

function absolute(path, label) {
  if (typeof path !== 'string' || !path || path.includes('\0')) throw new Error(`${label} is required`)
  return resolve(path)
}

// Check ancestors too: accepting a regular leaf through a junction/symlink is
// insufficient, especially before creating a fresh output directory.
async function regularPath(path, kind) {
  const chain = []
  for (let current = path; ; current = dirname(current)) {
    chain.push(current)
    if (dirname(current) === current) break
  }
  for (const current of chain.reverse()) {
    const info = await lstat(current)
    if (info.isSymbolicLink() || canonicalPath(await realpath(current)) !== canonicalPath(current)) {
      throw new Error('Symlink, junction or redirected path is not allowed: ' + current)
    }
    if (current !== path && !info.isDirectory()) throw new Error('Path ancestor is not a directory')
    if (current === path && !(kind === 'file' ? info.isFile() : info.isDirectory())) {
      throw new Error(`Expected a regular ${kind}: ${current}`)
    }
  }
}

async function boundedFile(path, maximum = MAX_FILE) {
  await regularPath(path, 'file')
  if ((await lstat(path)).size > maximum) throw new Error('Payload file exceeds its size limit')
  const bytes = await readFile(path)
  if (bytes.length > maximum) throw new Error('Payload file exceeds its size limit')
  return bytes
}

function exactKeys(value, keys) {
  return value && typeof value === 'object' && !Array.isArray(value)
    && Object.keys(value).length === keys.length && keys.every(key => Object.hasOwn(value, key))
}

function decodeManifest(bytes) {
  let manifest
  try { manifest = JSON.parse(bytes.toString('utf8')) } catch { throw new Error('Invalid runtime manifest JSON') }
  if (!exactKeys(manifest, MANIFEST_KEYS) || manifest.version !== 1 || manifest.os !== 'windows'
      || manifest.arch !== 'amd64' || !Array.isArray(manifest.files) || manifest.files.length !== 18
      || ![manifest.mihomo_version, manifest.openconnect_version].every(value => typeof value === 'string' && value.length > 0 && value.length <= 128)) {
    throw new Error('Runtime manifest does not describe the fixed Windows amd64 layout')
  }
  const seen = new Set()
  for (const entry of manifest.files) {
    if (!exactKeys(entry, ['path', 'sha256']) || typeof entry.path !== 'string'
        || !/^(bin|lib|certs)\/[A-Za-z0-9._-]+$/.test(entry.path)
        || ['.', '..'].includes(entry.path.split('/')[1])
        || typeof entry.sha256 !== 'string' || !/^[a-f0-9]{64}$/.test(entry.sha256)
        || seen.has(entry.path.toLowerCase())) throw new Error('Invalid or duplicate runtime manifest entry')
    seen.add(entry.path.toLowerCase())
  }
  if (!['bin/mihomo.exe', 'bin/openconnect.exe', 'bin/wintun.dll', 'certs/ca-bundle.crt'].every(path => seen.has(path))) {
    throw new Error('Required Windows runtime component is missing')
  }
  return manifest
}

function normalizedManifest(manifest) {
  return Object.fromEntries(MANIFEST_KEYS.map(key => [key, key === 'files'
    ? manifest.files.map(({ path, sha256 }) => ({ path, sha256 })).sort(comparePath)
    : manifest[key]]))
}

async function inspectTree(root, allowed) {
  const directories = new Set()
  for (const path of allowed) for (let parent = dirname(path); parent !== '.'; parent = dirname(parent)) directories.add(parent.split(sep).join('/'))
  const found = new Set()
  async function visit(directory, prefix = '') {
    await regularPath(directory, 'directory')
    for (const name of await readdir(directory)) {
      const path = prefix + name
      const full = join(directory, name)
      const info = await lstat(full)
      if (info.isSymbolicLink()) throw new Error('Payload symlinks/junctions are not allowed')
      if (info.isDirectory()) {
        if (!directories.has(path)) throw new Error('Payload includes an undeclared directory: ' + path)
        await visit(full, path + '/')
      } else if (!info.isFile() || !allowed.has(path)) throw new Error('Payload includes an undeclared file: ' + path)
      else found.add(path)
    }
  }
  await visit(root)
  if (found.size !== allowed.size) throw new Error('Payload is missing a declared file')
}

async function runtimePayload(repoRoot, runtimeRoot) {
  // The reference is always part of the trusted source checkout, never selected
  // by runtime input, an environment override, or a service RPC.
  const reference = decodeManifest(await boundedFile(join(repoRoot, MANIFEST), MAX_TEXT))
  const supplied = decodeManifest(await boundedFile(join(runtimeRoot, 'manifest.json'), MAX_TEXT))
  const normalized = normalizedManifest(reference)
  if (JSON.stringify(normalizedManifest(supplied)) !== JSON.stringify(normalized)) {
    throw new Error('Runtime metadata/components/checksums differ from the fixed source reference')
  }
  await inspectTree(runtimeRoot, new Set(['manifest.json', ...reference.files.map(entry => entry.path), ...NOTICES]))
  const payload = new Map()
  for (const entry of normalized.files) {
    const bytes = await boundedFile(join(runtimeRoot, entry.path))
    if (digest(bytes) !== entry.sha256) throw new Error('Runtime component checksum mismatch: ' + entry.path)
    payload.set('runtime/' + entry.path, bytes)
  }
  for (const path of NOTICES) {
    const bytes = await boundedFile(join(runtimeRoot, path), MAX_TEXT)
    if (bytes.includes(0)) throw new Error('Runtime notice is not plain text')
    payload.set('runtime/' + path, bytes)
  }
  const manifestBytes = Buffer.from(JSON.stringify(normalized, null, 2) + '\n')
  payload.set('runtime/manifest.json', manifestBytes)
  for (const [source, destination] of LEGAL) {
    const bytes = await boundedFile(join(repoRoot, source), MAX_TEXT)
    if (bytes.includes(0)) throw new Error('Legal notice is not plain text')
    payload.set(destination, bytes)
  }
  return { payload, manifestDigest: digest(manifestBytes) }
}

export async function defaultBuild(options) {
  const { repoRoot, goPath, packagePath, outputFile, mode = 'daily' } = options
  const tags = buildTags(options, mode)
  const result = spawnSync(goPath, ['build', '-tags', tags, '-trimpath', '-buildvcs=false', '-o', outputFile, packagePath], {
    cwd: repoRoot, shell: false, stdio: 'inherit', timeout: 180_000,
    env: { ...process.env, GOOS: 'windows', GOARCH: 'amd64', CGO_ENABLED: '0', GOTOOLCHAIN: 'local', GOENV: 'off',
      GOFLAGS: '', GOCACHEPROG: '', GOWORK: 'off', GOPROXY: 'off', GOSUMDB: 'off', GOPRIVATE: '', GONOPROXY: 'none', GOVCS: '*:off' },
  })
  if (result.error || result.status !== 0 || result.signal) throw new Error('Windows Go build failed for ' + packagePath)
}

async function copyVerified(root, path, bytes, executable = false) {
  const destination = join(root, path)
  await mkdir(dirname(destination), { recursive: true, mode: 0o700 })
  await regularPath(dirname(destination), 'directory')
  await writeFile(destination, bytes, { flag: 'wx', mode: executable ? 0o755 : 0o644 })
  if (digest(await boundedFile(destination)) !== digest(bytes)) throw new Error('Staged file failed copy readback: ' + path)
}

/** Build-only entry point. No payload is run, installed, or authorized here. */
export async function stageWindowsRelease(options = {}) {
  let { repoRoot, runtimeRoot, outputRoot, goPath = process.env.NETLAUNCH_GO || 'go', build = defaultBuild, mode = 'daily' } = options
  buildTags(options, mode)
  repoRoot = absolute(repoRoot, 'repoRoot')
  runtimeRoot = absolute(runtimeRoot, 'runtimeRoot')
  outputRoot = absolute(outputRoot, 'outputRoot')
  if (typeof build !== 'function' || typeof goPath !== 'string' || !goPath || goPath.includes('\0')) throw new Error('Invalid build function or Go path')
  const fromRuntime = relative(runtimeRoot, outputRoot)
  if (!fromRuntime || (!fromRuntime.startsWith('..' + sep) && fromRuntime !== '..' && !isAbsolute(fromRuntime))) {
    throw new Error('Output must be outside the runtime source')
  }
  await regularPath(repoRoot, 'directory')
  await regularPath(runtimeRoot, 'directory')
  await regularPath(dirname(outputRoot), 'directory')
  // mkdir without recursive is the exclusive claim. Existing output is never
  // reused, emptied, or deleted, including failed earlier attempts.
  await mkdir(outputRoot, { mode: 0o700 })
  await regularPath(outputRoot, 'directory')
  const buildRoot = join(outputRoot, '.build')
  const payloadRoot = join(outputRoot, '.payload')
  await mkdir(buildRoot, { mode: 0o700 })
  await mkdir(payloadRoot, { mode: 0o700 })
  const { payload, manifestDigest } = await runtimePayload(repoRoot, runtimeRoot)
  const executableHashes = new Map()
  for (const entry of ENTRIES) {
    const outputFile = join(buildRoot, entry.path)
    const result = await build({ repoRoot, goPath, packagePath: entry.packagePath, outputFile, target: 'windows/amd64', mode })
    if (result?.error || result?.signal || (result?.status !== undefined && result.status !== 0)) throw new Error('Windows builder reported failure')
    const bytes = await boundedFile(outputFile)
    if (!bytes.length) throw new Error('Windows builder produced an empty executable')
    executableHashes.set(entry.kind, digest(bytes))
    payload.set(entry.path, bytes)
  }
  await inspectTree(buildRoot, new Set(ENTRIES.map(entry => entry.path)))
  // Include every staged file, including notices and legal text. The catalog
  // is published afterward and is deliberately excluded to avoid a hash cycle.
  const identity = { version: 1, files: [...payload].map(([path, bytes]) => ({ path, sha256: digest(bytes) })).sort(comparePath) }
  const releaseID = digest(Buffer.from(JSON.stringify(identity) + '\n'))
  for (const [path, bytes] of payload) await copyVerified(payloadRoot, path, bytes, ENTRIES.some(entry => entry.path === path))
  await inspectTree(payloadRoot, new Set(payload.keys()))
  const catalog = {
    release_id: releaseID,
    files: Object.fromEntries([
      ...ENTRIES.map(entry => [entry.kind, { sha256: executableHashes.get(entry.kind) }]),
      ['core', { sha256: digest(payload.get('runtime/bin/mihomo.exe')) }],
      ['vpn', { sha256: digest(payload.get('runtime/bin/openconnect.exe')) }],
    ]),
    runtime_manifest_sha256: manifestDigest,
  }
  await mkdir(join(outputRoot, 'releases'), { mode: 0o700 })
  const releaseRoot = join(outputRoot, 'releases', releaseID)
  await rename(payloadRoot, releaseRoot)
  // Only our exclusively created temporary build directory is removed, and
  // only after successful validation. Failures retain materials for inspection.
  await rm(buildRoot, { recursive: true })
  const catalogBytes = Buffer.from(JSON.stringify(catalog, null, 2) + '\n')
  await copyVerified(outputRoot, '.catalog.pending', catalogBytes)
  const catalogPath = join(outputRoot, 'release-catalog.json')
  await rename(join(outputRoot, '.catalog.pending'), catalogPath)
  return { outputRoot, releaseRoot, releaseID, catalogPath, catalog, runtimeManifestSHA256: manifestDigest }
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const options = { repoRoot: resolve(dirname(fileURLToPath(import.meta.url)), '../..') }
  const flags = new Map([['--repo-root', 'repoRoot'], ['--runtime-root', 'runtimeRoot'], ['--output-root', 'outputRoot'], ['--go', 'goPath'], ['--mode', 'mode']])
  const seen = new Set()
  try {
    for (let index = 2; index < process.argv.length; index += 2) {
      const key = flags.get(process.argv[index])
      const value = process.argv[index + 1]
      if (!key || seen.has(key) || !value || value.startsWith('--')) throw new Error('Usage: windows-release-stage.mjs --runtime-root DIR --output-root NEW_DIR [--repo-root DIR] [--go GO] [--mode daily|validation]')
      seen.add(key); options[key] = value
    }
    const result = await stageWindowsRelease(options)
    process.stdout.write(`Staged Windows release ${result.releaseID}\n${result.outputRoot}\n`)
  } catch (error) {
    process.stderr.write((error instanceof Error ? error.message : 'Windows release staging failed') + '\n')
    process.exitCode = 1
  }
}
