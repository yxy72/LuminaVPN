import assert from 'node:assert/strict'
import childProcess from 'node:child_process'
import { createHash } from 'node:crypto'
import { lstat, mkdir, mkdtemp, readFile, readdir, realpath, rm, symlink, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { syncBuiltinESMExports } from 'node:module'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import test from 'node:test'
import { defaultBuild, stageWindowsRelease } from '../scripts/windows-release-stage.mjs'

const repository = resolve(dirname(fileURLToPath(import.meta.url)), '../..')
const referencePath = 'scripts/runtime-manifest.windows-amd64.json'
const hash = bytes => createHash('sha256').update(bytes).digest('hex')
const notices = ['notices/Go-LICENSE', 'notices/mihomo-LICENSE', 'notices/yaml-LICENSE',
  'notices/openconnect/COPYING.LGPL', 'notices/windows-components.txt']
const imagePaths = { service: 'lumina-service.exe', user_worker: 'lumina-user-worker.exe',
  lifecycle: 'netlaunch.exe', core: 'runtime/bin/mihomo.exe', vpn: 'runtime/bin/openconnect.exe' }

async function put(root, path, bytes) {
  await mkdir(dirname(join(root, path)), { recursive: true })
  await writeFile(join(root, path), bytes)
}

async function fixture(t) {
  const root = await mkdtemp(join(await realpath(tmpdir()), 'lumina-release-test-'))
  t.after(() => rm(root, { recursive: true, force: true }))
  const repoRoot = join(root, 'source')
  const runtimeRoot = join(root, 'runtime')
  await mkdir(repoRoot)
  await mkdir(runtimeRoot)
  const manifest = JSON.parse(await readFile(join(repository, referencePath), 'utf8'))
  for (const entry of manifest.files) {
    const bytes = Buffer.from('fixture-runtime:' + entry.path)
    entry.sha256 = hash(bytes)
    await put(runtimeRoot, entry.path, bytes)
  }
  for (const path of notices) await put(runtimeRoot, path, 'License fixture for ' + path + '\n')
  await put(repoRoot, 'licenses/golang-x-sys.txt', 'Go x/sys license fixture\n')
  await put(repoRoot, 'THIRD_PARTY.md', 'Third party license fixture\n')
  await put(repoRoot, referencePath, JSON.stringify(manifest, null, 2))
  await put(runtimeRoot, 'manifest.json', JSON.stringify(manifest))
  const calls = []
  const build = async spec => {
    calls.push(spec)
    await writeFile(spec.outputFile, `fixture-executable:${spec.mode}:${spec.packagePath}`)
  }
  const options = output => ({ repoRoot, runtimeRoot, outputRoot: join(root, output), goPath: 'unused-fixture-go', build })
  return { root, repoRoot, runtimeRoot, manifest, calls, build, options }
}

async function missing(path) {
  await assert.rejects(lstat(path), { code: 'ENOENT' })
}

test('production builder fixes its command and disables user Go settings without launching it', async t => {
  const calls = []
  let status = 0
  t.mock.method(childProcess, 'spawnSync', (...args) => { calls.push(args); return { status } })
  syncBuiltinESMExports()
  try {
    const request = { repoRoot: '/source', goPath: '/tools/go', packagePath: './cmd/lumina-service', outputFile: '/output/service.exe' }
    for (const [mode, tags] of [[undefined, 'windows_client'], ['daily', 'windows_client'], ['validation', 'windows_client,windows_client_validation']]) {
      await defaultBuild({ ...request, ...(mode ? { mode } : {}) })
      assert.deepEqual(calls.at(-1)[1], ['build', '-tags', tags, '-trimpath', '-buildvcs=false', '-o', request.outputFile, request.packagePath])
    }
    const [go, args, options] = calls[0]
    assert.equal(go, request.goPath)
    assert.deepEqual(args, ['build', '-tags', 'windows_client', '-trimpath', '-buildvcs=false', '-o', request.outputFile, request.packagePath])
    assert.equal(options.cwd, request.repoRoot)
    assert.equal(options.shell, false)
    assert.ok(options.timeout > 0 && options.timeout <= 180_000)
    for (const [key, value] of Object.entries({ GOOS: 'windows', GOARCH: 'amd64', CGO_ENABLED: '0',
      GOTOOLCHAIN: 'local', GOENV: 'off', GOFLAGS: '', GOCACHEPROG: '', GOWORK: 'off', GOPROXY: 'off', GOSUMDB: 'off', GOVCS: '*:off' })) {
      assert.equal(options.env[key], value)
    }
    status = 1
    await assert.rejects(defaultBuild(request), /Windows Go build failed/)
    const beforeInvalid = calls.length
    for (const extra of [{ mode: 'other' }, { mode: 'DAILY' }, { tags: ['windows_client'] }, { mode: 'validation', tags: 'windows_client' }]) {
      await assert.rejects(defaultBuild({ ...request, ...extra }), /mode must be|Custom build tags/)
    }
    assert.equal(calls.length, beforeInvalid)
  } finally {
    t.mock.restoreAll()
    syncBuiltinESMExports()
  }
})

test('stages all fixed images, runtime components and licenses with readback hashes', async t => {
  const f = await fixture(t)
  const result = await stageWindowsRelease(f.options('release'))
  assert.deepEqual(f.calls.map(call => call.packagePath), ['./cmd/lumina-service', './cmd/lumina-user-worker', './cmd/netlaunch'])
  for (const call of f.calls) {
    assert.equal(call.target, 'windows/amd64')
    assert.equal(call.mode, 'daily')
    assert.equal(Object.hasOwn(call, 'tags'), false)
    assert.equal(call.goPath, 'unused-fixture-go')
    assert.equal(call.repoRoot, f.repoRoot)
  }
  assert.match(result.releaseID, /^[a-f0-9]{64}$/)
  const catalog = JSON.parse(await readFile(result.catalogPath, 'utf8'))
  assert.deepEqual(catalog, result.catalog)
  assert.equal(catalog.release_id, result.releaseID)
  assert.deepEqual(Object.keys(catalog.files).sort(), Object.keys(imagePaths).sort())
  for (const [kind, path] of Object.entries(imagePaths)) {
    assert.equal(catalog.files[kind].sha256, hash(await readFile(join(result.releaseRoot, path))))
  }
  const stagedManifest = await readFile(join(result.releaseRoot, 'runtime/manifest.json'))
  assert.equal(catalog.runtime_manifest_sha256, hash(stagedManifest))
  assert.equal(result.runtimeManifestSHA256, catalog.runtime_manifest_sha256)
  for (const entry of f.manifest.files) {
    assert.deepEqual(await readFile(join(result.releaseRoot, 'runtime', entry.path)), await readFile(join(f.runtimeRoot, entry.path)))
  }
  for (const path of notices) assert.deepEqual(await readFile(join(result.releaseRoot, 'runtime', path)), await readFile(join(f.runtimeRoot, path)))
  assert.equal(await readFile(join(result.releaseRoot, 'legal/golang-x-sys.txt'), 'utf8'), 'Go x/sys license fixture\n')
  assert.equal(await readFile(join(result.releaseRoot, 'legal/THIRD_PARTY.md'), 'utf8'), 'Third party license fixture\n')
  assert.deepEqual((await readdir(result.outputRoot)).sort(), ['release-catalog.json', 'releases'])
})

test('validation mode reaches all three fixed entries and is bound through their bytes', async t => {
  const f = await fixture(t)
  const daily = await stageWindowsRelease(f.options('daily'))
  const validation = await stageWindowsRelease({ ...f.options('validation'), mode: 'validation' })
  assert.deepEqual(f.calls.slice(0, 3).map(call => call.mode), ['daily', 'daily', 'daily'])
  assert.deepEqual(f.calls.slice(3).map(call => call.mode), ['validation', 'validation', 'validation'])
  assert.deepEqual(f.calls.slice(3).map(call => call.packagePath), ['./cmd/lumina-service', './cmd/lumina-user-worker', './cmd/netlaunch'])
  assert.notEqual(daily.releaseID, validation.releaseID)
  assert.deepEqual(Object.keys(daily.catalog), Object.keys(validation.catalog))
  assert.equal(Object.hasOwn(validation.catalog, 'mode'), false)
})

test('unknown modes and custom tags are rejected before claiming output or invoking a builder', async t => {
  const f = await fixture(t)
  for (const [index, extra] of [{ mode: 'other' }, { mode: 'DAILY' }, { mode: null }, { tags: ['windows_client'] }, { mode: 'validation', tags: undefined }].entries()) {
    const options = { ...f.options('invalid-' + index), ...extra }
    await assert.rejects(stageWindowsRelease(options), /mode must be|Custom build tags/)
    await missing(options.outputRoot)
  }
  assert.equal(f.calls.length, 0)
})

test('entry order and manifest formatting do not change the content identity', async t => {
  const f = await fixture(t)
  const first = await stageWindowsRelease(f.options('first'))
  f.manifest.files.reverse()
  await put(f.repoRoot, referencePath, JSON.stringify(f.manifest))
  await put(f.runtimeRoot, 'manifest.json', JSON.stringify({ files: f.manifest.files, ...Object.fromEntries(Object.entries(f.manifest).filter(([key]) => key !== 'files')) }, null, 4))
  const second = await stageWindowsRelease(f.options('second'))
  assert.equal(first.releaseID, second.releaseID)
  assert.deepEqual(first.catalog, second.catalog)
  assert.deepEqual(f.calls.slice(0, 3).map(call => call.packagePath), f.calls.slice(3).map(call => call.packagePath))
  assert.deepEqual(await readFile(join(first.releaseRoot, 'runtime/manifest.json')), await readFile(join(second.releaseRoot, 'runtime/manifest.json')))
})

test('changing an executable or a reference-bound runtime component changes the ID', async t => {
  const f = await fixture(t)
  const first = await stageWindowsRelease(f.options('first'))
  const second = await stageWindowsRelease({ ...f.options('second'), build: async spec => {
    await f.build(spec)
    if (spec.packagePath === './cmd/lumina-service') await writeFile(spec.outputFile, 'different service fixture')
  } })
  assert.notEqual(first.releaseID, second.releaseID)
  const entry = f.manifest.files[0]
  const bytes = Buffer.from('new fixture runtime component')
  entry.sha256 = hash(bytes)
  await put(f.runtimeRoot, entry.path, bytes)
  await put(f.repoRoot, referencePath, JSON.stringify(f.manifest))
  await put(f.runtimeRoot, 'manifest.json', JSON.stringify(f.manifest))
  const third = await stageWindowsRelease(f.options('third'))
  assert.notEqual(first.releaseID, third.releaseID)
})

test('runtime notices and legal text are also covered by the release identity', async t => {
  const f = await fixture(t)
  const first = await stageWindowsRelease(f.options('first'))
  await put(f.runtimeRoot, notices[0], 'Updated runtime license text\n')
  const second = await stageWindowsRelease(f.options('second'))
  assert.notEqual(first.releaseID, second.releaseID)
  assert.equal(first.runtimeManifestSHA256, second.runtimeManifestSHA256)
  await put(f.repoRoot, 'THIRD_PARTY.md', 'Updated third-party license text\n')
  const third = await stageWindowsRelease(f.options('third'))
  assert.notEqual(second.releaseID, third.releaseID)
})

test('tampered metadata, hashes, component sets and traversal are rejected before build', async t => {
  const cases = [
    ['metadata', value => { value.mihomo_version = 'different-version' }],
    ['hash', value => { value.files[0].sha256 = '0'.repeat(64) }],
    ['duplicate', value => { value.files[1] = value.files[0] }],
    ['missing', value => { value.files.pop() }],
    ['traversal', value => { value.files[0].path = 'bin/../outside.exe' }],
    ['unknown-key', value => { value.override_reference = 'other.json' }],
  ]
  for (const [name, change] of cases) await t.test(name, async t => {
    const f = await fixture(t)
    change(f.manifest)
    await put(f.runtimeRoot, 'manifest.json', JSON.stringify(f.manifest))
    const options = f.options('rejected')
    await assert.rejects(stageWindowsRelease(options))
    assert.equal(f.calls.length, 0)
    await missing(join(options.outputRoot, 'release-catalog.json'))
  })
})

test('component bytes cannot be authorized by a runtime-local replacement manifest', async t => {
  const f = await fixture(t)
  const entry = f.manifest.files[0]
  const modified = Buffer.from('unreviewed component')
  await put(f.runtimeRoot, entry.path, modified)
  await assert.rejects(stageWindowsRelease(f.options('bad-bytes')), /checksum mismatch/)
  entry.sha256 = hash(modified)
  await put(f.runtimeRoot, 'manifest.json', JSON.stringify(f.manifest))
  await assert.rejects(stageWindowsRelease(f.options('bad-manifest')), /fixed source reference/)
  assert.equal(f.calls.length, 0)
})

test('unknown files, unknown empty directories and missing notices are rejected', async t => {
  for (const kind of ['unknown-file', 'unknown-directory', 'missing-notice']) await t.test(kind, async t => {
    const f = await fixture(t)
    if (kind === 'unknown-file') await put(f.runtimeRoot, 'bin/unreviewed.dll', 'extra')
    else if (kind === 'unknown-directory') await mkdir(join(f.runtimeRoot, 'extra-empty'))
    else await rm(join(f.runtimeRoot, notices[0]))
    await assert.rejects(stageWindowsRelease(f.options('bad-tree')))
    assert.equal(f.calls.length, 0)
  })
})

test('output is exclusive and cannot be placed inside the input runtime', async t => {
  const f = await fixture(t)
  const options = f.options('already-there')
  await mkdir(options.outputRoot)
  await put(options.outputRoot, 'keep.txt', 'must remain unchanged')
  await assert.rejects(stageWindowsRelease(options), { code: 'EEXIST' })
  assert.equal(await readFile(join(options.outputRoot, 'keep.txt'), 'utf8'), 'must remain unchanged')
  await assert.rejects(stageWindowsRelease({ ...f.options('unused'), outputRoot: join(f.runtimeRoot, 'output') }), /outside the runtime/)
  await missing(join(f.runtimeRoot, 'output'))
  assert.equal(f.calls.length, 0)
})

test('symlink or junction ancestors cannot redirect a fresh output directory', async t => {
  const f = await fixture(t)
  const actual = join(f.root, 'actual-output-parent')
  const alias = join(f.root, 'output-parent-alias')
  await mkdir(actual)
  await symlink(actual, alias, process.platform === 'win32' ? 'junction' : 'dir')
  await assert.rejects(stageWindowsRelease({ ...f.options('unused'), outputRoot: join(alias, 'new-output') }), /Symlink|junction|redirected/)
  await missing(join(actual, 'new-output'))
  assert.equal(f.calls.length, 0)
})

test('a runtime-root symlink or junction is rejected', async t => {
  const f = await fixture(t)
  const alias = join(f.root, 'runtime-alias')
  await symlink(f.runtimeRoot, alias, process.platform === 'win32' ? 'junction' : 'dir')
  await assert.rejects(stageWindowsRelease({ ...f.options('unused'), runtimeRoot: alias }), /Symlink|junction|redirected/)
  assert.equal(f.calls.length, 0)
})

test('a nested runtime symlink is rejected', async t => {
  const f = await fixture(t)
  const component = join(f.runtimeRoot, f.manifest.files[0].path)
  const actual = join(f.root, 'component-bytes')
  await writeFile(actual, await readFile(component))
  await rm(component)
  try { await symlink(actual, component, 'file') } catch (error) {
    if (process.platform === 'win32' && error.code === 'EPERM') return t.skip('Windows file symlinks require local symlink privileges')
    throw error
  }
  await assert.rejects(stageWindowsRelease(f.options('linked-component')), /symlink|junction/i)
  assert.equal(f.calls.length, 0)
})

test('a later builder failure leaves material without publishing a catalog', async t => {
  const f = await fixture(t)
  let count = 0
  const options = { ...f.options('failed'), build: async spec => {
    await f.build(spec)
    if (++count === 2) return { status: 2 }
  } }
  await assert.rejects(stageWindowsRelease(options), /builder reported failure/)
  await missing(join(options.outputRoot, 'release-catalog.json'))
  assert.equal((await readdir(join(options.outputRoot, '.build'))).length, 2)
  assert.equal(await readFile(join(options.outputRoot, '.build/lumina-service.exe'), 'utf8'), 'fixture-executable:daily:./cmd/lumina-service')
})

test('empty or undeclared build outputs cannot become an approved release', async t => {
  for (const kind of ['empty', 'extra']) await t.test(kind, async t => {
    const f = await fixture(t)
    const options = { ...f.options('bad-build'), build: async spec => {
      await f.build(spec)
      if (kind === 'empty') await writeFile(spec.outputFile, '')
      else await put(dirname(spec.outputFile), 'unreviewed.dll', 'extra')
    } }
    await assert.rejects(stageWindowsRelease(options), /empty executable|undeclared file/)
    await missing(join(options.outputRoot, 'release-catalog.json'))
  })
})
