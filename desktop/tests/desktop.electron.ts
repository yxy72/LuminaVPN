import { test, expect, _electron as electron, type ElectronApplication, type Page } from '@playwright/test'
import { chmod, lstat, mkdir, mkdtemp, readFile, writeFile } from 'node:fs/promises'
import { isAbsolute, join, relative, resolve, sep } from 'node:path'
import { existsSync } from 'node:fs'
import { execFileSync } from 'node:child_process'

// Only protect freshly created fixture objects, never their existing parents.
// POSIX modes do not establish the protected DACL required by the Go readers.
async function protectFixtureObjects(root: string, paths: string[]): Promise<void> {
  const objects = await Promise.all(paths.map(async path => {
    const child = relative(root, path)
    if (isAbsolute(child) || child === '..' || child.startsWith('..' + sep)) throw new Error('Fixture object escapes its new root')
    const info = await lstat(path)
    if (info.isSymbolicLink() || !info.isDirectory() && !info.isFile()) throw new Error('Fixture object is not a regular file or directory')
    return { path, directory: info.isDirectory() }
  }))
  if (process.platform !== 'win32') {
    await Promise.all(objects.map(object => chmod(object.path, object.directory ? 0o700 : 0o600)))
    return
  }
  const script = `
$ErrorActionPreference = 'Stop'
$sid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
foreach ($object in (ConvertFrom-Json $env:LUMINA_E2E_PRIVATE_OBJECTS)) {
  if ($object.directory) {
    $acl = New-Object System.Security.AccessControl.DirectorySecurity
    $flags = 'OICI'
  } else {
    $acl = New-Object System.Security.AccessControl.FileSecurity
    $flags = ''
  }
  $sddl = 'O:' + $sid + 'D:P(A;' + $flags + ';FA;;;' + $sid + ')(A;' + $flags + ';FA;;;SY)(A;' + $flags + ';FA;;;BA)'
  # Only change the DACL. Importing every section also marks the audit section
  # dirty and makes .NET demand SeSecurityPrivilege from an ordinary user.
  $acl.SetSecurityDescriptorSddlForm($sddl, [System.Security.AccessControl.AccessControlSections]::Access)
  # Use the native .NET ACL API; a fresh PowerShell session need not have the
  # optional Microsoft.PowerShell.Security cmdlet module available to autoload.
  if ($object.directory) { ([System.IO.DirectoryInfo] $object.path).SetAccessControl($acl) }
  else { ([System.IO.FileInfo] $object.path).SetAccessControl($acl) }
}`
  execFileSync('powershell.exe', ['-NoProfile', '-NonInteractive', '-EncodedCommand', Buffer.from(script, 'utf16le').toString('base64')], {
    env: { ...process.env, LUMINA_E2E_PRIVATE_OBJECTS: JSON.stringify(objects) }, windowsHide: true, timeout: 15000, stdio: 'pipe'
  })
}

async function checkRecoveryCapability(page: Page, userData: string): Promise<void> {
  const hello = await page.evaluate(() => window.lumina.hello())
  const button = page.getByRole('button', { name: '找到独立恢复入口', exact: true })
  if (hello.capabilities.native_lifecycle) {
    await expect(button).toBeVisible()
    return
  }
  expect(process.platform).toBe('win32')
  expect(hello.mode).toBe('windows_offline')
  await expect(button).toHaveCount(0)
  expect((await page.evaluate(() => window.lumina.describeRecovery())).available).toBe(false)
  const code = await page.evaluate(async () => {
    try { await window.lumina.showRecovery(); return 'unexpected' }
    catch (error) { return error instanceof Error ? error.message : String(error) }
  })
  expect(code).toBe('RECOVERY_UNAVAILABLE')
  expect(existsSync(join(userData, 'recovery'))).toBe(false)
}

function processExists(pid: number): boolean {
  try { process.kill(pid, 0); return true }
  catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ESRCH') return false
    throw error
  }
}

async function ownBridgePID(application: ElectronApplication, binary: string): Promise<number> {
  // Inspect only handles belonging to this application's main process. This
  // avoids a system process scan and cannot select another installation's CLI.
  const children = await application.evaluate((_electron, expectedBinary) => {
    type ChildHandle = { pid?: number; spawnfile?: string; spawnargs?: string[] }
    const handles = (process as typeof process & { _getActiveHandles(): ChildHandle[] })._getActiveHandles()
    return handles.filter(handle => handle.spawnfile?.toLowerCase() === expectedBinary.toLowerCase()
      && handle.spawnargs?.[1] === 'desktop' && handle.spawnargs?.[2] === 'serve')
      .map(handle => Number(handle.pid))
  }, binary)
  expect(children).toHaveLength(1)
  expect(Number.isSafeInteger(children[0]) && children[0] > 0).toBe(true)
  expect(processExists(children[0])).toBe(true)
  return children[0]
}

async function checkWindowsTrayLifecycle(application: ElectronApplication, page: Page, executable: string, userData: string, env: Record<string, string>, bridgePID: number): Promise<void> {
  const session = (await page.evaluate(() => window.lumina.hello())).session_id
  const original = await application.evaluate(({ BrowserWindow }) => BrowserWindow.getAllWindows().map(window => window.id))
  expect(original).toHaveLength(1)
  await application.evaluate(({ BrowserWindow }) => BrowserWindow.getAllWindows()[0].close())
  await expect.poll(() => application.evaluate(({ BrowserWindow }) => BrowserWindow.getAllWindows().map(window => ({ id: window.id, visible: window.isVisible() })))).toEqual([{ id: original[0], visible: false }])
  expect(application.process().exitCode).toBeNull()
  expect(processExists(bridgePID)).toBe(true)

  // Run the installed executable normally with the same fixture userData.
  // Success requires the secondary process to exit cleanly, while its native
  // single-instance message restores the existing window and bridge session.
  execFileSync(executable, ['--user-data-dir=' + userData], { env, windowsHide: true, timeout: 8000, stdio: 'pipe' })
  await expect.poll(() => application.evaluate(({ BrowserWindow }) => BrowserWindow.getAllWindows().map(window => ({ id: window.id, visible: window.isVisible() })))).toEqual([{ id: original[0], visible: true }])
  await expect(page.getByText('控制接口可用', { exact: true }).first()).toBeVisible()
  expect((await page.evaluate(() => window.lumina.hello())).session_id).toBe(session)
  expect(processExists(bridgePID)).toBe(true)
}

test('desktop reads real fixtures, protects IPC and ages evidence', async () => {
  await mkdir(resolve('../.local'), { recursive: true })
  const root = await mkdtemp(join(resolve('../.local'), 'desktop-e2e-中文 空格-'))
  const profile = join(root, 'profile'), userData = join(root, 'userdata')
  await mkdir(profile, { mode: 0o700 }); await chmod(root, 0o700); await mkdir(userData)
  const policy = JSON.parse(await readFile(resolve('../examples/policy.json'), 'utf8'))
  policy.personal_rules = Array.from({ length: 151 }, (_, i) => ({ type: 'DOMAIN', value: `fixture-${i}.example.org`, target: 'personal' }))
  await writeFile(join(profile, 'policy.json'), JSON.stringify(policy), { mode: 0o600 })
  await writeFile(join(profile, 'nodes.json'), JSON.stringify([{ type: 'vless', server: '203.0.113.77', port: 443, uuid: 'desktop-secret-canary', tls: true }]), { mode: 0o600 })
  await protectFixtureObjects(root, [root, profile, join(profile, 'policy.json'), join(profile, 'nodes.json')])
  await writeFile(join(userData, 'preferences.json'), JSON.stringify({ profile, closeNoticeSeen: true }))
  const env: Record<string, string> = Object.fromEntries(Object.entries(process.env).filter((entry): entry is [string, string] => entry[1] !== undefined)); delete env.ELECTRON_RUN_AS_NODE; delete env.NODE_OPTIONS
  const application = await electron.launch({ args: [resolve('.'), '--user-data-dir=' + userData], cwd: resolve('.'), env })
  try {
    await application.context().route(/^https?:\/\//, route => route.abort())
    const page = await application.firstWindow(), errors: string[] = []
    page.on('pageerror', error => errors.push(error.message))
    await expect(page.getByText('控制接口可用', { exact: true }).first()).toBeVisible()
    expect(await page.evaluate(() => typeof (window as any).require)).toBe('undefined')
    await expect(page.getByRole('button', { name: '连接网络', exact: true })).toBeDisabled()
    await page.getByRole('button', { name: /代理节点/ }).click()
    await expect(page.getByText('P001', { exact: true }).first()).toBeVisible()
    expect(await page.evaluate(() => document.body.innerText)).not.toContain('desktop-secret-canary')
    expect(await page.evaluate(() => document.body.innerText)).not.toContain('203.0.113.77')
    const config = await page.evaluate(() => window.lumina.getConfig({ offset: 100, limit: 100 }))
    expect(config.offset).toBe(100); expect(config.total).toBeGreaterThan(151); expect(config.rules.length).toBeLessThanOrEqual(100)
    await page.getByRole('button', { name: /分流规则/ }).click()
    await expect(page.getByRole('heading', { level: 1, name: '每个目的地，都有自己的路。' })).toBeVisible()
    await page.getByRole('button', { name: /诊断与恢复/ }).click()
    await expect(page.getByRole('heading', { level: 1, name: '看清状态，安心恢复。' })).toBeVisible()
    await checkRecoveryCapability(page, userData)
    const environment = await page.evaluate(() => window.lumina.checkEnvironment())
    expect(environment.checks.find(x => x.id === 'runtime_bundle')?.state).toBe('passed')
    expect(environment.ready_for_start).toBe(false)
    // Only fabricate saved files; the fixture never starts a network process.
    const run = join(root, 'netlaunch-fixture'); await mkdir(run, { mode: 0o700 })
    const now = new Date().toISOString()
    const channel = { state: 'ready', reason: 'path_verified', checked_at: now, path_state: 'verified', service_state: 'not_checked' }
    await writeFile(join(run, 'status.json'), JSON.stringify({ phase: 'ready', lifecycle: 'running', updated: now, last_ready: now, personal: 'P001', channels: { company: channel, personal: { ...channel, service_state: 'healthy' }, direct: channel } }), { mode: 0o600 })
    await writeFile(join(profile, 'current.json'), JSON.stringify({ run }), { mode: 0o600 })
    await protectFixtureObjects(root, [run, join(run, 'status.json'), join(profile, 'current.json')])
    await page.getByRole('button', { name: /^总览/ }).click()
    await expect(page.getByRole('heading', { name: '最近检查已通过' })).toBeVisible()
    expect(await page.evaluate(() => window.lumina.listNodes())).toMatchObject({ selection_scope: 'not_compared', items: [{ selected: false }] })
    const switchResult = await page.evaluate(async () => { try { await window.lumina.chooseProfile(); return 'unexpected' } catch { return 'blocked' } })
    expect(switchResult).toBe('blocked')
    await page.clock.install({ time: new Date(now) }); await page.clock.fastForward(91000)
    await expect(page.getByText('已过期', { exact: true }).first()).toBeVisible()
    expect(await page.evaluate(() => document.body.scrollWidth > window.innerWidth)).toBe(false)
    await page.screenshot({ path: join(root, 'overview.png'), fullPage: true })
    expect(errors).toEqual([])
    // Explicit exit in this test concerns only the read-only UI and bridge.
  } finally { await application.close() }
})

test('packaged preview uses fixed resources and reloads a crashed renderer', async () => {
  test.skip(process.platform !== 'darwin' && process.platform !== 'win32', 'A native Mac or Windows desktop package is required')
  // An explicit installed Windows executable must exist; do not silently skip
  // a misspelled path. Without it, test the ordinary electron-builder output.
  const specified = process.platform === 'win32' ? process.env.LUMINA_TEST_WINDOWS_EXE : undefined
  if (specified && !isAbsolute(specified)) throw new Error('LUMINA_TEST_WINDOWS_EXE must be an absolute executable path')
  const executable = specified || resolve(process.platform === 'win32'
    ? '../.local/desktop-packages/win-unpacked/LuminaVPN.exe'
    : '../.local/desktop-packages/mac-arm64/LuminaVPN.app/Contents/MacOS/LuminaVPN')
  if (specified && !existsSync(executable)) throw new Error('LUMINA_TEST_WINDOWS_EXE does not exist')
  test.skip(!existsSync(executable), 'Build the native desktop preview package first')
  await mkdir(resolve('../.local'), { recursive: true })
  const userData = await mkdtemp(join(resolve('../.local'), 'packaged-e2e-中文 空格-'))
  await writeFile(join(userData, 'preferences.json'), JSON.stringify({ profile: join(userData, 'missing-profile'), closeNoticeSeen: true }))
  const env: Record<string, string> = Object.fromEntries(Object.entries(process.env).filter((entry): entry is [string, string] => entry[1] !== undefined))
  delete env.ELECTRON_RUN_AS_NODE; delete env.NODE_OPTIONS
  const began = Date.now()
  const application = await electron.launch({ executablePath: executable, args: ['--user-data-dir=' + userData], env })
  let bridgePID: number | undefined
  try {
    await application.context().route(/^https?:\/\//, route => route.abort())
    const page = await application.firstWindow()
    await expect(page.getByText('控制接口可用', { exact: true }).first()).toBeVisible()
    const startupMs = Date.now() - began
    const layout = await application.evaluate(({ app }) => ({ packaged: app.isPackaged, resources: process.resourcesPath, appPath: app.getAppPath() }))
    expect(layout.packaged).toBe(true)
    expect(layout.appPath).toMatch(/app\.asar$/)
    expect(existsSync(join(layout.resources, 'backend', process.platform === 'win32' ? 'netlaunch.exe' : 'netlaunch'))).toBe(true)
    const manifest = JSON.parse(await readFile(join(layout.resources, 'runtime', 'manifest.json'), 'utf8'))
    expect({ os: manifest.os, arch: manifest.arch }).toEqual(process.platform === 'win32' ? { os: 'windows', arch: 'amd64' } : { os: 'darwin', arch: 'arm64' })
    expect((await page.evaluate(() => window.lumina.hello())).capabilities.read_only).toBe(true)
    await page.getByRole('button', { name: /诊断与恢复/ }).click()
    await expect(page.getByRole('heading', { name: '看清状态，安心恢复。' })).toBeVisible()
    await checkRecoveryCapability(page, userData)
    expect((await page.evaluate(() => window.lumina.checkEnvironment())).checks.find(x => x.id === 'runtime_bundle')?.state).toBe('passed')
    await page.getByRole('button', { name: /^总览/ }).click()
    await application.evaluate(({ app }) => app.getAppMetrics())
    // A measured interval is needed for the app's idle CPU counters.
    await new Promise(resolve => setTimeout(resolve, 1600))
    const metrics = await application.evaluate(({ app }) => app.getAppMetrics().map(x => ({ pid: x.pid, type: x.type, working_set_kb: x.memory.workingSetSize, cpu_percent: x.cpu.percentCPUUsage })))
    const parent = application.process().pid
    const bridge = process.platform === 'darwin'
      ? execFileSync('/bin/ps', ['-axo', 'pid=,ppid=,rss=,%cpu=,comm='], { encoding: 'utf8' }).split('\n').map(line => line.trim().split(/\s+/)).filter(fields => Number(fields[1]) === parent && fields.slice(4).join(' ').endsWith('/netlaunch')).map(fields => ({ working_set_kb: Number(fields[2]), cpu_percent: Number(fields[3]) }))
      : null
    const artifact = process.platform === 'win32' ? 'desktop-preview-windows' : 'desktop-preview'
    await writeFile(resolve('../.local/' + artifact + '-metrics.json'), JSON.stringify({ platform: process.platform, startup_ms: startupMs, electron: metrics, bridge, bridge_metrics_source: process.platform === 'darwin' ? 'ps' : 'not_sampled', sampled_at: new Date().toISOString() }, null, 2))
    await page.screenshot({ path: resolve('../.local/' + artifact + '.png'), scale: 'css', fullPage: true })
    const replacement = application.waitForEvent('window')
    await application.evaluate(({ BrowserWindow }) => BrowserWindow.getAllWindows()[0].webContents.forcefullyCrashRenderer())
    const recovered = await replacement
    await expect(recovered.getByText('控制接口可用', { exact: true }).first()).toBeVisible()
    expect((await recovered.evaluate(() => window.lumina.getState())).runtime_liveness).toBe('not_checked')
    if (process.platform === 'win32') {
      bridgePID = await ownBridgePID(application, join(layout.resources, 'backend', 'netlaunch.exe'))
      await checkWindowsTrayLifecycle(application, recovered, executable, userData, env, bridgePID)
    }
  } finally {
    await application.close()
    // The recorded PID came from this app's exact desktop bridge handle. Only
    // observe its exit; never enumerate or terminate unrelated CLI processes.
    const observedPID = bridgePID
    if (observedPID !== undefined) await expect.poll(() => processExists(observedPID), { timeout: 5000, message: 'The packaged app must close its own read-only bridge on exit' }).toBe(false)
  }
})
