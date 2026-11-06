import { spawnSync } from 'node:child_process'
import { createHash, randomUUID } from 'node:crypto'
import { lstat, mkdir, readFile, readdir, realpath, writeFile } from 'node:fs/promises'
import { createRequire } from 'node:module'
import { dirname, join, resolve, win32 } from 'node:path'
import { fileURLToPath } from 'node:url'
import { generateIcons } from './generate-icons.mjs'
import { stageWindowsRelease } from './windows-release-stage.mjs'

const desktopRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const repoRoot = resolve(desktopRoot, '..')
const hash = bytes => createHash('sha256').update(bytes).digest('hex')
const isRelease = value => typeof value === 'string' && /^[a-f0-9]{64}$/.test(value)
const canonical = value => process.platform === 'win32' ? resolve(value).toLowerCase() : resolve(value)
const images = { service: 'lumina-service.exe', user_worker: 'lumina-user-worker.exe', lifecycle: 'netlaunch.exe',
  core: 'runtime/bin/mihomo.exe', vpn: 'runtime/bin/openconnect.exe' }

async function regular(path, directory = false) {
  for (let current = resolve(path); ; current = dirname(current)) {
    const info = await lstat(current)
    if (info.isSymbolicLink() || canonical(await realpath(current)) !== canonical(current)) throw new Error('Redirected package path')
    if (current === resolve(path) && !(directory ? info.isDirectory() : info.isFile())) throw new Error('Invalid package file type')
    if (dirname(current) === current) break
  }
}

async function files(root) {
  const result = new Map()
  async function visit(directory, prefix = '') {
    await regular(directory, true)
    const names = await readdir(directory)
    if (!names.length) throw new Error('Empty package payload directory')
    for (const name of names) {
      const path = join(directory, name), info = await lstat(path)
      if (info.isDirectory() && !info.isSymbolicLink()) await visit(path, prefix + name + '/')
      else {
        await regular(path)
        if (info.size > 256 << 20 || result.size >= 1000) throw new Error('Package payload exceeds bounds')
        result.set(prefix + name, await readFile(path))
      }
    }
  }
  await visit(root)
  return result
}

async function put(root, path, bytes) {
  const destination = join(root, path)
  await mkdir(dirname(destination), { recursive: true })
  await regular(dirname(destination), true)
  await writeFile(destination, bytes, { flag: 'wx' })
  await regular(destination)
  if (hash(await readFile(destination)) !== hash(bytes)) throw new Error('Package copy readback failed')
}

export function recoveryEntry(releaseID) {
  if (!isRelease(releaseID)) throw new Error('Invalid recovery release identity')
  // This entry is merely revealed by the UI. Its fixed service image enforces
  // the native install root and performs only the restricted recovery action.
  return Buffer.from([
    '@echo off', 'setlocal DisableDelayedExpansion',
    `"%~dp0..\\..\\releases\\${releaseID}\\lumina-service.exe" --recover`,
    'set "lumina_exit=%errorlevel%"',
    'if not "%lumina_exit%"=="0" echo Recovery is not confirmed. Keep the installed files and retry the recovery entry.',
    'pause', 'exit /b %lumina_exit%', '',
  ].join('\r\n'))
}

function nsisLiteral(value) {
  if (typeof value !== 'string' || !value || /[\r\n\0"*?]/.test(value)) throw new Error('Invalid fixed NSIS source path')
  return value.replaceAll('$', () => '$$')
}

export function installerInclude(releaseID, { bootstrapSource, bootstrapSHA256, nsisTemplateRoot, nsisOverrideRoot } = {}) {
  if (!isRelease(releaseID)) throw new Error('Invalid installer release identity')
  if (typeof bootstrapSHA256 !== 'string' || !/^[a-f0-9]{64}$/.test(bootstrapSHA256)) throw new Error('Missing embedded bootstrap pin')
  const source = nsisLiteral(bootstrapSource)
  const protectedInclude = nsisLiteral(fileURLToPath(new URL('./windows-client-bootstrap.nsh', import.meta.url)))
  const templates = nsisLiteral(nsisTemplateRoot), overrides = nsisLiteral(nsisOverrideRoot)
  return `; Generated from the verified release; no renderer input or arbitrary command.
!include "x64.nsh"
!define LUMINA_BOOTSTRAP_SOURCE "${source}"
!define LUMINA_BOOTSTRAP_SHA256 "${bootstrapSHA256}"
!include "${protectedInclude}"
; Keep electron-builder's normal installer/uninstaller generation, but remove
; its elevated HKCU migration branch from the actual compiled install section.
!addincludedir "${templates}"
!macro customHeader
  ; The template first loads its own multiUser.nsh from the original CWD.
  ; Moving earlier can select NSIS's unrelated, case-insensitive MultiUser.nsh.
  !ifndef BUILD_UNINSTALLER
    !cd "${overrides}"
  !endif
!macroend
!macro customInit
  \${IfNot} \${RunningX64}
    SetErrorLevel 2
    Quit
  \${EndIf}
  StrCpy $INSTDIR "$PROGRAMFILES64\\LuminaVPN"
  SetShellVarContext all
  ; The machine installer must never elevate a mutable legacy per-user uninstaller.
  ReadRegStr $R0 HKCU "\${UNINSTALL_REGISTRY_KEY}" "UninstallString"
  \${If} $R0 != ""
    DetailPrint "Remove the legacy per-user preview using its original user account before installing the service client."
    SetErrorLevel 2
    Quit
  \${EndIf}
  Call LuminaPrepareBootstrap
  ClearErrors
  ExecWait '"$LuminaNoncePath\\lumina-service.exe" --print-install-plan' $R0
  \${If} \${Errors}
    StrCpy $LuminaFailure "PREFLIGHT_START"
    Call LuminaBootstrapFatal
  \${EndIf}
  \${If} $R0 != 0
    StrCpy $LuminaFailure "PREFLIGHT_REJECTED"
    Call LuminaBootstrapFatal
  \${EndIf}
  Call LuminaCloseBootstrap
  ClearErrors
!macroend
!macro customUnInit
  \${IfNot} \${RunningX64}
    SetErrorLevel 2
    Quit
  \${EndIf}
  \${If} $INSTDIR != "$PROGRAMFILES64\\LuminaVPN"
    DetailPrint "Unexpected installation directory; files were retained."
    SetErrorLevel 2
    Quit
  \${EndIf}
  SetShellVarContext all
!macroend
!macro LuminaRequireUninstallSuccess
  \${If} \${Errors}
    DetailPrint "The previous uninstaller could not be started; upgrade stopped."
    SetErrorLevel 2
    Quit
  \${EndIf}
  \${If} $R0 != 0
    DetailPrint "The previous uninstaller did not confirm recovery; upgrade stopped."
    SetErrorLevel 2
    Quit
  \${EndIf}
!macroend
!macro customUnInstallCheck
  !insertmacro LuminaRequireUninstallSuccess
!macroend
!macro customUnInstallCheckCurrentUser
  !insertmacro LuminaRequireUninstallSuccess
!macroend
!macro customInstall
  !ifndef LUMINA_MACHINE_ONLY_INSTALL_SECTION
    !error "The restricted machine-only install section was not selected"
  !endif
  Call LuminaPrepareBootstrap
  ClearErrors
  ExecWait '"$LuminaNoncePath\\lumina-service.exe" --bootstrap' $R0
  \${If} \${Errors}
    StrCpy $LuminaFailure "BOOTSTRAP_START"
    Call LuminaBootstrapFatal
  \${EndIf}
  \${If} $R0 != 0
    StrCpy $LuminaFailure "BOOTSTRAP_REJECTED"
    Call LuminaBootstrapFatal
  \${EndIf}
  Call LuminaCloseBootstrap
  ClearErrors
!macroend
!macro customUnInstall
  Call un.LuminaPrepareBootstrap
  ClearErrors
  ExecWait '"$LuminaNoncePath\\lumina-service.exe" --uninstall' $R0
  \${If} \${Errors}
    StrCpy $LuminaFailure "UNINSTALL_START"
    Call un.LuminaBootstrapFatal
  \${EndIf}
  \${If} $R0 != 0
    StrCpy $LuminaFailure "UNINSTALL_REJECTED"
    Call un.LuminaBootstrapFatal
  \${EndIf}
  Call un.LuminaCloseBootstrap
  ClearErrors
!macroend
`
}

export function removeUserUninstallerMigration(source) {
  source = source.replaceAll('\r\n', '\n')
  const branch = '\${if} $installMode == "all"\n  !insertmacro uninstallOldVersion HKEY_CURRENT_USER\n  !insertmacro handleUninstallResult HKEY_CURRENT_USER\n\${endIf}\n'
  if (source.split(branch).length !== 2) throw new Error('Pinned NSIS user-migration branch changed')
  const guarded = source.replace(branch, '; Per-user uninstallers are never executed by the machine installer.\n')
  if (guarded.includes('HKEY_CURRENT_USER') || !guarded.includes('!insertmacro uninstallOldVersion SHELL_CONTEXT')) {
    throw new Error('NSIS installer migration cannot be restricted')
  }
  return '!define LUMINA_MACHINE_ONLY_INSTALL_SECTION\n' + guarded
}

/** Turn one immutable staged release into the GUI and machine payloads. */
export async function prepareWindowsClientPackage({ releaseStage, outputRoot }) {
  outputRoot = resolve(outputRoot)
  await regular(dirname(outputRoot), true)
  await mkdir(outputRoot)
  const staged = await files(resolve(releaseStage))
  const catalogBytes = staged.get('release-catalog.json')
  if (!catalogBytes || catalogBytes.length > 1 << 20) throw new Error('Missing release catalog')
  const catalog = JSON.parse(catalogBytes.toString('utf8'))
  const releaseID = catalog.release_id
  if (!isRelease(releaseID)) throw new Error('Invalid staged release identity')
  const prefix = `releases/${releaseID}/`
  if ([...staged.keys()].some(path => path !== 'release-catalog.json' && !path.startsWith(prefix))) throw new Error('Unexpected staged payload')
  if (Object.keys(catalog).sort().join(',') !== 'files,release_id,runtime_manifest_sha256'
      || !catalog.files || Object.keys(catalog.files).sort().join(',') !== Object.keys(images).sort().join(',')) throw new Error('Invalid staged catalog')
  for (const [kind, path] of Object.entries(images)) {
    const bytes = staged.get(prefix + path), pin = catalog.files[kind]
    if (!bytes || !pin || Object.keys(pin).join(',') !== 'sha256' || pin.sha256 !== hash(bytes)) throw new Error('Staged image pin differs')
  }
  const manifest = staged.get(prefix + 'runtime/manifest.json')
  if (!manifest || catalog.runtime_manifest_sha256 !== hash(manifest)) throw new Error('Staged manifest pin differs')
  const identity = { version: 1, files: [...staged].filter(([path]) => path !== 'release-catalog.json')
    .map(([path, bytes]) => ({ path: path.slice(prefix.length), sha256: hash(bytes) }))
    .sort((a, b) => a.path < b.path ? -1 : a.path > b.path ? 1 : 0) }
  if (hash(Buffer.from(JSON.stringify(identity) + '\n')) !== releaseID) throw new Error('Staged release content identity differs')
  const gui = new Map()
  for (const [path, bytes] of staged) {
    await put(join(outputRoot, 'machine'), path, bytes)
    if (path.startsWith(prefix + 'runtime/') || path.startsWith(prefix + 'legal/')) gui.set(path.slice(prefix.length), bytes)
    if (path === prefix + 'netlaunch.exe') gui.set('backend/netlaunch.exe', bytes)
  }
  if (!gui.has('backend/netlaunch.exe') || !gui.has('runtime/manifest.json')) throw new Error('Incomplete staged GUI resources')
  gui.set('recovery/Stop-and-Recover.cmd', recoveryEntry(releaseID))
  for (const [path, bytes] of gui) await put(join(outputRoot, 'gui'), path, bytes)
  const require = createRequire(join(desktopRoot, 'package.json'))
  const builderPackage = require.resolve('app-builder-lib/package.json')
  if (JSON.parse(await readFile(builderPackage, 'utf8')).version !== '26.18.0') throw new Error('Unreviewed NSIS template version')
  const nsisTemplateRoot = join(dirname(builderPackage), 'templates', 'nsis')
  const nsisOverrideRoot = join(outputRoot, 'nsis-overrides')
  const section = removeUserUninstallerMigration(await readFile(join(nsisTemplateRoot, 'installSection.nsh'), 'utf8'))
  await put(nsisOverrideRoot, 'installSection.nsh', Buffer.from(section))
  await put(outputRoot, 'installer.nsh', Buffer.from(installerInclude(releaseID, {
    bootstrapSource: join(outputRoot, 'machine', 'releases', releaseID, 'lumina-service.exe'), bootstrapSHA256: catalog.files.service.sha256,
    nsisTemplateRoot, nsisOverrideRoot,
  })))
  const expectedHashes = Object.fromEntries([...staged, ...[...gui].map(([path, bytes]) => ['resources/' + path, bytes])]
    .map(([path, bytes]) => [path, hash(bytes)]))
  return { outputRoot, releaseID, machineRoot: join(outputRoot, 'machine'), guiRoot: join(outputRoot, 'gui'),
    includePath: join(outputRoot, 'installer.nsh'), expectedHashes,
    verifyPackagedPayload: packageRoot => verifyPackagedWindowsClient(packageRoot, expectedHashes) }
}

export async function verifyPackagedWindowsClient(packageRoot, expectedHashes) {
  const paths = Object.keys(expectedHashes)
  if (!paths.length || paths.length > 1000 || paths.some(path => path.includes('\\') || path.startsWith('/')
      || path.split('/').some(part => part === '..' || part === '.' || !part)
      || !/^[a-f0-9]{64}$/.test(expectedHashes[path]))) throw new Error('Invalid frozen package hashes')
  await regular(packageRoot, true)
  const actualRelease = await files(join(packageRoot, 'releases'))
  const expectedRelease = paths.filter(path => path.startsWith('releases/')).map(path => path.slice('releases/'.length))
  if (actualRelease.size !== expectedRelease.length || expectedRelease.some(path => !actualRelease.has(path))) throw new Error('Packaged release tree changed')
  for (const name of ['backend', 'runtime', 'legal', 'recovery']) {
    const found = await files(join(packageRoot, 'resources', name))
    const prefix = 'resources/' + name + '/'
    const wanted = paths.filter(path => path.startsWith(prefix)).map(path => path.slice(prefix.length))
    if (found.size !== wanted.length || wanted.some(path => !found.has(path))) throw new Error('Packaged GUI resources changed')
  }
  for (const [path, checksum] of Object.entries(expectedHashes)) {
    const installed = join(packageRoot, path)
    await regular(installed)
    if (hash(await readFile(installed)) !== checksum) throw new Error('Packaged payload bytes changed after staging')
  }
}

export function windowsClientConfiguration(prepared, { outputRoot, iconPath }) {
  return {
    appId: 'app.luminavpn.desktop', productName: 'LuminaVPN', asar: true, extends: null,
    // Pin the reviewed NSIS 3.12 bundle; an omitted toolset selects legacy 3.0.4.1.
    toolsets: { nsis: '1.2.1' },
    directories: { app: desktopRoot, output: outputRoot, buildResources: dirname(iconPath) },
    files: ['out/**/*', 'package.json', '!**/*.map'],
    extraResources: [{ from: prepared.guiRoot, to: '.' }],
    extraFiles: [{ from: prepared.machineRoot, to: '.' }],
    win: { icon: iconPath, target: [{ target: 'nsis', arch: ['x64'] }], requestedExecutionLevel: 'asInvoker',
      // Do not mutate any pinned Go image after release hashes are frozen.
      signAndEditExecutable: false, signExecutable: false },
    nsis: { oneClick: false, perMachine: true, selectPerMachineByDefault: true, allowElevation: true,
      allowToChangeInstallationDirectory: false, runAfterFinish: false, deleteAppDataOnUninstall: false,
      include: prepared.includePath, artifactName: `LuminaVPN-\${version}-${prepared.releaseID.slice(0, 12)}-\${arch}.\${ext}` },
    afterPack: context => prepared.verifyPackagedPayload(context.appOutDir),
    afterSign: context => prepared.verifyPackagedPayload(context.appOutDir),
  }
}

export async function writeWindowsClientConfiguration(prepared, options) {
  const { outputRoot, releaseID, machineRoot, guiRoot, includePath, expectedHashes } = prepared
  if (!isRelease(releaseID)) throw new Error('Invalid package release identity')
  // Passing an object to electron-builder still merges the legacy project
  // YAML and concatenates resource arrays. An explicit module path avoids
  // loading it, while retaining executable verification hooks.
  const source = `import { windowsClientConfiguration, verifyPackagedWindowsClient } from ${JSON.stringify(import.meta.url)};\n`
    + `const prepared = ${JSON.stringify({ outputRoot, releaseID, machineRoot, guiRoot, includePath, expectedHashes })};\n`
    + 'prepared.verifyPackagedPayload = path => verifyPackagedWindowsClient(path, prepared.expectedHashes);\n'
    + `export default windowsClientConfiguration(prepared, ${JSON.stringify(options)});\n`
  const name = 'electron-builder.windows-client.mjs'
  await put(prepared.outputRoot, name, Buffer.from(source))
  return join(prepared.outputRoot, name)
}

function runNode(script, args, cwd) {
  const result = spawnSync(process.execPath, [script, ...args], { cwd, shell: false, stdio: 'inherit' })
  if (result.error || result.signal || result.status !== 0) throw new Error('Windows client build step failed')
}

export function validateInstallPlan(plan) {
  const fields = ['version', 'schema', 'service_name', 'image_kind', 'image_relative', 'account', 'auto_connect',
    'requires_review', 'installed', 'service_arguments', 'supported_entries', 'bootstrap_available',
    'recovery_service_name', 'recovery_arguments', 'target_preflight', 'target_root', 'data_root']
  const entries = ['--bootstrap', '--service', '--recover', '--recover-service', '--uninstall', '--print-install-plan']
  // Paths are observations from the Go entry's own KnownFolder calls, never
  // installation arguments. The trusted native entry retains path authority.
  const nativeRoot = (value, suffix) => typeof value === 'string' && value.length <= 260
    && /^[A-Za-z]:\\/.test(value) && !/[\0\r\n"/]/.test(value)
    && win32.normalize(value) === value && value.endsWith(suffix)
  if (!plan || typeof plan !== 'object' || Array.isArray(plan) || Object.keys(plan).length !== fields.length
      || fields.some(field => !Object.hasOwn(plan, field))
      || plan.version !== 1 || plan.schema !== 'lumina-service-install-v1'
      || plan.service_name !== 'LuminaVPNService' || plan.image_kind !== 'service'
      || plan.image_relative !== 'releases/<reviewed-release>/lumina-service.exe'
      || plan.account !== 'LocalSystem with an explicit service SID'
      || plan.auto_connect !== false || plan.requires_review !== true || typeof plan.installed !== 'boolean'
      || plan.bootstrap_available !== true || plan.recovery_service_name !== 'LuminaVPNRecoveryService'
      || !Array.isArray(plan.service_arguments) || plan.service_arguments.length !== 1 || plan.service_arguments[0] !== '--service'
      || !Array.isArray(plan.recovery_arguments) || plan.recovery_arguments.length !== 1 || plan.recovery_arguments[0] !== '--recover-service'
      || !Array.isArray(plan.supported_entries) || plan.supported_entries.length !== entries.length
      || new Set(plan.supported_entries).size !== entries.length || entries.some(entry => !plan.supported_entries.includes(entry))
      || !['absent', 'protected'].includes(plan.target_preflight)
      || !nativeRoot(plan.target_root, '\\LuminaVPN') || !nativeRoot(plan.data_root, '\\LuminaVPN\\ServiceState')) {
    throw new Error('Service bootstrap/recovery contract is not ready for packaging')
  }
}

export function validateBuildTags(text, mode) {
  if (!['daily', 'validation'].includes(mode)) throw new Error('Unknown Windows client package mode')
  const matches = [...text.matchAll(/^\s*build\s+-tags=(.+)$/gm)]
  const expected = mode === 'validation' ? ['windows_client', 'windows_client_validation'] : ['windows_client']
  const tags = matches.length === 1 ? matches[0][1].trim().split(',') : []
  if (tags.length !== expected.length || new Set(tags).size !== tags.length || expected.some(tag => !tags.includes(tag))) {
    throw new Error('Go executable build tags differ from the selected package mode')
  }
}

function verifyBuildInterface(staged, mode, goPath) {
  for (const name of ['lumina-service.exe', 'lumina-user-worker.exe', 'netlaunch.exe']) {
    const metadata = spawnSync(goPath || 'go', ['version', '-m', join(staged.releaseRoot, name)], {
      shell: false, encoding: 'utf8', timeout: 10_000, maxBuffer: 64 << 10,
      env: { ...process.env, GOTOOLCHAIN: 'local', GOENV: 'off', GOWORK: 'off', GOPROXY: 'off' },
    })
    if (metadata.error || metadata.signal || metadata.status !== 0) throw new Error('Cannot verify Go executable build metadata')
    validateBuildTags(metadata.stdout, mode)
  }
  // The only payload invocation during packaging is this read-only fixed verb.
  // Older partially implemented bootstrap interfaces deliberately fail here.
  const result = spawnSync(join(staged.releaseRoot, 'lumina-service.exe'), ['--print-install-plan'], {
    shell: false, encoding: 'utf8', windowsHide: true, timeout: 10_000, maxBuffer: 64 << 10,
  })
  if (result.error || result.signal || result.status !== 0) throw new Error('Cannot inspect the service installation contract')
  validateInstallPlan(JSON.parse(result.stdout))
}

async function main() {
  if (process.platform !== 'win32' || process.arch !== 'x64') throw new Error('Windows client packaging requires native Windows x64')
  const options = { runtimeRoot: process.env.LUMINA_BUILD_RUNTIME, goPath: process.env.NETLAUNCH_GO }
  const flags = new Map([['--runtime-root', 'runtimeRoot'], ['--go', 'goPath'], ['--mode', 'mode']])
  const seen = new Set()
  for (let i = 2; i < process.argv.length; i += 2) {
    const key = flags.get(process.argv[i]), value = process.argv[i + 1]
    if (!key || seen.has(key) || !value || value.startsWith('--')) throw new Error('Use --mode daily|validation [--runtime-root DIR] [--go GO]')
    options[key] = value; seen.add(key)
  }
  if (!['daily', 'validation'].includes(options.mode)) throw new Error('An explicit daily or validation mode is required')
  if (!options.runtimeRoot) options.runtimeRoot = join(repoRoot, 'runtime')
  const require = createRequire(join(desktopRoot, 'package.json'))
  const base = join(repoRoot, '.local', 'windows-client-packages')
  await mkdir(base, { recursive: true })
  await regular(base, true)
  const output = join(base, randomUUID())
  await mkdir(output)
  const staged = await stageWindowsRelease({ repoRoot, ...options, outputRoot: join(output, 'release') })
  verifyBuildInterface(staged, options.mode, options.goPath)
  const prepared = await prepareWindowsClientPackage({ releaseStage: staged.outputRoot, outputRoot: join(output, 'payload') })
  const icons = join(output, 'icons')
  await generateIcons(icons, 'windows')
  const tscPackage = require.resolve('typescript/package.json')
  const vitePackage = require.resolve('electron-vite/package.json')
  runNode(join(dirname(tscPackage), JSON.parse(await readFile(tscPackage, 'utf8')).bin.tsc), ['--noEmit'], desktopRoot)
  runNode(join(dirname(vitePackage), JSON.parse(await readFile(vitePackage, 'utf8')).bin['electron-vite']), ['build'], desktopRoot)
  const configPath = await writeWindowsClientConfiguration(prepared, { outputRoot: join(output, 'artifacts'), iconPath: join(icons, 'icon.ico') })
  const { build, Platform, Arch } = await import('electron-builder')
  await build({ projectDir: desktopRoot, targets: Platform.WINDOWS.createTarget(['nsis'], Arch.x64),
    publish: 'never', config: configPath })
  process.stdout.write(`Windows client package built from release ${staged.releaseID}\n${output}\n`)
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main().catch(error => { process.stderr.write((error instanceof Error ? error.message : 'Windows client packaging failed') + '\n'); process.exitCode = 1 })
}
