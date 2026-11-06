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
; Keep electron-builder's normal installer/uninstaller generation, but remove
; its elevated HKCU migration branch from the actual compiled install section.
!addincludedir "${templates}"
!macro customHeader
  ; Expand plugin-using functions only after the builder has registered its
  ; plugin directories; re-registering an already used System.dll is rejected.
  !include "${protectedInclude}"
  ; The template first loads its own multiUser.nsh from the original CWD.
  ; Moving earlier can select NSIS's unrelated, case-insensitive MultiUser.nsh.
  !cd "${overrides}"
!macroend
!macro LuminaSetLinkVars
  ; Registry metadata is never a shortcut deletion or rename path authority.
  StrCpy $oldShortcutName "LuminaVPN"
  StrCpy $oldMenuDirectory ""
  StrCpy $oldDesktopLink "$DESKTOP\\LuminaVPN.lnk"
  StrCpy $newDesktopLink "$DESKTOP\\LuminaVPN.lnk"
  StrCpy $oldStartMenuLink "$SMPROGRAMS\\LuminaVPN.lnk"
  StrCpy $newStartMenuLink "$SMPROGRAMS\\LuminaVPN.lnk"
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
  ; Complete only this release's protected pending bootstrap before the
  ; template invokes its previous uninstaller. Other installs are read-only.
  ClearErrors
  ExecWait '"$LuminaNoncePath\\lumina-service.exe" --resume-install-preflight' $R0
  \${If} \${Errors}
    StrCpy $LuminaFailure "RESUME_PREFLIGHT_START"
    Call LuminaBootstrapFatal
  \${EndIf}
  \${If} $R0 != 0
    StrCpy $LuminaFailure "RESUME_PREFLIGHT_REJECTED"
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
!macro LuminaClaimRegistry
  ; A successful previous uninstaller deleted the product keys. Reclaim only
  ; those fixed leaves before the template writes any registration values.
  Call LuminaPrepareBootstrap
  ClearErrors
  ExecWait '"$LuminaNoncePath\\lumina-service.exe" --resume-install-preflight' $R0
  \${If} \${Errors}
    StrCpy $LuminaFailure "REGISTRY_CLAIM_START"
    Call LuminaBootstrapFatal
  \${EndIf}
  \${If} $R0 != 0
    StrCpy $LuminaFailure "REGISTRY_CLAIM_REJECTED"
    Call LuminaBootstrapFatal
  \${EndIf}
  Call LuminaCloseBootstrap
  ClearErrors
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
  if (guarded.split('!insertmacro setLinkVars').length !== 2
      || guarded.split('!insertmacro handleUninstallResult SHELL_CONTEXT\n').length !== 2) throw new Error('Pinned NSIS installation sequence changed')
  return '!define LUMINA_MACHINE_ONLY_INSTALL_SECTION\n' + guarded
    .replace('!insertmacro setLinkVars', '!insertmacro LuminaSetLinkVars')
    .replace('!insertmacro handleUninstallResult SHELL_CONTEXT\n', '!insertmacro handleUninstallResult SHELL_CONTEXT\n!insertmacro LuminaClaimRegistry\n')
}

export function restrictWindowsUninstallUtilities(source) {
  source = source.replaceAll('\r\n', '\n')
  const functions = [...source.matchAll(/^Function uninstallOldVersion\n[\s\S]*?^FunctionEnd$/gm)]
  if (functions.length !== 1 || !functions[0][0].includes('!insertmacro readReg $uninstallString')
      || !functions[0][0].includes('!insertmacro copyFile "$uninstallerFileName" "$uninstallerFileNameTemp"')
      || (functions[0][0].match(/ExecWait /g) ?? []).length !== 2) throw new Error('Pinned NSIS old-uninstaller function changed')
  // The native preflight verifies this fixed protected file even when legacy
  // registration was removed. Never execute a registry command or a temp copy.
  let restricted = source.replace(functions[0][0], `Function uninstallOldVersion
  Pop $R9
  ClearErrors
  StrCpy $R0 0
  \${If} $R9 != "SHELL_CONTEXT"
  \${OrIf} $installMode != "all"
  \${OrIf} $INSTDIR != "$PROGRAMFILES64\\LuminaVPN"
    StrCpy $R0 2
    SetErrors
    Return
  \${EndIf}
  IfFileExists "$PROGRAMFILES64\\LuminaVPN\\Uninstall LuminaVPN.exe" 0 lumina_no_old_uninstaller
  ; Legacy in-place uninstallers cannot atomically rename their own image.
  ; These fixed Lumina packages disable DELETE_APP_DATA_ON_UNINSTALL.
  ExecWait '"$PROGRAMFILES64\\LuminaVPN\\Uninstall LuminaVPN.exe" /S /KEEP_APP_DATA /allusers --keep-shortcuts _?=$PROGRAMFILES64\\LuminaVPN' $R0
  lumina_no_old_uninstaller:
  \${If} \${Errors}
    StrCpy $R0 2
    SetErrors
    Return
  \${EndIf}
  \${If} $R0 != 0
    Return
  \${EndIf}
  Call LuminaCheckUpgradeRemainder
FunctionEnd

Function LuminaCheckUpgradeRemainder
  ; The native preflight has checked every old target entry's protected ACL
  ; and rejected reparse points. The old process has exited before this check.
  ; Ordinary RMDir may silently leave busy files: never claim/extract over them.
  Push $0
  Push $1
  Push $2
  Push $3
  Push $4
  StrCpy $R0 2
  System::Call '$SYSDIR\\kernel32.dll::GetFileAttributesW(w "$INSTDIR")i.r0 ?e'
  Pop $1
  \${If} $0 == -1
    \${If} $1 == 2
    \${OrIf} $1 == 3
      StrCpy $R0 0
    \${EndIf}
    Goto lumina_remainder_done
  \${EndIf}
  IntOp $0 $0 & 0x410
  \${If} $0 <> 0x10
    Goto lumina_remainder_done
  \${EndIf}
  System::Alloc 592 ; Bounded WIN32_FIND_DATAW, Unicode compiler required.
  Pop $1
  \${If} $1 == 0
    Goto lumina_remainder_done
  \${EndIf}
  System::Call '$SYSDIR\\kernel32.dll::FindFirstFileW(w "$INSTDIR\\*", p r1)p.r0 ?e'
  Pop $2
  \${If} $0 == -1
    \${If} $2 == 2
      StrCpy $R0 0
    \${EndIf}
    Goto lumina_remainder_free
  \${EndIf}
  lumina_remainder_entry:
    IntOp $3 $1 + 44
    System::Call '*$3(&w260.r4)'
    StrCmp $4 "." lumina_remainder_next
    StrCmp $4 ".." lumina_remainder_next
    System::Call '*$1(i.r2)'
    IntOp $2 $2 & 0x410
    \${If} $2 != 0
      Goto lumina_remainder_close
    \${EndIf}
    StrCmp $4 "Uninstall LuminaVPN.exe" lumina_remainder_next lumina_remainder_close
  lumina_remainder_next:
    System::Call '$SYSDIR\\kernel32.dll::FindNextFileW(p r0, p r1)i.r2 ?e'
    Pop $3
    \${If} $2 != 0
      Goto lumina_remainder_entry
    \${EndIf}
    \${If} $3 == 18
      StrCpy $R0 0
    \${EndIf}
  lumina_remainder_close:
  System::Call '$SYSDIR\\kernel32.dll::FindClose(p r0)'
  lumina_remainder_free:
  System::Free $1
  lumina_remainder_done:
  Pop $4
  Pop $3
  Pop $2
  Pop $1
  Pop $0
  \${If} $R0 != 0
    DetailPrint "Previous installation has busy or unverified remaining entries; upgrade stopped."
    SetErrors
  \${Else}
    ClearErrors
  \${EndIf}
FunctionEnd`)
  // These parsers belonged only to the removed mutable registry command path.
  // Drop their definitions instead of suppressing native NSIS unused warnings.
  for (const name of ['GetInQuotes', 'GetFileParent']) {
    const definition = new RegExp(`^Function ${name}\\n[\\s\\S]*?^FunctionEnd\\n`, 'gm')
    if ([...restricted.matchAll(definition)].length !== 1) throw new Error('Pinned NSIS legacy parser changed')
    restricted = restricted.replace(definition, '')
  }
  const macro = /^!macro GetInQuotes Var Str\n[\s\S]*?^!macroend\n/gm
  if ([...restricted.matchAll(macro)].length !== 1) throw new Error('Pinned NSIS legacy parser macro changed')
  return restricted.replace(macro, '')
}

export function restrictWindowsUninstaller(source) {
  source = source.replaceAll('\r\n', '\n')
  const menuRead = 'ReadRegStr $R1 SHELL_CONTEXT "\${INSTALL_REGISTRY_KEY}" MenuDirectory'
  const selfComparison = 'StrCmp "$R0\\$R2" "${UNINSTALL_FILENAME}" 0 +2'
  if (source.split('!insertmacro setLinkVars').length !== 2 || source.split(menuRead).length !== 2
      || source.split(selfComparison).length !== 2) throw new Error('Pinned NSIS uninstaller shortcuts or self-image check changed')
  return source.replace('!insertmacro setLinkVars', '!insertmacro LuminaSetLinkVars')
    .replace(selfComparison, 'StrCmp "$INSTDIR$R0\\$R2" "$EXEPATH" 0 +2')
    .replace(menuRead, 'StrCpy $R1 "" ; Fixed flat product shortcut has no menu directory.')
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
  await put(nsisOverrideRoot, 'installUtil.nsh', Buffer.from(restrictWindowsUninstallUtilities(await readFile(join(nsisTemplateRoot, 'include', 'installUtil.nsh'), 'utf8'))))
  await put(nsisOverrideRoot, 'uninstaller.nsh', Buffer.from(restrictWindowsUninstaller(await readFile(join(nsisTemplateRoot, 'uninstaller.nsh'), 'utf8'))))
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

function validateInstallPlanShape(plan) {
  const fields = ['version', 'schema', 'service_name', 'image_kind', 'image_relative', 'account', 'auto_connect',
    'requires_review', 'installed', 'service_arguments', 'supported_entries', 'bootstrap_available',
    'recovery_service_name', 'recovery_arguments', 'target_preflight', 'target_root', 'data_root']
  const entries = ['--bootstrap', '--service', '--recover', '--recover-service', '--uninstall', '--print-install-plan', '--resume-install-preflight']
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
      || !['absent', 'protected', 'unsafe'].includes(plan.target_preflight)
      || !nativeRoot(plan.target_root, '\\LuminaVPN') || !nativeRoot(plan.data_root, '\\LuminaVPN\\ServiceState')) {
    throw new Error('Service bootstrap/recovery contract is not ready for packaging')
  }
}

export function validateInstallPlan(plan) {
  validateInstallPlanShape(plan)
  if (!['absent', 'protected'].includes(plan.target_preflight)) {
    throw new Error('Service bootstrap/recovery contract is not ready for packaging')
  }
}

// Packaging checks the executable contract, not permission to install on the
// build host. Runtime Go/NSIS preflight still requires an independently observed
// safe target and a zero exit before resume or any previous uninstaller runs.
export function validateBuildInstallPlanResult(result) {
  if (!result || result.error != null || result.signal != null || ![0, 1].includes(result.status)
      || typeof result.stdout !== 'string') throw new Error('Cannot inspect the service installation contract')
  const plan = JSON.parse(result.stdout)
  validateInstallPlanShape(plan)
  const preflightPassed = plan.target_preflight !== 'unsafe'
  if (result.status !== (preflightPassed ? 0 : 1)) throw new Error('Service installation plan and exit status disagree')
  return { native_preflight_passed: preflightPassed, exit_status: result.status, plan }
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
  // Older partially implemented bootstrap interfaces deliberately fail here;
  // a complete contract may report that this build host cannot install it.
  const result = spawnSync(join(staged.releaseRoot, 'lumina-service.exe'), ['--print-install-plan'], {
    shell: false, encoding: 'utf8', windowsHide: true, timeout: 10_000, maxBuffer: 64 << 10,
  })
  return validateBuildInstallPlanResult(result)
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
  const hostReadiness = verifyBuildInterface(staged, options.mode, options.goPath)
  // Local evidence only: outside release, payload and every packaged resource.
  await put(output, 'build-host-readiness.json', Buffer.from(JSON.stringify({
    schema: 'lumina-build-host-readiness-v1', observed_at: new Date().toISOString(),
    build_mode: options.mode, release_id: staged.releaseID,
    service_sha256: staged.catalog.files.service.sha256, ...hostReadiness,
  }, null, 2) + '\n'))
  if (!hostReadiness.native_preflight_passed) {
    process.stderr.write('WARNING build-host-not-installable: native preflight is unsafe (exit 1); packaging does not authorize installation.\n')
  }
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
  main().catch(error => {
    process.stderr.write((error instanceof Error ? error.message : 'Windows client packaging failed') + '\n')
    process.exitCode = 1
    // Match electron-builder's CLI: its asynchronous cleanup hook can call
    // process.exit(0), so preserve the failure after cleanup reaches exit.
    process.on('exit', () => { process.exitCode = 1 })
  })
}
