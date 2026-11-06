import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { cp, mkdir, mkdtemp, readFile, readdir, realpath, rm, symlink, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { createRequire } from 'node:module'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import test from 'node:test'
import { installerInclude, prepareWindowsClientPackage, recoveryEntry, removeUserUninstallerMigration, validateBuildTags,
  restrictWindowsUninstallUtilities, restrictWindowsUninstaller, validateBuildInstallPlanResult, validateInstallPlan, windowsClientConfiguration, writeWindowsClientConfiguration } from '../scripts/windows-client-package.mjs'

const hash = bytes => createHash('sha256').update(bytes).digest('hex')
async function put(root, path, bytes) {
  await mkdir(dirname(join(root, path)), { recursive: true })
  await writeFile(join(root, path), bytes)
}
async function fixture(t) {
  const root = await mkdtemp(join(await realpath(tmpdir()), 'lumina-client-package-'))
  t.after(() => rm(root, { recursive: true, force: true }))
  const payload = new Map([
    ['lumina-service.exe', Buffer.from('fixed service image fixture')],
    ['lumina-user-worker.exe', Buffer.from('fixed worker image fixture')],
    ['netlaunch.exe', Buffer.from('fixed lifecycle image fixture')],
    ['runtime/manifest.json', Buffer.from('{"version":1}')],
    ['runtime/bin/mihomo.exe', Buffer.from('runtime core fixture')],
    ['runtime/bin/openconnect.exe', Buffer.from('runtime vpn fixture')],
    ['runtime/notices/windows-components.txt', Buffer.from('license fixture')],
    ['legal/THIRD_PARTY.md', Buffer.from('third party fixture')],
    ['legal/golang-x-sys.txt', Buffer.from('Go x/sys license fixture')],
  ])
  const identity = { version: 1, files: [...payload].map(([path, bytes]) => ({ path, sha256: hash(bytes) }))
    .sort((a, b) => a.path < b.path ? -1 : a.path > b.path ? 1 : 0) }
  const releaseID = hash(Buffer.from(JSON.stringify(identity) + '\n'))
  const releaseStage = join(root, 'stage')
  const images = { service: 'lumina-service.exe', user_worker: 'lumina-user-worker.exe', lifecycle: 'netlaunch.exe',
    core: 'runtime/bin/mihomo.exe', vpn: 'runtime/bin/openconnect.exe' }
  const catalog = { release_id: releaseID, files: Object.fromEntries(Object.entries(images).map(([kind, path]) => [kind, { sha256: hash(payload.get(path)) }])),
    runtime_manifest_sha256: hash(payload.get('runtime/manifest.json')) }
  for (const [path, bytes] of payload) await put(releaseStage, `releases/${releaseID}/${path}`, bytes)
  await put(releaseStage, 'release-catalog.json', JSON.stringify(catalog))
  return { root, releaseStage, releaseID, catalog, payload, outputRoot: join(root, 'prepared') }
}

test('packages the exact staged lifecycle image and checks every copied byte afterward', async t => {
  const f = await fixture(t)
  const prepared = await prepareWindowsClientPackage(f)
  assert.equal(prepared.releaseID, f.releaseID)
  assert.deepEqual(await readFile(join(prepared.guiRoot, 'backend/netlaunch.exe')), f.payload.get('netlaunch.exe'))
  assert.deepEqual(await readFile(join(prepared.guiRoot, 'recovery/Stop-and-Recover.cmd')), recoveryEntry(f.releaseID))
  const packaged = join(f.root, 'win-unpacked')
  await cp(prepared.machineRoot, packaged, { recursive: true })
  await cp(prepared.guiRoot, join(packaged, 'resources'), { recursive: true })
  await prepared.verifyPackagedPayload(packaged)
  await writeFile(join(packaged, `releases/${f.releaseID}/lumina-service.exe`), 'resigned or edited image')
  await assert.rejects(prepared.verifyPackagedPayload(packaged), /bytes changed/)
})

test('does not accept modified catalog pins, extra release files, or reused output', async t => {
  for (const change of ['pin', 'extra', 'reused']) {
    const f = await fixture(t)
    if (change === 'pin') {
      f.catalog.files.service.sha256 = '0'.repeat(64)
      await writeFile(join(f.releaseStage, 'release-catalog.json'), JSON.stringify(f.catalog))
    } else if (change === 'extra') await put(f.releaseStage, 'local.private.json', 'private fixture')
    else await mkdir(f.outputRoot)
    await assert.rejects(prepareWindowsClientPackage(f))
  }
})

test('package readback rejects additional runtime payload and symlink substitution', async t => {
  const f = await fixture(t), prepared = await prepareWindowsClientPackage(f)
  const packaged = join(f.root, 'win-unpacked')
  await cp(prepared.machineRoot, packaged, { recursive: true })
  await cp(prepared.guiRoot, join(packaged, 'resources'), { recursive: true })
  const extra = join(packaged, 'resources/runtime/extra.exe')
  await writeFile(extra, 'unexpected fixture')
  await assert.rejects(prepared.verifyPackagedPayload(packaged), /resources changed/)
  await rm(extra)
  const image = join(packaged, 'resources/backend/netlaunch.exe'), outside = join(f.root, 'outside.exe')
  await writeFile(outside, f.payload.get('netlaunch.exe')); await rm(image)
  try { await symlink(outside, image) } catch (error) {
    if (process.platform === 'win32' && error.code === 'EPERM') { t.skip('Windows symlink privilege unavailable'); return }
    throw error
  }
  await assert.rejects(prepared.verifyPackagedPayload(packaged), /Redirected/)
})

test('generated installer retains files unless the fixed recovery verb succeeds', async () => {
  const release = 'a'.repeat(64), include = installerInclude(release, { bootstrapSource: 'D:\\source$test\\lumina-service.exe', bootstrapSHA256: 'b'.repeat(64),
    nsisTemplateRoot: 'D:\\tools\\nsis-template', nsisOverrideRoot: 'D:\\prepared\\nsis-overrides' })
  assert.match(include, /StrCpy \$INSTDIR "\$PROGRAMFILES64\\LuminaVPN"/)
  for (const hook of ['customUnInit', 'customUnInstall', 'customUnInstallCheck', 'customUnInstallCheckCurrentUser']) assert.ok(include.includes('!macro ' + hook))
  assert.ok(include.includes('!define LUMINA_BOOTSTRAP_SOURCE "D:\\source$$test\\lumina-service.exe"'))
  assert.deepEqual([...include.matchAll(/ExecWait '"([^"\r\n]+)" ([^'\r\n]+)'/g)].map(match => [match[1], match[2]]), [
    ['$LuminaNoncePath\\lumina-service.exe', '--print-install-plan'],
    ['$LuminaNoncePath\\lumina-service.exe', '--resume-install-preflight'],
    ['$LuminaNoncePath\\lumina-service.exe', '--resume-install-preflight'],
    ['$LuminaNoncePath\\lumina-service.exe', '--bootstrap'], ['$LuminaNoncePath\\lumina-service.exe', '--uninstall'],
  ])
  assert.match(include, /!macro customInit[\s\S]*Call LuminaPrepareBootstrap[\s\S]*--print-install-plan[\s\S]*PREFLIGHT_REJECTED[\s\S]*!macroend/)
  assert.ok(!include.includes('RMDir') && !include.includes('Delete '))
  assert.match(include, /!macro LuminaRequireUninstallSuccess[\s\S]*\$\{Errors\}[\s\S]*SetErrorLevel 2[\s\S]*Quit[\s\S]*\$R0 != 0/)
  for (const invalid of ['../escape', 'x'.repeat(64), 'a'.repeat(63)]) {
    assert.throws(() => installerInclude(invalid)); assert.throws(() => recoveryEntry(invalid))
  }
  assert.throws(() => installerInclude(release), /bootstrap pin/)
  assert.throws(() => installerInclude(release, { bootstrapSource: 'bad\npath', bootstrapSHA256: 'b'.repeat(64) }), /source path/)
})

test('the compiled install section cannot migrate an elevated per-user uninstaller', async t => {
  const f = await fixture(t), prepared = await prepareWindowsClientPackage(f)
  const original = await readFile(join(dirname(createRequire(import.meta.url).resolve('app-builder-lib/package.json')), 'templates/nsis/installSection.nsh'), 'utf8')
  const section = await readFile(join(prepared.outputRoot, 'nsis-overrides/installSection.nsh'), 'utf8')
  assert.equal(section, removeUserUninstallerMigration(original))
  assert.ok(!section.includes('HKEY_CURRENT_USER'))
  assert.ok(section.includes('uninstallOldVersion SHELL_CONTEXT'))
  const include = await readFile(prepared.includePath, 'utf8')
  const init = /!macro customInit\n([\s\S]*?)!macroend/.exec(include)?.[1]
  assert.ok(init && init.indexOf('--print-install-plan') < init.indexOf('--resume-install-preflight'))
  assert.ok(init.indexOf('--resume-install-preflight') < init.indexOf('Call LuminaCloseBootstrap'))
  assert.match(init, /--resume-install-preflight[\s\S]*\$\{Errors\}[\s\S]*RESUME_PREFLIGHT_START[\s\S]*\$R0 != 0[\s\S]*RESUME_PREFLIGHT_REJECTED/)
  // The real template runs init before its old-uninstaller section. A retry
  // must finish the exact pending bootstrap before that uninstall can work.
  const template = await readFile(join(dirname(createRequire(import.meta.url).resolve('app-builder-lib/package.json')), 'templates/nsis/installer.nsi'), 'utf8')
  assert.ok(template.indexOf('!insertmacro customInit') < template.indexOf('!include "installSection.nsh"'))
  assert.ok(section.indexOf('uninstallOldVersion SHELL_CONTEXT') < section.indexOf('!insertmacro customInstall'))
  assert.ok(include.includes(`!cd "${join(prepared.outputRoot, 'nsis-overrides')}"`))
  assert.ok(include.includes('!addincludedir "'))
  assert.deepEqual(await readdir(join(prepared.outputRoot, 'nsis-overrides')), ['installSection.nsh', 'installUtil.nsh', 'uninstaller.nsh'])
  assert.ok(include.includes('!ifndef LUMINA_MACHINE_ONLY_INSTALL_SECTION'))
  assert.ok(section.startsWith('!define LUMINA_MACHINE_ONLY_INSTALL_SECTION\n'))
  assert.throws(() => removeUserUninstallerMigration(original.replace('HKEY_CURRENT_USER', 'changed')), /branch changed/)
})

test('customHeader defers protected plugin functions and keeps the template include directory until loaded', async t => {
  const f = await fixture(t), prepared = await prepareWindowsClientPackage(f)
  const require = createRequire(import.meta.url)
  const templateRoot = join(dirname(require.resolve('app-builder-lib/package.json')), 'templates/nsis')
  const template = await readFile(join(templateRoot, 'installer.nsi'), 'utf8')
  const hook = template.indexOf('!insertmacro customHeader')
  assert.ok(hook > template.indexOf('!include "common.nsh"'))
  assert.ok(hook > template.indexOf('!include "multiUser.nsh"'))
  assert.ok(hook > template.indexOf('!include "assistedInstaller.nsh"'))
  assert.ok(hook < template.indexOf('!include "installSection.nsh"'))
  const include = await readFile(prepared.includePath, 'utf8')
  const start = include.indexOf('!macro customHeader'), end = include.indexOf('!macroend', start)
  assert.ok(start >= 0 && end > start)
  const protectedIncludes = [...include.matchAll(/!include "[^"\r\n]*windows-client-bootstrap\.nsh"/g)]
  assert.equal(protectedIncludes.length, 1)
  assert.ok(protectedIncludes[0].index > start && protectedIncludes[0].index < end,
    'plugin functions must be expanded by customHeader after the shared plugin directories, never while defining hooks')
  assert.ok(protectedIncludes[0].index < include.indexOf('!cd ', start))
  assert.ok(!include.slice(0, start).includes('!cd '), 'shared header must not change CWD before builder includes')
  assert.match(include.slice(start, end), /!cd "[^"\r\n]+"/)
  assert.ok(!include.slice(start, end).includes('BUILD_UNINSTALLER'), 'both branches must select the restricted templates')
  assert.equal((include.match(/!cd /g) ?? []).length, 1)
})

test('fixed registry claims bracket legacy uninstall and registration without mutable execution or deletion paths', async t => {
  const f = await fixture(t), prepared = await prepareWindowsClientPackage(f)
  const templateRoot = join(dirname(createRequire(import.meta.url).resolve('app-builder-lib/package.json')), 'templates/nsis')
  const utilitySource = await readFile(join(templateRoot, 'include/installUtil.nsh'), 'utf8')
  const uninstallerSource = await readFile(join(templateRoot, 'uninstaller.nsh'), 'utf8')
  const utility = await readFile(join(prepared.outputRoot, 'nsis-overrides/installUtil.nsh'), 'utf8')
  const uninstaller = await readFile(join(prepared.outputRoot, 'nsis-overrides/uninstaller.nsh'), 'utf8')
  const section = await readFile(join(prepared.outputRoot, 'nsis-overrides/installSection.nsh'), 'utf8')
  const include = await readFile(prepared.includePath, 'utf8')
  assert.equal(utility, restrictWindowsUninstallUtilities(utilitySource))
  assert.equal(uninstaller, restrictWindowsUninstaller(uninstallerSource))
  const old = /^Function uninstallOldVersion\n([\s\S]*?)^FunctionEnd$/m.exec(utility)?.[1]
  assert.ok(old && !/ReadReg|readReg|PLUGINSDIR|CopyFiles|copyFile/.test(old))
  assert.ok(!/GetInQuotes|GetFileParent/.test(utility), 'unused registry command parsers must not survive the native warning gate')
  assert.deepEqual([...old.matchAll(/ExecWait '([^'\r\n]+)'/g)].map(match => match[1]),
    ['"$PROGRAMFILES64\\LuminaVPN\\Uninstall LuminaVPN.exe" /S /KEEP_APP_DATA /allusers --keep-shortcuts _?=$PROGRAMFILES64\\LuminaVPN'])
  assert.ok(old.indexOf('ExecWait') < old.indexOf('Call LuminaCheckUpgradeRemainder'))
  assert.match(old, /\$\{Errors\}\s+StrCpy \$R0 2\s+SetErrors\s+Return/)
  assert.match(old, /\$R0 != 0\s+Return[\s\S]*Call LuminaCheckUpgradeRemainder/)
  const remainder = /^Function LuminaCheckUpgradeRemainder\n([\s\S]*?)^FunctionEnd$/m.exec(utility)?.[1]
  assert.ok(remainder && !/^\s*(?:Exec|RMDir|Delete|CopyFiles|ReadReg)/m.test(remainder))
  assert.ok(remainder.includes('IntOp $0 $0 & 0x410') && remainder.includes('IntOp $2 $2 & 0x410'))
  assert.ok(remainder.includes('StrCmp $4 "Uninstall LuminaVPN.exe" lumina_remainder_next lumina_remainder_close'))
  assert.match(remainder, /FindNextFileW[^\n]*\?e'\s+Pop \$3[\s\S]*\$3 == 18/)
  assert.ok(!remainder.includes('GetLastError'), 'error disposition must come from the same native API call')
  assert.match(remainder, /\$R0 != 0[\s\S]*SetErrors/)
  assert.ok(uninstaller.includes('StrCmp "$INSTDIR$R0\\$R2" "$EXEPATH" 0 +2'))
  assert.ok(!uninstaller.includes('StrCmp "$R0\\$R2" "${UNINSTALL_FILENAME}"'))
  assert.ok(section.indexOf('handleUninstallResult SHELL_CONTEXT') < section.indexOf('!insertmacro LuminaClaimRegistry'))
  assert.ok(section.indexOf('!insertmacro LuminaClaimRegistry') < section.indexOf('!insertmacro installApplicationFiles'))
  assert.ok(section.indexOf('!insertmacro LuminaClaimRegistry') < section.indexOf('!insertmacro registryAddInstallInfo'))
  assert.ok(section.includes('!insertmacro LuminaSetLinkVars') && uninstaller.includes('!insertmacro LuminaSetLinkVars'))
  assert.ok(!/ReadRegStr.*MenuDirectory/.test(uninstaller))
  assert.match(include, /!macro LuminaClaimRegistry[\s\S]*--resume-install-preflight[\s\S]*REGISTRY_CLAIM_REJECTED[\s\S]*LuminaBootstrapFatal/)
  assert.throws(() => restrictWindowsUninstallUtilities(utilitySource.replace('Function uninstallOldVersion', 'Function unknown')), /changed/)
  assert.throws(() => restrictWindowsUninstaller(uninstallerSource.replace('MenuDirectory', 'UnknownDirectory')), /changed/)
  assert.throws(() => restrictWindowsUninstaller(uninstallerSource.replace('"${UNINSTALL_FILENAME}" 0 +2', '"changed" 0 +2')), /changed/)
})

test('protected bootstrap source uses exclusive files and locks the verified image through the fixed action', async () => {
  const source = await readFile(new URL('../scripts/windows-client-bootstrap.nsh', import.meta.url), 'utf8')
  assert.ok(source.includes('O:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)'))
  assert.match(source, /CreateFileW\(w r0, i 0xC0000000, i 0, p \$LuminaSA, i 1,/)
  assert.match(source, /CreateFileW\(w "\$LuminaNoncePath\\lumina-service.exe", i 0x80020000, i 1,/)
  assert.ok(source.includes('BCryptHashData') && source.includes('HASH_MISMATCH'))
  assert.ok(source.includes('bootstrap-trust.json') && source.includes('System::Int64Op $LuminaCreated + 1800'))
  assert.ok(source.includes('SHGetKnownFolderPath') && source.includes('GetSecurityInfo'))
  assert.ok(source.includes('PROGRAMDATA_ANCESTOR_ACL') && source.includes('DIRECTORY_REPARSE_OR_QUERY'))
  assert.match(source, /LookupAccountNameW\(p 0, w "NT SERVICE\\TrustedInstaller", p \$LuminaTrustedInstallerSID, \*i 68/)
  assert.equal((source.match(/EqualSid\(p r[04], p \$LuminaTrustedInstallerSID\)/g) ?? []).length, 2)
  assert.equal((source.match(/\$\{If\} \$LuminaCheckStrict == 0\s+System::Call '[^'\n]*EqualSid\(p r[04], p \$LuminaTrustedInstallerSID\)/g) ?? []).length, 2,
    'OS service identity applies only to ancestor owner/writer checks, never strict setup payloads')
  assert.match(source, /GetLengthSid\(p \$LuminaTrustedInstallerSID\)/)
  assert.ok(!/\*[ip]\s+\d+\s+\.r\d/.test(source), 'System input/output parameters have exactly source and destination slots')
  assert.match(source, /GetSecurityDescriptorControl\(p r2, \*i 0 r3, \*i \.r4\)/)
  assert.match(source, /\$\{If\} \$3 = 0x10/)
  assert.ok(!/\$\{(?:If|AndIf|OrIf|ElseIf)\}[^\n]*(?:==|!=)\s+0x/.test(source), 'numeric masks must not use LogicLib string equality')
  assert.match(source, /\$\{If\} \$LuminaCheckStrict == 1\s*;[^\n]*\n\s*IntOp \$7 \$7 & 0x500D0156/)
  assert.match(source, /IntOp \$7 \$7 & 0x100D0040/)
  assert.match(source, /CreateFileW\(w r0, i 0x120081, i 1, p 0, i 3, i 0x02200000/)
  assert.match(source, /GetFinalPathNameByHandleW\(p r1, w \.r4, i \$\{NSIS_MAX_STRLEN\}, i 0\)/)
  assert.ok(source.includes('StrCpy $5 "\\\\?\\$0"'))
  const anchorStart = source.indexOf('StrCpy $LuminaAnchorPath $LuminaSetupParent')
  const createSetup = source.indexOf('CreateDirectoryW(w "$LuminaSetupParent"')
  assert.ok(anchorStart > 0 && createSetup > anchorStart)
  const anchor = source.slice(anchorStart, createSetup)
  assert.ok(anchor.includes('StrCpy $LuminaAnchorPath "$LuminaProgramData\\Microsoft"'))
  assert.match(anchor, /LuminaAnchorHandle[\s\S]*LuminaCheckProtected[\s\S]*LuminaCheckPinnedDirectory/)
  for (const failure of ['PROGRAMDATA_ANCESTOR_CHANGED', 'PROGRAMDATA_CHANGED', 'PROGRAMDATA_ANCHOR_CHANGED']) assert.ok(anchor.includes(failure))
  assert.match(source, /CloseHandle\(p \$LuminaAnchorHandle\)'\s+StrCpy \$LuminaAnchorHandle 0/)
  assert.match(source, /System::Free \$LuminaTrustedInstallerSID\s+StrCpy \$LuminaTrustedInstallerSID 0/)
  assert.ok(!/PowerShell|nsExec::|CopyFileW|RMDir \/r|ExecWait.*\$INSTDIR/.test(source))
})

test('the NSIS trust declaration contains real quote escape bytes and produces the fixed JSON envelope', async () => {
  const source = await readFile(new URL('../scripts/windows-client-bootstrap.nsh', import.meta.url), 'utf8')
  const declarations = source.split(/\r?\n/).filter(line => line.includes('StrCpy $2') && line.includes('created_unix'))
  assert.equal(declarations.length, 1)
  const declaration = declarations[0]
  for (let i = 0; i < declaration.length; i++) if (declaration.charCodeAt(i) === 34) {
    assert.equal(declaration.charCodeAt(i - 1), 92, 'NSIS JSON quotes require a literal backslash byte')
    assert.equal(declaration.charCodeAt(i - 2), 36, 'NSIS escape must begin with a dollar byte')
  }
  const escapedQuote = String.fromCharCode(36, 92, 34)
  const prefix = "  StrCpy $2 '", nonce = 'a'.repeat(32), checksum = 'b'.repeat(64)
  assert.ok(declaration.startsWith(prefix) && declaration.endsWith("'"))
  const raw = declaration.slice(prefix.length, -1).replaceAll(escapedQuote, '"')
    .replaceAll('${LUMINA_BOOTSTRAP_SHA256}', checksum).replaceAll('$LuminaNonce', nonce)
    .replaceAll('$LuminaCreated', '1793960000').replaceAll('$LuminaExpires', '1793961800')
  assert.deepEqual(JSON.parse(raw), { version: 1, product: 'LuminaVPN', purpose: 'service-bootstrap', nonce,
    sha256: checksum, created_unix: 1793960000, expires_unix: 1793961800 })
})

test('client configuration requires machine installation and disables late image mutations', async t => {
  const f = await fixture(t), prepared = await prepareWindowsClientPackage(f)
  const config = windowsClientConfiguration(prepared, { outputRoot: join(f.root, 'artifacts'), iconPath: join(f.root, 'icons/icon.ico') })
  assert.equal(config.nsis.perMachine, true)
  assert.equal(config.nsis.allowToChangeInstallationDirectory, false)
  assert.equal(config.nsis.deleteAppDataOnUninstall, false)
  assert.equal(config.nsis.runAfterFinish, false)
  assert.deepEqual(config.toolsets, { nsis: '1.2.1' })
  assert.equal(config.nsis.customNsisBinary, undefined)
  assert.equal(config.nsis.customNsisResources, undefined)
  assert.equal(config.win.requestedExecutionLevel, 'asInvoker')
  assert.equal(config.win.signAndEditExecutable, false)
  assert.equal(config.win.signExecutable, false)
  assert.deepEqual(config.extraResources, [{ from: prepared.guiRoot, to: '.' }])
  assert.deepEqual(config.extraFiles, [{ from: prepared.machineRoot, to: '.' }])
  assert.equal(typeof config.afterPack, 'function'); assert.equal(typeof config.afterSign, 'function')
})

test('the real builder loads only the explicit client module and keeps its byte verification hooks', async t => {
  const f = await fixture(t), prepared = await prepareWindowsClientPackage(f)
  const configPath = await writeWindowsClientConfiguration(prepared, { outputRoot: join(f.root, 'artifacts'), iconPath: join(f.root, 'icons/icon.ico') })
  const require = createRequire(import.meta.url)
  const { getConfig } = require('app-builder-lib/out/util/config/config')
  const { validateSchema } = require('app-builder-lib/out/util/config/schemaValidator')
  const config = await getConfig(fileURLToPath(new URL('..', import.meta.url)), configPath)
  await validateSchema(config)
  assert.equal(config.extraResources.length, 1)
  assert.equal(config.extraResources[0].from, prepared.guiRoot)
  assert.equal(config.extraFiles.length, 1)
  assert.equal(config.extraFiles[0].from, prepared.machineRoot)
  assert.equal(config.win.target.length, 1)
  assert.equal(config.mac, undefined)
  assert.equal(config.nsis.include, prepared.includePath)
  assert.equal(config.nsis.script, undefined)
  assert.deepEqual(config.toolsets, { nsis: '1.2.1' })
  const { nsisChecksums } = require('app-builder-lib/out/toolsets/windows')
  assert.equal(nsisChecksums[config.toolsets.nsis]['nsis-bundle-3.12.tar.gz'],
    '56997fdefe25e7928a1a68b4583d08b240b66cf660234053b20131a74cc082f4')
  const packaged = join(f.root, 'win-unpacked')
  await cp(prepared.machineRoot, packaged, { recursive: true })
  await cp(prepared.guiRoot, join(packaged, 'resources'), { recursive: true })
  await config.afterPack({ appOutDir: packaged })
  await writeFile(join(packaged, 'resources/backend/netlaunch.exe'), 'late stale backend')
  await assert.rejects(config.afterSign({ appOutDir: packaged }), /bytes changed/)
})

test('the Go v1 install plan fixture keeps all 17 fields and explicit review requirements', () => {
  // Same public synthetic paths as Go TestInstallPlanSerializationMatchesFixedInstallerContract.
  // This fixture is not a native target observation or proof of installation.
  const plan = { version: 1, schema: 'lumina-service-install-v1', service_name: 'LuminaVPNService', image_kind: 'service',
    image_relative: 'releases/<reviewed-release>/lumina-service.exe', account: 'LocalSystem with an explicit service SID',
    auto_connect: false, requires_review: true, installed: false, bootstrap_available: true,
    recovery_service_name: 'LuminaVPNRecoveryService', recovery_arguments: ['--recover-service'],
    service_arguments: ['--service'], supported_entries: ['--bootstrap', '--service', '--recover', '--recover-service', '--uninstall', '--print-install-plan', '--resume-install-preflight'],
    target_preflight: 'absent', target_root: 'C:\\Program Files\\LuminaVPN', data_root: 'C:\\ProgramData\\LuminaVPN\\ServiceState' }
  assert.equal(Object.keys(plan).length, 17)
  validateInstallPlan(plan)
  validateInstallPlan({ ...plan, target_preflight: 'protected', installed: true })
  validateInstallPlan({ ...plan, target_root: 'D:\\Program Files\\LuminaVPN' })
  for (const patch of [{ bootstrap_available: false }, { auto_connect: true }, { supported_entries: plan.supported_entries.slice(1) },
    { supported_entries: plan.supported_entries.filter(entry => entry !== '--resume-install-preflight') },
    { supported_entries: [...plan.supported_entries, '--exec'] }, { service_arguments: ['--service', 'user-path'] },
    { version: '1' }, { schema: 'unknown-install-v1' }, { requires_review: false }, { installed: 'false' },
    { image_relative: 'C:\\user\\service.exe' }, { account: 'LocalSystem with explicit service SID and reviewed minimum privileges' },
    { recovery_arguments: ['--recover-service', 'user-path'] },
    { recovery_service_name: 'OtherRecoveryService' }, { target_preflight: 'unknown' }, { target_preflight: 'unsafe' },
    { target_root: 'LuminaVPN' }, { target_root: '\\\\server\\share\\LuminaVPN' },
    { target_root: 'C:\\Program Files\\..\\Temp\\LuminaVPN' }, { data_root: 'C:\\ProgramData\\OtherService' },
    { data_root: '' }, { arbitrary_command: '--exec' }]) {
    assert.throws(() => validateInstallPlan({ ...plan, ...patch }), /contract is not ready/)
  }
  const { data_root, ...missingField } = plan
  assert.throws(() => validateInstallPlan(missingField), /contract is not ready/)
})

function buildContractPlan() {
  return { version: 1, schema: 'lumina-service-install-v1', service_name: 'LuminaVPNService', image_kind: 'service',
    image_relative: 'releases/<reviewed-release>/lumina-service.exe', account: 'LocalSystem with an explicit service SID',
    auto_connect: false, requires_review: true, installed: false, bootstrap_available: true,
    recovery_service_name: 'LuminaVPNRecoveryService', recovery_arguments: ['--recover-service'],
    service_arguments: ['--service'], supported_entries: ['--bootstrap', '--service', '--recover', '--recover-service', '--uninstall', '--print-install-plan', '--resume-install-preflight'],
    target_preflight: 'unsafe', target_root: 'C:\\Program Files\\LuminaVPN', data_root: 'C:\\ProgramData\\LuminaVPN\\ServiceState' }
}

test('build-only contract validation preserves the native unsafe observation and strict installer rejection', () => {
  for (const [state, status, preflightPassed] of [['absent', 0, true], ['protected', 0, true], ['unsafe', 1, false]]) {
    const plan = { ...buildContractPlan(), target_preflight: state }, stdout = JSON.stringify(plan)
    const result = { status, signal: null, stdout }
    const observation = validateBuildInstallPlanResult(result)
    assert.deepEqual(observation, { native_preflight_passed: preflightPassed, exit_status: status, plan })
    assert.equal(result.stdout, stdout, 'the native plan must not be rewritten for packaging')
    if (state === 'unsafe') assert.throws(() => validateInstallPlan(observation.plan), /contract is not ready/)
  }
})

test('build-only contract rejects inconsistent exits and process failures despite valid JSON', () => {
  const plan = buildContractPlan(), result = { status: 1, signal: null, stdout: JSON.stringify(plan) }
  for (const patch of [{ status: 0 }, { status: 2 }, { status: -1 }, { status: null }, { status: undefined }, { status: '1' },
    { error: new Error('spawn failed') }, { error: Object.assign(new Error('timed out'), { code: 'ETIMEDOUT' }) },
    { signal: 'SIGTERM' }, { signal: 'SIGKILL' },
    { stdout: JSON.stringify({ ...plan, target_preflight: 'absent' }) },
    { stdout: JSON.stringify({ ...plan, target_preflight: 'protected' }) }]) {
    assert.throws(() => validateBuildInstallPlanResult({ ...result, ...patch }))
  }
  assert.throws(() => validateBuildInstallPlanResult(null))
})

test('unsafe build observations must still satisfy the entire fixed interface and native path contract', () => {
  const plan = buildContractPlan()
  for (const patch of [{ target_preflight: 'unknown' }, { target_preflight: '' },
    { supported_entries: plan.supported_entries.filter(entry => entry !== '--resume-install-preflight') },
    { supported_entries: [...plan.supported_entries.slice(0, 6), '--exec'] },
    { version: 2 }, { bootstrap_available: false }, { service_arguments: ['--service', 'user-path'] },
    { recovery_arguments: ['--recover-service', 'user-path'] }, { arbitrary_command: '--exec' },
    { target_root: 'LuminaVPN' }, { target_root: '\\\\server\\share\\LuminaVPN' },
    { target_root: 'C:\\Program Files\\..\\Temp\\LuminaVPN' }, { data_root: 'C:\\ProgramData\\OtherService' }]) {
    assert.throws(() => validateBuildInstallPlanResult({ status: 1, stdout: JSON.stringify({ ...plan, ...patch }) }))
  }
  const { data_root, ...missingField } = plan
  assert.throws(() => validateBuildInstallPlanResult({ status: 1, stdout: JSON.stringify(missingField) }))
})

test('build-only contract refuses malformed or missing stdout instead of substituting a plan', () => {
  for (const stdout of ['', '{', 'null', '[]', 'true', JSON.stringify(buildContractPlan()) + '\nextra output', null, undefined]) {
    assert.throws(() => validateBuildInstallPlanResult({ status: 1, stdout }))
  }
})

test('read-only Go metadata must match the chosen mode for every fixed image', () => {
  validateBuildTags('file.exe: go1.27.3\n\tbuild\t-tags=windows_client\n', 'daily')
  validateBuildTags('\tbuild\t-tags=windows_client,windows_client_validation\n', 'validation')
  for (const [text, mode] of [['\tbuild\t-tags=windows_client\n', 'validation'],
    ['\tbuild\t-tags=windows_client,windows_client_validation\n', 'daily'], ['', 'daily'],
    ['\tbuild\t-tags=windows_client,custom\n', 'daily']]) assert.throws(() => validateBuildTags(text, mode))
})

test('the package CLI preserves failure after the fixed asynchronous cleanup hook exits zero', async t => {
  const { spawnSync } = await import('node:child_process')
  const { rmdir, unlink } = await import('node:fs/promises')
  const root = await mkdtemp(join(tmpdir(), 'lumina-build-exit-'))
  const preload = join(root, 'cleanup.cjs')
  t.after(async () => {
    await unlink(preload).catch(error => { if (error.code !== 'ENOENT') throw error })
    await rmdir(root)
  })
  const hook = createRequire(import.meta.url).resolve('async-exit-hook')
  await writeFile(preload, `require(${JSON.stringify(hook)})((done) => {
  setImmediate(() => { process.stderr.write('BUILD_EXIT_FIXTURE_CLEANUP_COMPLETED\\n'); done(); });
});\n`)
  // Invalid mode fails before staging or building. Exercise the real CLI catch,
  // while reproducing only the fixed dependency's asynchronous exit behavior.
  const result = spawnSync(process.execPath, ['--require', preload,
    fileURLToPath(new URL('../scripts/windows-client-package.mjs', import.meta.url)), '--mode', 'invalid'], {
    shell: false, windowsHide: true, encoding: 'utf8', timeout: 10_000, maxBuffer: 64 << 10,
    env: { ...process.env, NODE_OPTIONS: '' },
  })
  assert.equal(result.error, undefined)
  assert.equal(result.signal, null)
  assert.equal(result.status, 1, result.stderr)
  assert.match(result.stderr, /An explicit daily or validation mode is required|Windows client packaging requires native Windows x64/)
  assert.match(result.stderr, /BUILD_EXIT_FIXTURE_CLEANUP_COMPLETED/)
  assert.doesNotMatch(result.stdout, /Windows client package built/)
})
