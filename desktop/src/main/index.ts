import { app, BrowserWindow, dialog, ipcMain, Menu, nativeImage, shell, Tray, type IpcMainInvokeEvent } from 'electron'
import { mkdir, readFile, rename, writeFile, lstat } from 'node:fs/promises'
import { createHash, randomUUID } from 'node:crypto'
import { join, resolve } from 'node:path'
import { pathToFileURL } from 'node:url'
import { deflateSync } from 'node:zlib'
import { Bridge } from './bridge'
import { isRecord, validateRequest } from '../../protocol/validation'
import { READ_METHODS, type Hello, type ReadMethod, type Profile } from '../../protocol/types'
import { CLIENT_METHODS, opaqueID, validateClientRequest, type ServiceSnapshot, type ServiceOperation, type ClientMethod } from '../../protocol/client'
import { QuitController, confirmedUninstalledWithoutOwnedState } from './quit-controller'
import {installedRecoveryScript} from './recovery-entry'
import { assertProfileMayLeave, commitProfileSelection, windowsClientProfile } from './profile-selection'

let window: BrowserWindow | null = null
let tray: Tray | null = null
let bridge: Bridge | null = null
let quitting = false
let profile: string | undefined
let choosing = false
let pendingMutations=0
let exitInProgress = false
let closeNoticeSeen = false
const rendererPath = resolve(__dirname, '../renderer/index.html')
const rendererURL = pathToFileURL(rendererPath).href
const resourceRoot = (): string => app.isPackaged ? process.resourcesPath : resolve(__dirname, '../../resources')
const binaryPath = (): string => join(resourceRoot(), 'backend', process.platform === 'win32' ? 'netlaunch.exe' : 'netlaunch')
const runtimePath = (): string => join(resourceRoot(), 'runtime')

function authorize(event: IpcMainInvokeEvent): void {
  if (!window || event.sender !== window.webContents || event.senderFrame !== window.webContents.mainFrame || event.senderFrame.url.split('#')[0] !== rendererURL) throw new Error('UNTRUSTED_FRAME')
}
function client(): Bridge {
  bridge ??= new Bridge(binaryPath(), runtimePath(), profile, app.getVersion())
  return bridge
}
const importGrants = new Map<string, { content: string; expires: number;profileID:string }>()
let exitController: QuitController | null = null
let exitIdentity: { request: string; profile: string; run?: string } | null = null
function finishQuit(): void { quitting = true; app.quit() }
async function normalExit(): Promise<boolean> {
  if (choosing || exitInProgress) return false
  exitInProgress = true
  try { return await attemptNormalExit() } finally { exitInProgress = false }
}
async function attemptNormalExit(): Promise<boolean> {
  if (process.platform !== 'win32') { finishQuit(); return true }
  try {
    const hello = await client().request('session.hello', { protocol_major: 1, app_version: app.getVersion() }) as Hello
    if (process.platform !== 'win32' || hello.capabilities.windows_client !== true) { finishQuit(); return true }
    const preflight = await client().request('service.snapshot', {}) as ServiceSnapshot
    if (confirmedUninstalledWithoutOwnedState(preflight)) { finishQuit(); return true }
    exitController ??= new QuitController({
      request: async () => {
        const snapshot = await client().request('service.snapshot', {}) as ServiceSnapshot
        const request = randomUUID()
        exitIdentity = { request, profile: snapshot.profile_id, run:snapshot.run_ref }
        const operation = await client().request('service.submit', { request_id: request, profile_id: snapshot.profile_id,
          expected_revision: snapshot.revision, ...(snapshot.run_ref ? { run_ref: snapshot.run_ref } : {}), kind: 'exit_restore', stop: {} }) as ServiceOperation
        if (operation.kind !== 'exit_restore' || operation.request_id !== request || operation.profile_id !== snapshot.profile_id || snapshot.run_ref && operation.run_ref !== snapshot.run_ref) throw new Error('EXIT_OPERATION_MISMATCH')
        return operation
      },
      inspect: async id => {
        const operation = await client().request('service.operation', { operation_id: id }) as ServiceOperation
        if (operation.kind !== 'exit_restore' || operation.request_id !== exitIdentity?.request || operation.profile_id !== exitIdentity.profile || exitIdentity.run && operation.run_ref !== exitIdentity.run) throw new Error('EXIT_OPERATION_MISMATCH')
        return { ...operation, error_code: operation.error?.code }
      }
    }, finishQuit, code => { showWindow(); window?.webContents.send('lumina:exit-error', code); void dialog.showMessageBox({type:'error',title:'恢复尚未完成',message:'停止或恢复尚未确认，LuminaVPN 保持打开。',detail:'请在诊断与恢复页面检查后台状态。',buttons:['知道了']}) })
    return exitController.requestExit()
  } catch {
    showWindow(); window?.webContents.send('lumina:exit-error', 'EXIT_RESTORE_UNAVAILABLE')
    void dialog.showMessageBox({type:'error',title:'恢复状态未确认',message:'后台恢复确认暂不可用，LuminaVPN 保持打开。',detail:'请检查诊断与恢复页面。',buttons:['知道了']})
    return false
  }
}
const preferencesFile = (): string => join(app.getPath('userData'), 'preferences.json')
async function savePreferences(selection: { profile?: string } = { profile }): Promise<void> {
  await mkdir(app.getPath('userData'), { recursive: true, mode: 0o700 })
  const temp = preferencesFile() + '.tmp-' + randomUUID()
  await writeFile(temp, JSON.stringify({ profile: selection.profile, closeNoticeSeen }), { mode: 0o600 })
  await rename(temp, preferencesFile())
}
async function showRecovery(): Promise<boolean> {
  const selectedProfile = profile
  let hello: Hello
  try { hello = await client().request('session.hello', { protocol_major: 1, app_version: app.getVersion() }) as Hello }
  catch { throw new Error('RECOVERY_UNAVAILABLE') }
  if (hello.capabilities.windows_client === true) {
    const target=client(),current=await target.request('profile.inspect') as Profile
    if(!opaqueID(current.profile_id))throw new Error('RECOVERY_UNAVAILABLE')
    const entry=await target.request('workspace.read',{action:'recovery_entry',profile_id:current.profile_id})
    if(bridge!==target)throw new Error('PROFILE_CHANGED')
    const script=installedRecoveryScript(entry)
    const dir=join(app.getPath('userData'),'recovery',createHash('sha256').update(current.profile_id).digest('hex').slice(0,16))
    await mkdir(dir,{recursive:true,mode:0o700})
    const file=join(dir,'Stop-and-Recover-Service.cmd')
    await writeFile(file,script,{mode:0o600})
    shell.showItemInFolder(file)
    return true
  }
  if (hello.capabilities.native_lifecycle !== true) throw new Error('RECOVERY_UNAVAILABLE')
  const identity = createHash('sha256').update(selectedProfile ?? 'default').digest('hex').slice(0, 16)
  const dir = join(app.getPath('userData'), 'recovery', identity)
  await mkdir(dir, { recursive: true, mode: 0o700 })
  const args = ['down', '--runtime', runtimePath(), ...(selectedProfile ? ['--profile', selectedProfile] : [])]
  let file: string
  if (process.platform === 'win32') {
    const quote = (x: string): string => "'" + x.replaceAll("'", "''") + "'"
    file = join(dir, 'Stop-and-Recover.cmd')
    const command = '& ' + [binaryPath(), ...args].map(quote).join(' ') + '; exit $LASTEXITCODE'
    const encoded = Buffer.from(command, 'utf16le').toString('base64')
    await writeFile(file, '@echo off\r\nsetlocal DisableDelayedExpansion\r\npowershell.exe -NoProfile -EncodedCommand ' + encoded + '\r\nset "lumina_exit=%errorlevel%"\r\npause\r\nexit /b %lumina_exit%\r\n', { mode: 0o600 })
  } else {
    const quote = (x: string): string => "'" + x.replaceAll("'", "'\\''") + "'"
    file = join(dir, '停止与恢复.command')
    await writeFile(file, '#!/bin/sh\n' + [binaryPath(), ...args].map(quote).join(' ') + '\nrc=$?\nprintf "\\n命令已结束（退出码 %s）。按回车关闭。\\n" "$rc"\nread answer\nexit "$rc"\n', { mode: 0o700 })
  }
  // Reveal the independent CLI entry; opening the folder never starts recovery.
  shell.showItemInFolder(file)
  return true
}
async function showRecoveryFromTray(): Promise<void> {
  try { await showRecovery() }
  catch {
    if (quitting) return
    try {
      await dialog.showMessageBox({ type: 'warning', title: '恢复入口不可用', message: '当前桌面预览无法提供可用的恢复入口。', detail: '请使用创建该运行的 CLI 及其独立恢复入口。', buttons: ['知道了'] })
    } catch {}
  }
}
function safeIPC(action: (event: IpcMainInvokeEvent, ...args: any[]) => Promise<unknown>) {
  return async (event: IpcMainInvokeEvent, ...args: unknown[]) => {
    try { return { ok: true, result: await action(event, ...args) } }
    catch (error) {
      const code = error instanceof Error && 'code' in error ? String(error.code) : error instanceof Error ? error.message : ''
      return { ok: false, error: { code: /^[A-Z_]{1,64}$/.test(code) ? code : 'READ_FAILED' } }
    }
  }
}
function registerIPC(): void {
  ipcMain.handle('lumina:client', safeIPC(async (event, method: unknown, params: unknown) => {
    authorize(event)
    if (process.platform !== 'win32' || typeof method !== 'string' || !CLIENT_METHODS.includes(method as ClientMethod) || !validateClientRequest(method, params)) throw new Error('INVALID_PARAMS')
    const mutating=method==='service.submit'||method==='workspace.submit'
    if(mutating&&choosing)throw new Error('PROFILE_BUSY')
    if(mutating)pendingMutations++
    try{return await client().request(method as ClientMethod, params as Record<string, unknown>)}finally{if(mutating)pendingMutations--}
  }))
  ipcMain.handle('lumina:normal-exit', safeIPC(async event => { authorize(event); return normalExit() }))
  ipcMain.handle('lumina:pick-import', safeIPC(async (event,params:unknown) => {
    authorize(event)
    if (process.platform !== 'win32') throw new Error('CLIENT_UNAVAILABLE')
    if(choosing)throw new Error('PROFILE_BUSY')
    if(!isRecord(params)||Object.keys(params).length!==1||!opaqueID(params.profile_id))throw new Error('INVALID_PARAMS')
    const target=client(),identity=await target.request('profile.inspect') as Profile
    if(identity.profile_id!==params.profile_id||bridge!==target)throw new Error('PROFILE_CHANGED')
    for (const [id, grant] of importGrants) if (grant.expires <= Date.now()) importGrants.delete(id)
    if (importGrants.size >= 8) throw new Error('BUSY')
    const result = await dialog.showOpenDialog(window!, { title: '选择个人节点文件', properties: ['openFile', 'dontAddToRecent'], filters: [{ name: '节点文件', extensions: ['json','yaml','yml','txt'] }] })
    if (result.canceled || result.filePaths.length !== 1) return null
    if(bridge!==target)throw new Error('PROFILE_CHANGED')
    const info = await lstat(result.filePaths[0]); if (!info.isFile() || info.isSymbolicLink() || info.size > 700000) throw new Error('IMPORT_INVALID')
    const content = await readFile(result.filePaths[0], 'utf8'); if (Buffer.byteLength(content, 'utf8') > 700000) throw new Error('IMPORT_INVALID')
    if(bridge!==target)throw new Error('PROFILE_CHANGED')
    const id = randomUUID(); importGrants.set(id, { content, expires: Date.now() + 600000,profileID:params.profile_id }); return { import_id: id }
  }))
  ipcMain.handle('lumina:import-nodes', safeIPC(async (event, params: unknown) => {
    authorize(event)
    if(choosing)throw new Error('PROFILE_BUSY')
    if (!isRecord(params) || Object.keys(params).some(k => !['request_id','import_id','profile_id'].includes(k)) || !opaqueID(params.request_id) || !opaqueID(params.import_id)||!opaqueID(params.profile_id)) throw new Error('INVALID_PARAMS')
    const grant = importGrants.get(params.import_id); importGrants.delete(params.import_id)
    if (!grant || grant.expires <= Date.now()) throw new Error('IMPORT_EXPIRED')
    if(grant.profileID!==params.profile_id)throw new Error('PROFILE_CHANGED')
    const target=client(),identity=await target.request('profile.inspect') as Profile
    if(identity.profile_id!==params.profile_id||bridge!==target)throw new Error('PROFILE_CHANGED')
    if(choosing)throw new Error('PROFILE_BUSY')
    pendingMutations++
    try{return await target.request('workspace.submit', { action: 'import_nodes', profile_id:params.profile_id,request_id: params.request_id, content: grant.content })}finally{pendingMutations--}
  }))
  ipcMain.handle('lumina:read', safeIPC(async (event, method: unknown, input: unknown) => {
    authorize(event)
    if (typeof method !== 'string' || !READ_METHODS.includes(method as ReadMethod)) throw new Error('INVALID_REQUEST')
    if (method === 'session.hello' && (!isRecord(input) || Object.keys(input).length !== 0)) throw new Error('INVALID_PARAMS')
    const params = method === 'session.hello' ? { protocol_major: 1, app_version: app.getVersion() } : input
    validateRequest(method, params)
    return client().request(method, params as Record<string, unknown>)
  }))
  ipcMain.handle('lumina:choose-profile', safeIPC(async event => {
    authorize(event)
    if (choosing||pendingMutations||exitInProgress) throw new Error('PROFILE_BUSY')
    choosing = true
    try {
      const current = client()
      const clientMode = process.platform === 'win32' && await windowsClientProfile(current, app.getVersion())
      await assertProfileMayLeave(current, clientMode)
      if (bridge !== current || quitting) throw new Error('PROFILE_CHANGED')
      const result = await dialog.showOpenDialog(window!, { title: '选择已有的 LuminaVPN 配置目录', properties: ['openDirectory', 'dontAddToRecent'] })
      if (result.canceled || result.filePaths.length !== 1) return null
      const next = new Bridge(binaryPath(), runtimePath(), result.filePaths[0], app.getVersion())
      return commitProfileSelection({ current, next, nextPath: result.filePaths[0], clientMode, mode: 'select', version: app.getVersion(),
        currentUnchanged: () => bridge === current && !quitting,
        persist: selected => savePreferences({ profile: selected }),
        publish: (_next, selected) => { bridge = next; profile = selected; current.close(); exitController = null; exitIdentity = null; importGrants.clear() }
      })
    } finally { choosing = false }
  }))
  ipcMain.handle('lumina:restore-default-profile', safeIPC(async event => {
    authorize(event)
    if (process.platform !== 'win32') throw new Error('CLIENT_UNAVAILABLE')
    if (choosing || pendingMutations || exitInProgress) throw new Error('PROFILE_BUSY')
    choosing = true
    try {
      const current = client()
      if (!await windowsClientProfile(current, app.getVersion())) throw new Error('CLIENT_UNAVAILABLE')
      // Omit --profile: the trusted backend resolves its fixed default itself.
      const next = new Bridge(binaryPath(), runtimePath(), undefined, app.getVersion())
      return commitProfileSelection({ current, next, clientMode: true, mode: 'recover-default', version: app.getVersion(),
        currentUnchanged: () => bridge === current && !quitting,
        persist: selected => savePreferences({ profile: selected }),
        publish: () => { bridge = next; profile = undefined; current.close(); exitController = null; exitIdentity = null; importGrants.clear() }
      })
    } finally { choosing = false }
  }))
  ipcMain.handle('lumina:show-recovery', safeIPC(async event => { authorize(event); return showRecovery() }))
}

// A tiny code-drawn tray glyph avoids binary source assets and stays crisp at 2x.
function trayImage() {
  const crc = (b: Buffer): number => { let c = 0xffffffff; for (const n of b) { c ^= n; for (let i = 0; i < 8; i++) c = (c >>> 1) ^ ((c & 1) ? 0xedb88320 : 0) } return (c ^ 0xffffffff) >>> 0 }
  const chunk = (tag: string, b: Buffer): Buffer => { const name = Buffer.from(tag); const size = Buffer.alloc(4); size.writeUInt32BE(b.length); const sum = Buffer.alloc(4); sum.writeUInt32BE(crc(Buffer.concat([name, b]))); return Buffer.concat([size, name, b, sum]) }
  const size = 36, rows = Buffer.alloc(size * (size * 4 + 1))
  for (let y = 0; y < size; y++) for (let x = 0; x < size; x++) {
    const at = y * (size * 4 + 1) + 1 + x * 4
    const draw = x >= 9 && x < 15 && y >= 7 && y < 29 || x >= 9 && x < 28 && y >= 23 && y < 29
    rows[at + 3] = draw ? 255 : 0
  }
  const header = Buffer.alloc(13); header.writeUInt32BE(size, 0); header.writeUInt32BE(size, 4); header[8] = 8; header[9] = 6
  const img = nativeImage.createFromBuffer(Buffer.concat([Buffer.from([137,80,78,71,13,10,26,10]), chunk('IHDR', header), chunk('IDAT', deflateSync(rows)), chunk('IEND', Buffer.alloc(0))])).resize({ width: 18, height: 18 })
  img.setTemplateImage(true); return img
}
function showWindow(): void { if (!window) createWindow(); window!.show(); window!.focus() }
function createTray(): void {
  try {
    tray = new Tray(trayImage())
    tray.setToolTip('LuminaVPN')
    tray.setContextMenu(Menu.buildFromTemplate([
      { label: '打开 LuminaVPN', click: showWindow },
      { label: '显示独立恢复入口', click: () => { void showRecoveryFromTray() } },
      { type: 'separator' },
      { label: process.platform === 'win32' ? '停止并恢复后退出' : '退出界面（保留现有网络）', click: () => { void normalExit() } }
    ]))
    tray.on('click', showWindow)
  } catch { tray = null }
}
function createWindow(): void {
  const created = new BrowserWindow({
    title: 'LuminaVPN', width: 1280, height: 850, minWidth: 960, minHeight: 680,
    backgroundColor: '#f4f7f5', autoHideMenuBar: true,
    webPreferences: { preload: resolve(__dirname, '../preload/index.js'), nodeIntegration: false, contextIsolation: true, sandbox: true, webviewTag: false, devTools: !app.isPackaged }
  })
  window = created
  const web = created.webContents
  web.setWindowOpenHandler(() => ({ action: 'deny' }))
  web.on('will-navigate', (event, url) => { if (url.split('#')[0] !== rendererURL) event.preventDefault() })
  web.on('will-attach-webview', event => event.preventDefault())
  web.session.setPermissionRequestHandler((_web, _permission, cb) => cb(false))
  web.session.setPermissionCheckHandler(() => false)
  web.on('render-process-gone', () => {
    if (quitting || window !== created || created.isDestroyed()) return
    const bounds = created.getBounds(), hidden = !created.isVisible()
    // A new webContents provides a fresh sandbox and control frame. Keep the
    // old window until replacement exists, including when a tray is unavailable.
    createWindow(); window!.setBounds(bounds)
    if (hidden) window!.hide()
    created.destroy()
  })
  created.on('close', event => {
    if (!quitting && tray) {
      event.preventDefault(); created.hide()
      if (!closeNoticeSeen) {
        closeNoticeSeen = true; if (!choosing) void savePreferences().catch(() => {})
        void dialog.showMessageBox({ type: 'info', title: 'LuminaVPN 已隐藏到菜单栏', message: '现有网络不会因关闭界面而停止。', detail: '点击菜单栏图标重新打开。需要停止时，使用独立恢复入口。', buttons: ['知道了'] })
      }
    }
  })
  created.on('closed', () => { if (window === created) window = null })
  void created.loadFile(rendererPath)
}

if (!app.requestSingleInstanceLock()) app.quit()
else {
  app.on('second-instance', showWindow)
  app.whenReady().then(async () => {
    try {
      const raw: unknown = JSON.parse(await readFile(preferencesFile(), 'utf8'))
      if (typeof raw === 'object' && raw !== null && !Array.isArray(raw)) {
        const p = raw as Record<string, unknown>
        if (typeof p.profile === 'string' && p.profile.length < 4096 && resolve(p.profile) === p.profile) profile = p.profile
        closeNoticeSeen = p.closeNoticeSeen === true
      }
    } catch {}
    registerIPC(); createTray(); createWindow()
    Menu.setApplicationMenu(Menu.buildFromTemplate([
      ...(process.platform === 'darwin' ? [{ label: 'LuminaVPN', submenu: [{ role: 'about' as const }, { type: 'separator' as const }, { label: '退出界面（保留现有网络）', click: () => { void normalExit() } }] }] : []),
      { role: 'editMenu' }, { role: 'viewMenu' }, { role: 'windowMenu' }
    ]))
    app.on('activate', showWindow)
  })
  app.on('window-all-closed', () => { if (!tray && !quitting) void normalExit() })
  app.on('before-quit', event => { if (!quitting && process.platform === 'win32') { event.preventDefault(); void normalExit(); return }; quitting = true; bridge?.close(); tray?.destroy(); tray = null; importGrants.clear() })
}
