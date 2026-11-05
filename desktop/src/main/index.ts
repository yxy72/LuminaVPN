import { app, BrowserWindow, dialog, ipcMain, Menu, nativeImage, shell, Tray, type IpcMainInvokeEvent } from 'electron'
import { mkdir, readFile, rename, writeFile } from 'node:fs/promises'
import { createHash, randomUUID } from 'node:crypto'
import { join, resolve } from 'node:path'
import { pathToFileURL } from 'node:url'
import { deflateSync } from 'node:zlib'
import { Bridge } from './bridge'
import { isRecord, validateRequest } from '../../protocol/validation'
import type { Hello } from '../../protocol/types'

let window: BrowserWindow | null = null
let tray: Tray | null = null
let bridge: Bridge | null = null
let quitting = false
let profile: string | undefined
let choosing = false
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
const preferencesFile = (): string => join(app.getPath('userData'), 'preferences.json')
async function savePreferences(selectedProfile = profile): Promise<void> {
  await mkdir(app.getPath('userData'), { recursive: true, mode: 0o700 })
  const temp = preferencesFile() + '.tmp-' + randomUUID()
  await writeFile(temp, JSON.stringify({ profile: selectedProfile, closeNoticeSeen }), { mode: 0o600 })
  await rename(temp, preferencesFile())
}
async function showRecovery(): Promise<boolean> {
  const selectedProfile = profile
  let hello: Hello
  try { hello = await client().request('session.hello', { protocol_major: 1, app_version: app.getVersion() }) as Hello }
  catch { throw new Error('RECOVERY_UNAVAILABLE') }
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
  ipcMain.handle('lumina:read', safeIPC(async (event, method: unknown, input: unknown) => {
    authorize(event)
    if (method === 'session.hello' && (!isRecord(input) || Object.keys(input).length !== 0)) throw new Error('INVALID_PARAMS')
    const params = method === 'session.hello' ? { protocol_major: 1, app_version: app.getVersion() } : input
    validateRequest(method, params)
    return client().request(method, params as Record<string, unknown>)
  }))
  ipcMain.handle('lumina:choose-profile', safeIPC(async event => {
    authorize(event)
    if (choosing) throw new Error('BUSY')
    choosing = true
    try {
      const maySwitch = async (): Promise<boolean> => {
        const state = await client().request('state.get') as { run_ref: string | null; recovery_required: boolean; status: { phase: string } }
        return !state.recovery_required && (state.status.phase === 'stopped' || !state.run_ref && state.status.phase === 'not_started')
      }
      if (!await maySwitch()) throw new Error('PROFILE_BUSY')
      const result = await dialog.showOpenDialog(window!, { title: '选择已有的 LuminaVPN 配置目录', properties: ['openDirectory', 'dontAddToRecent'] })
      if (result.canceled || result.filePaths.length !== 1) return null
      const next = new Bridge(binaryPath(), runtimePath(), result.filePaths[0], app.getVersion())
      let info: unknown
      try { info = await next.request('profile.inspect') } catch (e) { next.close(); throw e }
      if (!await maySwitch()) { next.close(); throw new Error('PROFILE_BUSY') }
      try { await savePreferences(result.filePaths[0]) } catch (e) { next.close(); throw e }
      bridge?.close(); bridge = next; profile = result.filePaths[0]
      return info
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
    tray.setToolTip('LuminaVPN · 只读桌面预览')
    tray.setContextMenu(Menu.buildFromTemplate([
      { label: '打开 LuminaVPN', click: showWindow },
      { label: '显示独立恢复入口', click: () => { void showRecoveryFromTray() } },
      { type: 'separator' },
      { label: '退出界面（保留现有网络）', click: () => { quitting = true; app.quit() } }
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
      ...(process.platform === 'darwin' ? [{ label: 'LuminaVPN', submenu: [{ role: 'about' as const }, { type: 'separator' as const }, { label: '退出界面（保留现有网络）', click: () => { quitting = true; app.quit() } }] }] : []),
      { role: 'editMenu' }, { role: 'viewMenu' }, { role: 'windowMenu' }
    ]))
    app.on('activate', showWindow)
  })
  app.on('window-all-closed', () => { if (!tray) { quitting = true; app.quit() } })
  app.on('before-quit', () => { quitting = true; bridge?.close(); tray?.destroy(); tray = null })
}
