import { contextBridge, ipcRenderer } from 'electron'
import type { LuminaAPI } from '../../protocol/types'
import type { ClientAPI, ServiceMutation, WorkspaceRead, WorkspaceWrite } from '../../protocol/client'

async function invoke(channel: string, ...args: unknown[]): Promise<any> {
  const response: unknown = await ipcRenderer.invoke(channel, ...args)
  if (typeof response !== 'object' || response === null || !('ok' in response)) throw Object.assign(new Error('INVALID_PROTOCOL'), { code: 'INVALID_PROTOCOL' })
  const r = response as { ok: boolean; result?: unknown; error?: { code?: string } }
  if (!r.ok) { const code = r.error?.code ?? 'READ_FAILED'; throw Object.assign(new Error(code), { code }) }
  return r.result
}
const read = (method: string, params: Record<string, unknown> = {}): Promise<any> => invoke('lumina:read', method, params)
const clientAPI: ClientAPI = Object.freeze({
  snapshot: () => invoke('lumina:client', 'service.snapshot', {}),
  submit: (mutation: ServiceMutation) => invoke('lumina:client', 'service.submit', mutation),
  operation: (id: string) => invoke('lumina:client', 'service.operation', { operation_id: id }),
  read: (request: WorkspaceRead) => invoke('lumina:client', 'workspace.read', request),
  command: (request: WorkspaceWrite) => invoke('lumina:client', 'workspace.submit', request),
  pickImport: (profileID:string) => invoke('lumina:pick-import',{profile_id:profileID}),
  importNodes: (requestID: string, importID: string,profileID:string) => invoke('lumina:import-nodes', { request_id: requestID, import_id: importID,profile_id:profileID }),
  exit: () => invoke('lumina:normal-exit'),
  onExitError: (handler: (code: string) => void) => { const listener = (_event: unknown, code: unknown) => { if (typeof code === 'string' && /^EXIT_[A-Z_]+$/.test(code)) handler(code) }; ipcRenderer.on('lumina:exit-error', listener); return () => ipcRenderer.removeListener('lumina:exit-error', listener) }
})
const api: LuminaAPI = Object.freeze({
  client: clientAPI,
  hello: () => read('session.hello'), getState: () => read('state.get'),
  inspectProfile: () => read('profile.inspect'), listNodes: (params = {}) => read('nodes.list', params),
  getConfig: (params = {}) => read('config.get', params), subscriptionsSummary: () => read('subscriptions.summary'),
  checkEnvironment: () => read('environment.check'), describeRecovery: () => read('recovery.describe'),
  chooseProfile: () => invoke('lumina:choose-profile'), restoreDefaultProfile: () => invoke('lumina:restore-default-profile'), showRecovery: () => invoke('lumina:show-recovery')
})
contextBridge.exposeInMainWorld('lumina', api)
