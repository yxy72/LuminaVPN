import { contextBridge, ipcRenderer } from 'electron'
import type { LuminaAPI } from '../../protocol/types'

async function invoke(channel: string, ...args: unknown[]): Promise<any> {
  const response: unknown = await ipcRenderer.invoke(channel, ...args)
  if (typeof response !== 'object' || response === null || !('ok' in response)) throw Object.assign(new Error('INVALID_PROTOCOL'), { code: 'INVALID_PROTOCOL' })
  const r = response as { ok: boolean; result?: unknown; error?: { code?: string } }
  if (!r.ok) { const code = r.error?.code ?? 'READ_FAILED'; throw Object.assign(new Error(code), { code }) }
  return r.result
}
const read = (method: string, params: Record<string, unknown> = {}): Promise<any> => invoke('lumina:read', method, params)
const api: LuminaAPI = Object.freeze({
  hello: () => read('session.hello'), getState: () => read('state.get'),
  inspectProfile: () => read('profile.inspect'), listNodes: (params = {}) => read('nodes.list', params),
  getConfig: (params = {}) => read('config.get', params), subscriptionsSummary: () => read('subscriptions.summary'),
  checkEnvironment: () => read('environment.check'), describeRecovery: () => read('recovery.describe'),
  chooseProfile: () => invoke('lumina:choose-profile'), showRecovery: () => invoke('lumina:show-recovery')
})
contextBridge.exposeInMainWorld('lumina', api)
