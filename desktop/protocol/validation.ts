import { CLIENT_METHODS, validateClientRequest, validateClientResult, type ClientMethod } from './client'
import { READ_METHODS, type ReadMethod } from './types'
export type BridgeMethod = ReadMethod | ClientMethod

export function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}
export function validateRequest(method: unknown, params: unknown): asserts method is BridgeMethod {
  if (typeof method === 'string' && CLIENT_METHODS.includes(method as ClientMethod)) { if (!validateClientRequest(method,params)) throw new Error('INVALID_PARAMS'); return }
  if (typeof method !== 'string' || !READ_METHODS.includes(method as ReadMethod) || !isRecord(params)) throw new Error('INVALID_REQUEST')
  const keys = Object.keys(params)
  if (method === 'nodes.list' || method === 'config.get') {
    if (keys.some(k => k !== 'offset' && k !== 'limit')) throw new Error('INVALID_PARAMS')
    if (params.offset !== undefined && (!Number.isSafeInteger(params.offset) || (params.offset as number) < 0 || (params.offset as number) > (method === 'nodes.list' ? 256 : 50000))) throw new Error('INVALID_PARAMS')
    if (params.limit !== undefined && (!Number.isSafeInteger(params.limit) || (params.limit as number) < 1 || (params.limit as number) > 100)) throw new Error('INVALID_PARAMS')
  } else if (method === 'session.hello') {
    if (keys.some(k => k !== 'protocol_major' && k !== 'app_version') || params.protocol_major !== 1 || typeof params.app_version !== 'string' || params.app_version.length > 64) throw new Error('INVALID_PARAMS')
  } else if (keys.length) throw new Error('INVALID_PARAMS')
}

const string = (x: unknown): boolean => typeof x === 'string' && x.length <= 8192
const nullableString = (x: unknown): boolean => x === null || string(x)
const integer = (x: unknown): boolean => Number.isSafeInteger(x) && (x as number) >= 0
const bool = (x: unknown): boolean => typeof x === 'boolean'
const array = (x: unknown, fn: (item: unknown) => boolean, max = 100): boolean => Array.isArray(x) && x.length <= max && x.every(fn)
const methodGroup = (value: unknown, client: boolean): boolean => {
  const expected = client ? [...READ_METHODS,...CLIENT_METHODS] : [...READ_METHODS]
  return Array.isArray(value) && value.length===expected.length && value.every((method,index)=>method===expected[index])
}

// Both ends validate the contract; the renderer only receives product DTOs.
export function validateResult(method: BridgeMethod, v: unknown): boolean {
  if (CLIENT_METHODS.includes(method as ClientMethod)) return validateClientResult(method,v)
  if (!isRecord(v)) return false
  switch (method) {
    case 'session.hello': return v.protocol_major === 1 && string(v.session_id) && string(v.mode) && isRecord(v.build) && ['version', 'os', 'arch', 'go_version'].every(k => string(v.build && (v.build as Record<string, unknown>)[k])) && isRecord(v.capabilities) && ((v.capabilities.read_only === true && v.capabilities.connection_start === false && v.capabilities.connection_stop === false && v.capabilities.config_write === false && v.capabilities.windows_client !== true) || (v.build.os === 'windows' && v.capabilities.windows_client === true && v.capabilities.read_only === false && v.capabilities.connection_start === true && v.capabilities.connection_stop === true && v.capabilities.config_write === true)) && bool(v.capabilities.native_lifecycle) && methodGroup(v.capabilities.methods,v.capabilities.windows_client===true)
    case 'state.get': return bool(v.profile_configured) && nullableString(v.run_ref) && bool(v.snapshot_stale) && (v.snapshot_age_seconds === null || integer(v.snapshot_age_seconds)) && v.runtime_liveness === 'not_checked' && bool(v.recovery_required) && bool(v.stop_requested) && string(v.observed_at) && isRecord(v.status) && string(v.status.phase) && string(v.status.lifecycle) && nullableString(v.status.updated) && nullableString(v.status.last_ready) && nullableString(v.status.personal) && isRecord(v.status.channels) && ['company', 'personal', 'direct'].every(k => { const c = (v.status as Record<string, unknown>).channels as Record<string, unknown>; const h = c[k]; return isRecord(h) && string(h.state) && string(h.reason) && nullableString(h.checked_at) && string(h.path_state) && string(h.service_state) })
    case 'profile.inspect': return (v.profile_id===undefined||typeof v.profile_id==='string'&&/^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$/.test(v.profile_id)) && ['configured', 'policy_valid', 'nodes_available', 'transaction_pending', 'read_only'].every(k => bool(v[k])) && string(v.profile_name) && integer(v.node_count) && nullableString(v.revision) && array(v.issues, string)
    case 'nodes.list': return ['total', 'offset', 'limit'].every(k => integer(v[k])) && string(v.inventory) && string(v.selection_scope) && v.latency === 'not_provided' && array(v.items, n => isRecord(n) && string(n.id) && string(n.name) && string(n.type) && bool(n.selected))
    case 'config.get': return nullableString(v.revision) && ['total', 'offset', 'limit'].every(k => integer(v[k])) && v.static_only === true && v.read_only === true && array(v.rules, r => isRecord(r) && ['type', 'value', 'target', 'source'].every(k => string(r[k])) && integer(r.index))
    case 'subscriptions.summary': return bool(v.configured) && bool(v.cache_available) && nullableString(v.updated_at) && v.next_start_only === true && array(v.sources, s => isRecord(s) && string(s.id) && string(s.kind) && string(s.state))
    case 'environment.check': return string(v.checked_at) && v.read_only === true && array(v.checks, c => isRecord(c) && ['id', 'label', 'state', 'message'].every(k => string(c[k])))
    case 'recovery.describe': return ['required', 'stop_requested', 'available', 'read_only'].every(k => bool(v[k])) && nullableString(v.run_ref) && array(v.instructions, string)
  }
  return false
}
