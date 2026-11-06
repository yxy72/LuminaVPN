import { isRecord } from './validation-base'
export type DesiredChannels = { company: boolean; personal: boolean }
export type OperationKind = 'takeover_start' | 'channels_set' | 'takeover_stop' | 'exit_restore' | 'profile_apply' | 'auth_respond' | 'auth_cancel' | 'node_select' | 'settings_apply' | 'workspace' | 'attach_enrollment'
export interface SafeServiceError { code: string; message: string; retryable: boolean }
export interface ServiceOperation { operation_id: string; request_id: string; profile_id: string; run_ref?: string; revision: number; kind: OperationKind; phase: string; completed: boolean; restored: boolean; created_at: string; updated_at: string; error?: SafeServiceError; first_failure?: SafeServiceError;alias_of?:string }
export interface HealthRound { epoch: string; config_revision: string; node_set_revision: string; expected_candidate_ids: string[]; candidates: { id: string; state: 'pending'|'healthy'|'failed'|'unknown'; failure_scope: string; epoch: string; config_revision: string; node_set_revision: string }[] }
export interface ServiceChannel { desired: boolean; state: string; route: string; reason?: string; health_epoch?: string; ipv6_state?: string; health?: HealthRound }
export interface ServiceSettings { auto_connect: boolean; environment: 'office'|'home'; office_overrides: EnvironmentOverride[]; home_overrides: EnvironmentOverride[] }
export interface AuthField { field_id:string; kind:'username'|'password'|'otp'|'text'|'select'; label_code?:string; choices?:{choice_id:string;label:string}[] }
export interface AuthFieldValue {field_id:string;value:string}
export interface ServiceSnapshot { protocol_version: 1; service_state: string; takeover_state: string; profile_id: string; revision: number; run_ref?: string; desired: DesiredChannels; company: ServiceChannel; personal: ServiceChannel; operation_id?: string; challenge?: { challenge_id: string; kind: string; expires_at: string; sequence:number; fields?:AuthField[] }; recovery_required: boolean; restored: boolean; auto_connect: boolean; settings?: ServiceSettings; local_exit_proof?:{source:'LOCALONLY';service_absent:boolean;no_owned_state:boolean} }
export interface EnvironmentOverride { type: 'domain' | 'domain_suffix' | 'cidr'; value: string; target: 'personal' | 'direct' }
export type ServiceMutation = { request_id: string; profile_id: string; expected_revision: number; run_ref?: string } & (
  { kind: 'takeover_start'; start: { channels: DesiredChannels } & ({mode:'daily';validation_seconds?:never}|{mode:'validation';validation_seconds:number}) } | { kind: 'channels_set'; channels: DesiredChannels } |
  { kind: 'takeover_stop' | 'exit_restore'; stop: Record<string, never> } |
  { kind: 'auth_respond'; auth: { challenge_id: string; sequence:number; username?: string; password?: string; otp?: string; fields?:AuthFieldValue[] } } |
  { kind: 'auth_cancel'; cancel_auth: { challenge_id: string } } |
  { kind: 'node_select'; selection: { node_id: string } } |
  { kind: 'settings_apply'; settings: ServiceSettings } |
  { kind: 'profile_apply'; profile: { policy: Record<string, unknown>; nodes: Record<string, unknown>[]; name: string } })
export type WorkspaceReadBody = { action: 'document' | 'history' | 'diagnostics' | 'cleanup_preview' | 'runtime' | 'version' | 'recovery_entry' } | { action: 'validate' | 'diff'; policy_json: string } | { action: 'explain'; target: string }
export type WorkspaceRead = {profile_id:string} & WorkspaceReadBody
export type WorkspaceWrite = { request_id: string;profile_id:string } & (
  { action: 'initialize'; policy_json: string; bootstrap_json?: never } | { action: 'initialize'; bootstrap_json: string; policy_json?: never } |
  { action: 'apply'; policy_json: string; expected_revision: string } |
  { action: 'rollback'; revision: string; expected_revision: string } |
  { action: 'import_nodes'; content: string } | { action: 'sync' } | { action: 'sources_save'; sources_json: string; expected_revision: string } | { action: 'cleanup'; opaque_run_id: string })
export type WorkspaceCommand = WorkspaceWrite extends infer W ? W extends WorkspaceWrite ? Omit<W,'request_id'|'profile_id'> : never : never
export type WorkspaceOperation = ServiceOperation
export interface ClientAPI {
  snapshot(): Promise<ServiceSnapshot>; submit(mutation: ServiceMutation): Promise<ServiceOperation>; operation(id: string): Promise<ServiceOperation>
  read(request: WorkspaceRead): Promise<Record<string, unknown>>; command(request: WorkspaceWrite): Promise<WorkspaceOperation>
  pickImport(profileID:string): Promise<{ import_id: string } | null>; importNodes(requestID: string, importID: string,profileID:string): Promise<WorkspaceOperation>
  exit(): Promise<boolean>; onExitError(handler: (code: string) => void): () => void
}
export const CLIENT_METHODS = ['service.snapshot', 'service.submit', 'service.operation', 'workspace.read', 'workspace.submit'] as const
export type ClientMethod = typeof CLIENT_METHODS[number]
export const opaqueID = (x: unknown): x is string => typeof x === 'string' && /^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$/.test(x)
const text = (x: unknown, max = 65536): x is string => typeof x === 'string' && x.length <= max && new TextEncoder().encode(x).byteLength <= max
const uint = (x: unknown): x is number => Number.isSafeInteger(x) && (x as number) >= 0
const bool = (x: unknown): x is boolean => typeof x === 'boolean'
const own = (x: Record<string, unknown>, keys: string[]) => Object.keys(x).every(k => keys.includes(k))
const channels = (x: unknown): boolean => isRecord(x) && own(x, ['company', 'personal']) && bool(x.company) && bool(x.personal)
const settings = (p: unknown): boolean => isRecord(p) && own(p, ['auto_connect','environment','office_overrides','home_overrides']) && bool(p.auto_connect) && ['office','home'].includes(String(p.environment)) && [p.office_overrides,p.home_overrides].every(rows => Array.isArray(rows) && rows.length <= 128 && rows.every(row => isRecord(row) && own(row,['type','value','target']) && ['domain','domain_suffix','cidr'].includes(String(row.type)) && ['personal','direct'].includes(String(row.target)) && text(row.value,253) && !!row.value))
export function validateMutation(value: unknown): value is ServiceMutation {
  if (!isRecord(value) || !opaqueID(value.request_id) || !opaqueID(value.profile_id) || !uint(value.expected_revision) || value.run_ref !== undefined && !opaqueID(value.run_ref)) return false
  const base = ['request_id', 'profile_id', 'expected_revision', 'run_ref', 'kind']
  const payload = (name: string) => own(value, [...base, name]) && isRecord(value[name])
  switch (value.kind) {
    case 'takeover_start': return payload('start') && own(value.start as Record<string, unknown>, ['channels','mode','validation_seconds']) && channels((value.start as Record<string, unknown>).channels) && (((value.start as Record<string,unknown>).mode === 'daily'&&(value.start as Record<string,unknown>).validation_seconds===undefined)||((value.start as Record<string,unknown>).mode==='validation'&&uint((value.start as Record<string,unknown>).validation_seconds)&&Number((value.start as Record<string,unknown>).validation_seconds)>=1&&Number((value.start as Record<string,unknown>).validation_seconds)<=2700))
    case 'channels_set': return own(value, [...base, 'channels']) && channels(value.channels)
    case 'takeover_stop': case 'exit_restore': return payload('stop') && Object.keys(value.stop as object).length === 0
    case 'auth_respond': { const p = value.auth; return payload('auth') && isRecord(p) && own(p, ['challenge_id','sequence','username','password','otp','fields']) && opaqueID(p.challenge_id) && uint(p.sequence) && p.sequence>0 && (p.username === undefined || text(p.username,256)) && (p.password === undefined || text(p.password,4096)) && (p.otp === undefined || text(p.otp,1024)) && [p.username,p.password,p.otp].every(v=>v===undefined||typeof v==='string'&&!/[\x00\r\n]/.test(v)) && (p.fields===undefined || Array.isArray(p.fields) && p.fields.length<=16 && new Set(p.fields.map(f=>isRecord(f)?f.field_id:undefined)).size===p.fields.length && p.fields.every(f=>isRecord(f)&&own(f,['field_id','value'])&&opaqueID(f.field_id)&&text(f.value,4096)&&!/[\x00\r\n]/.test(f.value))) && (!Array.isArray(p.fields)||!p.fields.length||!p.username&&!p.password&&!p.otp) }
    case 'auth_cancel': return payload('cancel_auth') && own(value.cancel_auth as Record<string, unknown>, ['challenge_id']) && opaqueID((value.cancel_auth as Record<string, unknown>).challenge_id)
    case 'node_select': return payload('selection') && own(value.selection as Record<string, unknown>, ['node_id']) && opaqueID((value.selection as Record<string, unknown>).node_id)
    case 'settings_apply': return payload('settings') && settings(value.settings)
    case 'profile_apply': { const p = value.profile; return payload('profile') && isRecord(p) && own(p,['policy','nodes','name']) && isRecord(p.policy) && Array.isArray(p.nodes) && p.nodes.length <= 256 && p.nodes.every(isRecord) && text(p.name,128) }
    default: return false
  }
}
export function validateWorkspaceRead(x: unknown): x is WorkspaceRead {
  if (!isRecord(x)||!opaqueID(x.profile_id)) return false
  if (['document','history','diagnostics','cleanup_preview','runtime','version','recovery_entry'].includes(String(x.action))) return own(x,['action','profile_id'])
  if (x.action === 'validate' || x.action === 'diff') return own(x,['action','policy_json','profile_id']) && text(x.policy_json)
  return x.action === 'explain' && own(x,['action','target','profile_id']) && text(x.target,253) && !!x.target && !/[\s\x00-\x1f]/.test(x.target)
}
export function validateWorkspaceWrite(x: unknown): x is WorkspaceWrite {
  if (!isRecord(x) || !opaqueID(x.request_id)||!opaqueID(x.profile_id)) return false
  const base = ['action','request_id','profile_id']
  switch(x.action) {
    case 'initialize': return own(x,[...base,'policy_json','bootstrap_json']) && ((text(x.policy_json) && !!x.policy_json && x.bootstrap_json === undefined) || (text(x.bootstrap_json) && !!x.bootstrap_json && x.policy_json === undefined))
    case 'apply': return own(x,[...base,'policy_json','expected_revision']) && text(x.policy_json) && text(x.expected_revision,128)
    case 'rollback': return own(x,[...base,'revision','expected_revision']) && text(x.revision,128) && text(x.expected_revision,128)
    case 'import_nodes': return own(x,[...base,'content']) && text(x.content,700000)
    case 'sync': return own(x,base)
    case 'sources_save': return own(x,[...base,'sources_json','expected_revision']) && text(x.sources_json) && text(x.expected_revision,128) && !!x.expected_revision
    case 'cleanup': return own(x,[...base,'opaque_run_id']) && opaqueID(x.opaque_run_id)
    default: return false
  }
}
export function validateClientRequest(method: string, params: unknown): boolean {
  if (method==='service.snapshot') return isRecord(params) && !Object.keys(params).length
  if (method==='service.submit') return validateMutation(params)
  if (method==='service.operation') return isRecord(params) && own(params,['operation_id']) && opaqueID(params.operation_id)
  if (method==='workspace.read') return validateWorkspaceRead(params)
  if (method==='workspace.submit') return validateWorkspaceWrite(params)
  return false
}
export function validateClientResult(method: string, x: unknown): boolean {
  if (!isRecord(x)) return false
  const optionalID = (v: unknown) => v === undefined || opaqueID(v)
  const error = (v: unknown) => v === undefined || isRecord(v) && own(v,['code','message','retryable']) && typeof v.code === 'string' && /^[A-Z_]{1,64}$/.test(v.code) && text(v.message,1024) && bool(v.retryable)
  const health = (v: unknown) => v === undefined || isRecord(v) && own(v,['epoch','config_revision','node_set_revision','expected_candidate_ids','candidates']) && ['epoch','config_revision','node_set_revision'].every(k=>text(v[k],128)) && Array.isArray(v.expected_candidate_ids) && v.expected_candidate_ids.length<=256 && v.expected_candidate_ids.every(opaqueID) && Array.isArray(v.candidates) && v.candidates.length<=256 && v.candidates.every(c=>isRecord(c)&&own(c,['id','state','failure_scope','epoch','config_revision','node_set_revision'])&&opaqueID(c.id)&&['pending','healthy','failed','unknown'].includes(String(c.state))&&['failure_scope','epoch','config_revision','node_set_revision'].every(k=>text(c[k],128)))
  const channel = (v: unknown) => isRecord(v) && own(v,['desired','state','route','reason','health_epoch','ipv6_state','health']) && bool(v.desired) && text(v.state,128) && text(v.route,128) && ['reason','health_epoch','ipv6_state'].every(k=>v[k]===undefined || text(v[k],128)) && health(v.health)
  if (method==='service.snapshot') return own(x,['protocol_version','service_state','takeover_state','profile_id','revision','run_ref','desired','company','personal','operation_id','challenge','recovery_required','restored','auto_connect','settings','local_exit_proof']) && x.protocol_version===1 && text(x.service_state,128) && text(x.takeover_state,128) && opaqueID(x.profile_id) && uint(x.revision) && optionalID(x.run_ref) && optionalID(x.operation_id) && channels(x.desired) && channel(x.company) && channel(x.personal) && bool(x.auto_connect) && bool(x.restored) && bool(x.recovery_required) && (x.local_exit_proof===undefined || isRecord(x.local_exit_proof) && own(x.local_exit_proof,['source','service_absent','no_owned_state']) && x.local_exit_proof.source==='LOCALONLY' && bool(x.local_exit_proof.service_absent) && bool(x.local_exit_proof.no_owned_state)) && (x.settings===undefined || settings(x.settings)) && (x.challenge===undefined || isRecord(x.challenge) && own(x.challenge,['challenge_id','kind','expires_at','sequence','fields']) && opaqueID(x.challenge.challenge_id) && text(x.challenge.kind,64) && text(x.challenge.expires_at,64) && uint(x.challenge.sequence) && x.challenge.sequence>0 && (x.challenge.fields===undefined||Array.isArray(x.challenge.fields)&&x.challenge.fields.length<=16&&x.challenge.fields.every(field=>isRecord(field)&&own(field,['field_id','kind','label_code','choices'])&&opaqueID(field.field_id)&&['username','password','otp','text','select'].includes(String(field.kind))&&(field.label_code===undefined||opaqueID(field.label_code))&&(field.choices===undefined||Array.isArray(field.choices)&&field.choices.length<=64&&field.choices.every(choice=>isRecord(choice)&&own(choice,['choice_id','label'])&&opaqueID(choice.choice_id)&&text(choice.label,128))))))
  if (method==='service.submit' || method==='service.operation' || method==='workspace.submit') return own(x,['operation_id','request_id','profile_id','run_ref','revision','kind','phase','completed','restored','created_at','updated_at','error','first_failure','alias_of']) && opaqueID(x.operation_id) && opaqueID(x.request_id) && opaqueID(x.profile_id) && uint(x.revision) && optionalID(x.run_ref) && ['takeover_start','channels_set','takeover_stop','exit_restore','profile_apply','auth_respond','auth_cancel','node_select','settings_apply','workspace','attach_enrollment'].includes(String(x.kind)) && text(x.phase,64) && bool(x.completed) && bool(x.restored) && text(x.created_at,64) && text(x.updated_at,64) && error(x.error) && error(x.first_failure) && optionalID(x.alias_of)
  return method==='workspace.read' && opaqueID(x.profile_id)
}
