export type ChannelName = 'company' | 'personal' | 'direct'
export interface Channel {
  state: string; reason: string; checked_at: string | null; next_action?: string
  path_state: string; service_state: string; probe_scope?: string
}
export interface Hello {
  protocol_major: 1; session_id: string
  build: { version: string; os: string; arch: string; go_version: string; revision?: string }
  mode: string
  capabilities: { read_only: boolean; connection_start: boolean; connection_stop: boolean; config_write: boolean; native_lifecycle: boolean; methods: string[] }
}
export interface State {
  profile_configured: boolean; run_ref: string | null
  status: { phase: string; lifecycle: string; updated: string | null; last_ready: string | null; personal: string | null; channels: Record<ChannelName, Channel> }
  snapshot_stale: boolean; snapshot_age_seconds: number | null; runtime_liveness: 'not_checked'
  recovery_required: boolean; stop_requested: boolean; observed_at: string
}
export interface Profile {
  configured: boolean; profile_name: string; policy_valid: boolean; nodes_available: boolean
  node_count: number; revision: string | null; transaction_pending: boolean; issues: string[]; read_only: boolean
}
export interface Nodes {
  items: { id: string; name: string; type: string; selected: boolean }[]; total: number; offset: number; limit: number
  inventory: string; selection_scope: string; latency: 'not_provided'
}
export interface Config {
  revision: string | null; rules: { type: string; value: string; target: string; source: string; index: number; guard?: boolean }[]
  total: number; offset: number; limit: number; static_only: boolean; read_only: boolean
}
export interface Subscriptions {
  configured: boolean; sources: { id: string; kind: string; state: string; updated_at?: string | null }[]
  cache_available: boolean; updated_at: string | null; next_start_only: boolean
}
export interface Environment {
  checks: { id: string; label: string; state: string; message: string }[]; checked_at: string
  read_only: boolean; ready_for_start?: boolean
}
export interface Recovery {
  required: boolean; run_ref: string | null; stop_requested: boolean
  available: boolean; instructions: string[]; read_only: boolean
}
export interface LuminaAPI {
  hello(): Promise<Hello>; getState(): Promise<State>; inspectProfile(): Promise<Profile>
  listNodes(params?: { offset?: number; limit?: number }): Promise<Nodes>; getConfig(params?: { offset?: number; limit?: number }): Promise<Config>
  subscriptionsSummary(): Promise<Subscriptions>; checkEnvironment(): Promise<Environment>
  describeRecovery(): Promise<Recovery>; chooseProfile(): Promise<Profile | null>; showRecovery(): Promise<boolean>
}
export const READ_METHODS = ['session.hello', 'state.get', 'profile.inspect', 'nodes.list', 'config.get', 'subscriptions.summary', 'environment.check', 'recovery.describe'] as const
export type ReadMethod = typeof READ_METHODS[number]
