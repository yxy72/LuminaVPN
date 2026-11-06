import type { BridgeMethod } from '../../protocol/validation'
import { opaqueID, type ServiceOperation, type ServiceSnapshot } from '../../protocol/client'
import type { Hello, Profile, State } from '../../protocol/types'
import { confirmedUninstalledWithoutOwnedState } from './quit-controller'

export interface ProfileBridge {
  request(method: BridgeMethod, params?: Record<string, unknown>): Promise<unknown>
  close(): void
}
type SelectionMode = 'select' | 'recover-default'
const fail = (code: string): never => { throw Object.assign(new Error(code), { code }) }
const errorCode = (error: unknown): unknown => typeof error === 'object' && error !== null && 'code' in error ? error.code : undefined

export async function windowsClientProfile(bridge: ProfileBridge, version: string): Promise<boolean> {
  const hello = await bridge.request('session.hello', { protocol_major: 1, app_version: version }) as Hello
  return hello.capabilities.windows_client === true
}

async function completedOperation(bridge: ProfileBridge, snapshot: ServiceSnapshot): Promise<void> {
  if (!snapshot.operation_id) return
  const operation = await bridge.request('service.operation', { operation_id: snapshot.operation_id }) as ServiceOperation
  if (operation.operation_id !== snapshot.operation_id || operation.profile_id !== snapshot.profile_id) fail('PROFILE_MISMATCH')
  if (!operation.completed) fail('PROFILE_BUSY')
}

function strictIdle(snapshot: ServiceSnapshot): boolean {
  return snapshot.service_state === 'available' && ['idle', 'stopped'].includes(snapshot.takeover_state) &&
    snapshot.restored === true && snapshot.recovery_required === false &&
    snapshot.desired.company === false && snapshot.desired.personal === false && !snapshot.challenge
}

async function enrolledSnapshot(bridge: ProfileBridge, info: Profile, mode: SelectionMode): Promise<void> {
  const snapshot = await bridge.request('service.snapshot', {}) as ServiceSnapshot
  if (snapshot.protocol_version !== 1 || !opaqueID(info.profile_id) || snapshot.profile_id !== info.profile_id) fail('PROFILE_MISMATCH')
  if (mode === 'recover-default' && confirmedUninstalledWithoutOwnedState(snapshot)) return
  // An unavailable service or a local not-installed proof is not enrollment.
  if (snapshot.service_state !== 'available') fail('PROFILE_NOT_ENROLLED')
  await completedOperation(bridge, snapshot)
  if (strictIdle(snapshot)) return
  // Recovery only attaches the UI to an already enrolled default run. It never
  // replays channels/settings, claims restoration, or adopts an unknown owner.
  if (mode === 'recover-default' && opaqueID(snapshot.run_ref) &&
      ['ready', 'managed', 'degraded', 'authentication_required', 'network_unavailable'].includes(snapshot.takeover_state)) return
  fail('PROFILE_BUSY')
}

async function assertLocalStopped(bridge: ProfileBridge): Promise<void> {
  const state = await bridge.request('state.get') as State
  if (state.recovery_required || !(state.status.phase === 'stopped' || !state.run_ref && state.status.phase === 'not_started')) fail('PROFILE_BUSY')
}

export async function assertProfileMayLeave(bridge: ProfileBridge, clientMode: boolean): Promise<void> {
  if (clientMode) {
    const info = await bridge.request('profile.inspect') as Profile
    await enrolledSnapshot(bridge, info, 'select')
  }
  await assertLocalStopped(bridge)
}

async function assertExplicitlyUnenrolled(bridge: ProfileBridge): Promise<void> {
  try { await bridge.request('service.snapshot', {}) }
  catch (error) { if (errorCode(error) === 'PROFILE_NOT_ENROLLED') return; throw error }
  fail('PROFILE_RECOVERY_NOT_REQUIRED')
}

export interface ProfileSelection {
  current: ProfileBridge
  next: ProfileBridge
  nextPath?: string
  clientMode: boolean
  mode: SelectionMode
  version: string
  currentUnchanged(): boolean
  persist(path: string | undefined): Promise<void>
  publish(next: ProfileBridge, path: string | undefined): void
}

export async function commitProfileSelection(selection: ProfileSelection): Promise<Profile> {
  const { current, next, clientMode, mode } = selection
  const unchanged = (): void => { if (!selection.currentUnchanged()) fail('PROFILE_CHANGED') }
  let published = false
  try {
    unchanged()
    if (mode === 'recover-default') {
      if (!clientMode || selection.nextPath !== undefined) fail('INVALID_PARAMS')
      await assertExplicitlyUnenrolled(current)
    } else await assertProfileMayLeave(current, clientMode)
    unchanged()
    const info = await next.request('profile.inspect') as Profile
    unchanged()
    if (clientMode) {
      if (!await windowsClientProfile(next, selection.version)) fail('CLIENT_UNAVAILABLE')
      unchanged()
      await enrolledSnapshot(next, info, mode)
      unchanged()
      if (mode === 'select') await assertLocalStopped(next)
      unchanged()
    }
    if (mode === 'recover-default') await assertExplicitlyUnenrolled(current)
    else await assertProfileMayLeave(current, clientMode)
    unchanged()
    await selection.persist(selection.nextPath)
    unchanged()
    selection.publish(next, selection.nextPath)
    published = true
    return info
  } finally { if (!published) next.close() }
}
