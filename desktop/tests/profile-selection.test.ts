import { describe, expect, it, vi } from 'vitest'
import { commitProfileSelection, type ProfileBridge, type ProfileSelection } from '../src/main/profile-selection'
import type { BridgeMethod } from '../protocol/validation'
import type { ServiceSnapshot } from '../protocol/client'

const unavailable = (code: string): Error => Object.assign(new Error(code), { code })
const idle = (id: string): ServiceSnapshot => ({ protocol_version: 1, service_state: 'available', takeover_state: 'idle', profile_id: id,
  revision: 1, desired: { company: false, personal: false }, company: { desired: false, state: 'off', route: 'none' },
  personal: { desired: false, state: 'off', route: 'direct' }, recovery_required: false, restored: true, auto_connect: false })
function context(id: string, snapshot: ServiceSnapshot | Error = idle(id)) {
  const requests: BridgeMethod[] = []
  const target: ProfileBridge = {
    close: vi.fn(),
    request: vi.fn(async method => {
      requests.push(method)
      if (method === 'session.hello') return { capabilities: { windows_client: true } }
      if (method === 'profile.inspect') return { profile_id: id, configured: true }
      if (method === 'state.get') return { recovery_required: false, run_ref: null, status: { phase: 'not_started' } }
      if (method === 'service.snapshot') { if (snapshot instanceof Error) throw snapshot; return snapshot }
      if (method === 'service.operation') return { operation_id: 'pending', profile_id: id, completed: false }
      throw unavailable('UNEXPECTED_METHOD')
    })
  }
  return { target, requests }
}
function transaction(current: ProfileBridge, next: ProfileBridge, extra: Partial<ProfileSelection> = {}) {
  let selected = current, path: string | undefined = 'old-directory'
  const persist = vi.fn(async (_path: string | undefined) => {})
  const publish = vi.fn((value: ProfileBridge, selectedPath: string | undefined) => { selected = value; path = selectedPath; current.close() })
  const options: ProfileSelection = { current, next, nextPath: 'next-directory', clientMode: true, mode: 'select', version: 'fixture',
    currentUnchanged: () => selected === current, persist, publish, ...extra }
  return { options, persist, publish, selected: () => selected, path: () => path }
}

describe('profile selection owns one validated bridge context', () => {
  it('does not persist or swap a readable CLI directory rejected by the service', async () => {
    const old = context('old'), next = context('next', unavailable('PROFILE_NOT_ENROLLED'))
    const tx = transaction(old.target, next.target)
    await expect(commitProfileSelection(tx.options)).rejects.toMatchObject({ code: 'PROFILE_NOT_ENROLLED' })
    expect(next.requests).toContain('profile.inspect')
    expect(tx.persist).not.toHaveBeenCalled(); expect(tx.publish).not.toHaveBeenCalled()
    expect(tx.selected()).toBe(old.target); expect(tx.path()).toBe('old-directory')
    expect(old.target.close).not.toHaveBeenCalled(); expect(next.target.close).toHaveBeenCalledOnce()
  })
  it('publishes an enrolled idle candidate only after its own state and the old state are checked', async () => {
    const old = context('old'), next = context('next'), tx = transaction(old.target, next.target)
    expect(await commitProfileSelection(tx.options)).toMatchObject({ profile_id: 'next' })
    expect(next.requests).toContain('service.snapshot'); expect(old.requests.filter(method => method === 'service.snapshot')).toHaveLength(2)
    expect(tx.persist).toHaveBeenCalledExactlyOnceWith('next-directory'); expect(tx.selected()).toBe(next.target)
    expect(next.target.close).not.toHaveBeenCalled(); expect(old.target.close).toHaveBeenCalledOnce()
  })
  it('does not reuse default recovery exceptions for normal directory selection', async () => {
    const old = context('old')
    for (const changed of [
      { takeover_state: 'ready', run_ref: 'owned-run', desired: { company: false, personal: true }, restored: false, recovery_required: true },
      { service_state: 'not_installed', local_exit_proof: { source: 'LOCALONLY' as const, service_absent: true, no_owned_state: true } },
    ]) {
      const next = context('next', { ...idle('next'), ...changed }), tx = transaction(old.target, next.target)
      await expect(commitProfileSelection(tx.options)).rejects.toHaveProperty('code')
      expect(tx.persist).not.toHaveBeenCalled(); expect(tx.selected()).toBe(old.target); expect(next.target.close).toHaveBeenCalledOnce()
    }
  })
  it('explicitly restores the fixed default bridge even while its enrolled run is active, without replaying mutations', async () => {
    const old = context('preview-cli', unavailable('PROFILE_NOT_ENROLLED'))
    const next = context('default', { ...idle('default'), takeover_state: 'ready', run_ref: 'owned-run', desired: { company: false, personal: true }, restored: false, recovery_required: true })
    const tx = transaction(old.target, next.target, { mode: 'recover-default', nextPath: undefined })
    expect(await commitProfileSelection(tx.options)).toMatchObject({ profile_id: 'default' })
    expect(tx.persist).toHaveBeenCalledExactlyOnceWith(undefined); expect(tx.path()).toBeUndefined()
    expect(tx.selected()).toBe(next.target)
    expect([...old.requests, ...next.requests].every(method => ['session.hello', 'profile.inspect', 'service.snapshot'].includes(method))).toBe(true)
  })
  it('can recover the fixed default before installation only with the same strict local empty-state proof used for quit', async () => {
    const old = context('preview-cli', unavailable('PROFILE_NOT_ENROLLED'))
    const absent: ServiceSnapshot = { ...idle('default'), service_state: 'not_installed', local_exit_proof: { source: 'LOCALONLY', service_absent: true, no_owned_state: true } }
    const next = context('default', absent), tx = transaction(old.target, next.target, { mode: 'recover-default', nextPath: undefined })
    expect(await commitProfileSelection(tx.options)).toMatchObject({ profile_id: 'default' })
    expect(tx.persist).toHaveBeenCalledExactlyOnceWith(undefined)
    for (const changed of [{ local_exit_proof: undefined }, { service_state: 'unavailable' }, { takeover_state: 'unknown' }, { run_ref: 'unconfirmed' }, { protocol_version: 2 }]) {
      const unsafe = context('default', { ...absent, ...changed } as ServiceSnapshot)
      const rejected = transaction(old.target, unsafe.target, { mode: 'recover-default', nextPath: undefined })
      await expect(commitProfileSelection(rejected.options)).rejects.toHaveProperty('code')
      expect(rejected.persist).not.toHaveBeenCalled(); expect(unsafe.target.close).toHaveBeenCalledOnce()
    }
  })
  it.each(['SERVICE_UNAVAILABLE', 'ACCESS_DENIED', 'READ_TIMEOUT', 'PROFILE_UNAVAILABLE'])('does not turn %s on the current directory into default recovery authorization', async code => {
    const old = context('old', unavailable(code)), next = context('default')
    const tx = transaction(old.target, next.target, { mode: 'recover-default', nextPath: undefined })
    await expect(commitProfileSelection(tx.options)).rejects.toMatchObject({ code })
    expect(next.requests).toEqual([]); expect(tx.persist).not.toHaveBeenCalled(); expect(next.target.close).toHaveBeenCalledOnce()
  })
  it.each([
    { service_state: 'attaching', takeover_state: 'restoring', operation_id: 'pending' },
    { service_state: 'unavailable', takeover_state: 'unknown' },
    { takeover_state: 'unknown', run_ref: 'owned-run', restored: false },
    { takeover_state: 'starting', run_ref: 'owned-run', restored: false },
    { profile_id: 'foreign' },
    { takeover_state: 'ready', run_ref: 'owned-run', operation_id: 'pending', restored: false },
  ])('rejects pending, unknown or foreign default state before persisting', async changed => {
    const old = context('old', unavailable('PROFILE_NOT_ENROLLED')), next = context('default', { ...idle('default'), ...changed })
    const tx = transaction(old.target, next.target, { mode: 'recover-default', nextPath: undefined })
    await expect(commitProfileSelection(tx.options)).rejects.toHaveProperty('code')
    expect(tx.persist).not.toHaveBeenCalled(); expect(tx.selected()).toBe(old.target); expect(next.target.close).toHaveBeenCalledOnce()
  })
  it('cannot use an arbitrary selected path as the default recovery target', async () => {
    const old = context('old', unavailable('PROFILE_NOT_ENROLLED')), next = context('next')
    const tx = transaction(old.target, next.target, { mode: 'recover-default' })
    await expect(commitProfileSelection(tx.options)).rejects.toMatchObject({ code: 'INVALID_PARAMS' })
    expect(tx.persist).not.toHaveBeenCalled(); expect(next.requests).toEqual([])
  })
  it('rejects a delayed candidate response after its old main context has changed', async () => {
    const old = context('old'), next = context('next')
    let finish!: (value: unknown) => void, unchanged = true
    const request = next.target.request.bind(next.target)
    next.target.request = (method, params) => method === 'profile.inspect' ? new Promise(resolve => { finish = resolve }) : request(method, params)
    const tx = transaction(old.target, next.target, { currentUnchanged: () => unchanged })
    const result = commitProfileSelection(tx.options)
    await vi.waitFor(() => expect(finish).toBeTypeOf('function'))
    unchanged = false; finish({ profile_id: 'next' })
    await expect(result).rejects.toMatchObject({ code: 'PROFILE_CHANGED' })
    expect(tx.persist).not.toHaveBeenCalled(); expect(tx.publish).not.toHaveBeenCalled(); expect(next.target.close).toHaveBeenCalledOnce()
  })
  it('preserves the offline directory picker without requiring a Windows service', async () => {
    const old = context('old'), next = context('arbitrary-cli'), tx = transaction(old.target, next.target, { clientMode: false })
    expect(await commitProfileSelection(tx.options)).toMatchObject({ profile_id: 'arbitrary-cli' })
    expect([...old.requests, ...next.requests]).not.toContain('service.snapshot')
  })
  it('keeps the old bridge if atomic preferences persistence fails', async () => {
    const old = context('old'), next = context('next'), tx = transaction(old.target, next.target, { persist: async () => { throw unavailable('WRITE_FAILED') } })
    await expect(commitProfileSelection(tx.options)).rejects.toMatchObject({ code: 'WRITE_FAILED' })
    expect(tx.selected()).toBe(old.target); expect(old.target.close).not.toHaveBeenCalled(); expect(next.target.close).toHaveBeenCalledOnce()
  })
})
