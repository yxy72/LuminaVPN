import { describe, it, expect } from 'vitest'
import { checkMacExitOperation, classifyMacExit, macExitSnapshotMatches, QuitController, confirmedUninstalledWithoutOwnedState, type ExitOperation } from '../src/main/quit-controller'
import type { ServiceOperation, ServiceSnapshot } from '../protocol/client'

describe('macOS quit accepts a bound native receipt', () => {
  const binding = { profile: 'profile', run: 'run-one', request: 'request' }
  const idle: ServiceSnapshot = {
    protocol_version: 1, service_state: 'local', takeover_state: 'idle', profile_id: binding.profile, revision: 1,
    desired: { company: true, personal: true }, company: { desired: true, state: 'unknown', route: 'unknown' },
    personal: { desired: true, state: 'unknown', route: 'unknown' }, recovery_required: false, restored: false, auto_connect: false,
  }
  const receipt: ServiceOperation = {
    operation_id: 'operation', request_id: binding.request, profile_id: binding.profile, run_ref: binding.run,
    revision: 2, kind: 'exit_restore', phase: 'restored', completed: true, restored: true,
    created_at: '2026-11-16T09:00:00Z', updated_at: '2026-11-16T09:00:01Z',
  }

  it('distinguishes a missing selected run from a saved or verified stop', () => {
    expect(classifyMacExit(idle)).toBe('no_current_run')
    expect(classifyMacExit({ ...idle, takeover_state: 'unconfirmed' })).toBe('unconfirmed')
    expect(classifyMacExit({ ...idle, operation_id: 'start-in-progress' })).toBe('unconfirmed')
    expect(classifyMacExit({ ...idle, takeover_state: 'stopped_reported', run_ref: binding.run })).toBe('needs_restore')
    expect(classifyMacExit({ ...idle, takeover_state: 'restored', run_ref: binding.run, restored: true })).toBe('restored')
    expect(macExitSnapshotMatches({ ...idle, takeover_state: 'restored', run_ref: 'run-two', restored: true }, binding)).toBe(false)
    expect(macExitSnapshotMatches({ ...idle, run_ref: 'run-two' }, binding)).toBe(false)
    expect(macExitSnapshotMatches({ ...idle, profile_id: 'different-profile' }, binding)).toBe(false)
    expect(macExitSnapshotMatches(idle, binding)).toBe(true)
  })
  it('normalizes only an exact verified restore and rejects a later or foreign result', async () => {
    expect(checkMacExitOperation(receipt, binding, receipt.operation_id)).toMatchObject({ phase: 'completed', restored: true })
    expect(checkMacExitOperation({ ...receipt, phase: 'stopped_reported' }, binding)).toMatchObject({ restored: false })
    expect(checkMacExitOperation({ ...receipt, phase: 'completed' }, binding)).toMatchObject({ restored: false })
    for (const changed of [{ run_ref: 'other-run' }, { request_id: 'other-request' }, { profile_id: 'other-profile' }, { operation_id: 'other-op' }]) {
      expect(() => checkMacExitOperation({ ...receipt, ...changed }, binding, receipt.operation_id)).toThrow('EXIT_OPERATION_MISMATCH')
    }
    let finished = false
    const gate = new QuitController({
      request: async () => receipt,
      inspect: async () => checkMacExitOperation({ ...receipt, phase: 'stopped_reported' }, binding),
    }, () => { finished = true }, () => {})
    expect(await gate.requestExit()).toBe(false)
    expect(finished).toBe(false)
  })
})

describe('normal menu exit', () => {
  const absent={service_state:'not_installed',takeover_state:'idle',restored:true,recovery_required:false,desired:{company:false,personal:false},local_exit_proof:{source:'LOCALONLY',service_absent:true,no_owned_state:true}}
  it('allows only confirmed not-installed with no owned state to close without a service operation',()=>{
    expect(confirmedUninstalledWithoutOwnedState(absent)).toBe(true)
    for(const changed of [{service_state:'unavailable'},{service_state:'running'},{takeover_state:'unknown'},{takeover_state:'active'},{run_ref:'owned'},{operation_id:'pending'},{challenge:{}},{recovery_required:true},{restored:false},{desired:{company:true,personal:false}},{local_exit_proof:{source:'remote',service_absent:true,no_owned_state:true}},{local_exit_proof:{source:'LOCALONLY',service_absent:true,no_owned_state:false}},{local_exit_proof:undefined}])expect(confirmedUninstalledWithoutOwnedState({...absent,...changed})).toBe(false)
    expect(confirmedUninstalledWithoutOwnedState({code:'SERVICE_UNAVAILABLE'})).toBe(false)
  })
  const complete: ExitOperation = { operation_id: 'one', phase: 'completed', completed: true, restored: true }
  it('quits only after the exact completed and restored acknowledgement', async () => {
    let finished = 0, requested = 0, tick = 0
    const gate = new QuitController({ request: async () => { requested++; return { operation_id: 'one' } }, inspect: async () => (++tick === 1 ? { ...complete, completed: false, phase: 'running' } : complete) }, () => finished++, () => { throw new Error('unexpected') }, () => tick, async () => {})
    const a = gate.requestExit(), b = gate.requestExit()
    expect(await a).toBe(true); expect(await b).toBe(true); expect(finished).toBe(1); expect(requested).toBe(1)
  })
  it.each([{ ...complete, restored: false }, { ...complete, operation_id: 'other' }, { ...complete, phase: 'failed' }, { ...complete, error_code: 'RECOVERY_FAILED' }])('keeps the UI for failed or mismatched evidence', async value => {
    let finished = false, failed = ''
    const gate = new QuitController({ request: async () => ({ operation_id: 'one' }), inspect: async () => value }, () => { finished = true }, code => { failed = code })
    expect(await gate.requestExit()).toBe(false); expect(finished).toBe(false); expect(failed).toMatch(/^EXIT_/)
  })
  it('a late successful reply cannot authorize quit', async () => {
    let now = 0, finished = false
    const gate = new QuitController({ request: async () => ({ operation_id: 'one' }), inspect: async () => { now = 100; return complete } }, () => { finished = true }, () => {}, () => now, async () => {}, 100)
    expect(await gate.requestExit()).toBe(false); expect(finished).toBe(false)
  })
})
