import { describe, it, expect } from 'vitest'
import { QuitController, confirmedUninstalledWithoutOwnedState, type ExitOperation } from '../src/main/quit-controller'
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
