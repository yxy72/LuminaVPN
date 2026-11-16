import { opaqueID, type ServiceOperation, type ServiceSnapshot } from '../../protocol/client'
import { isRecord } from '../../protocol/validation-base'

// This proof is issued only by the trusted local client after inspecting the
// fixed installation/ownership state. A missing pipe or generic error is not
// this proof, and cannot authorize closing a possibly active recovery owner.
export function confirmedUninstalledWithoutOwnedState(value: unknown): boolean {
  if (!isRecord(value) || !isRecord(value.local_exit_proof) || !isRecord(value.desired)) return false
  const proof=value.local_exit_proof
  return Object.keys(proof).length===3 && proof.source==='LOCALONLY' && proof.service_absent===true && proof.no_owned_state===true &&
    value.service_state==='not_installed' && value.takeover_state==='idle' && value.restored===true &&
    value.recovery_required===false && value.desired.company===false && value.desired.personal===false &&
    value.run_ref===undefined && value.operation_id===undefined && value.challenge===undefined
}
export type MacExitState = 'no_current_run' | 'restored' | 'needs_restore' | 'unconfirmed'

export function classifyMacExit(snapshot: ServiceSnapshot): MacExitState {
  if (snapshot.service_state !== 'local' || !opaqueID(snapshot.profile_id) || snapshot.challenge) return 'unconfirmed'
  if (snapshot.run_ref === undefined) {
    // This proves only that the selected profile has no current run. It is
    // never represented as a privileged system restoration receipt.
    return snapshot.takeover_state === 'idle' && !snapshot.recovery_required && !snapshot.restored && !snapshot.operation_id
      ? 'no_current_run' : 'unconfirmed'
  }
  if (!opaqueID(snapshot.run_ref)) return 'unconfirmed'
  if (snapshot.takeover_state === 'restored' && snapshot.restored && !snapshot.recovery_required) return 'restored'
  return 'needs_restore'
}

export function macExitSnapshotMatches(snapshot: ServiceSnapshot, binding: MacExitBinding): boolean {
  if (snapshot.profile_id !== binding.profile) return false
  const state = classifyMacExit(snapshot)
  return state === 'no_current_run' || state === 'restored' && snapshot.run_ref === binding.run
}

export interface MacExitBinding { profile: string; run: string; request: string }
export function checkMacExitOperation(value: ServiceOperation, binding: MacExitBinding, id?: string): ExitOperation {
  if (value.kind !== 'exit_restore' || value.request_id !== binding.request || value.profile_id !== binding.profile ||
      value.run_ref !== binding.run || !opaqueID(value.operation_id) || id !== undefined && value.operation_id !== id) {
    throw new Error('EXIT_OPERATION_MISMATCH')
  }
  // A Darwin saved stop report is useful feedback but it is not what the
  // verifier returns after checking the exact run and the administrator receipt.
  const phase = value.phase === 'restored' ? 'completed' : value.completed && value.phase === 'completed' ? 'unconfirmed' : value.phase
  return { ...value, phase, restored: value.phase === 'restored' && value.restored, error_code: value.error?.code }
}

export interface ExitOperation {
  operation_id: string; phase: string; completed: boolean; restored: boolean; error_code?: string
}
export interface ExitBackend {
  request(): Promise<{ operation_id: string }>
  inspect(operationID: string): Promise<ExitOperation>
}
export class QuitController {
  private pending: Promise<boolean> | null = null
  constructor(private backend: ExitBackend, private finish: () => void, private failed: (code: string) => void,
    private now: () => number = Date.now, private pause: (ms: number) => Promise<void> = ms => new Promise(resolve => setTimeout(resolve, ms)),
    private timeoutMS = 120000) {}
  requestExit(): Promise<boolean> {
    if (this.pending) return this.pending
    this.pending = this.run().finally(() => { this.pending = null })
    return this.pending
  }
  private async run(): Promise<boolean> {
    try {
      const deadline = this.now() + this.timeoutMS
      const accepted = await this.backend.request()
      if (!accepted.operation_id || this.now() >= deadline) throw new Error('EXIT_RESTORE_TIMEOUT')
      for (;;) {
        const operation = await this.backend.inspect(accepted.operation_id)
        if (this.now() >= deadline) throw new Error('EXIT_RESTORE_TIMEOUT')
        if (operation.operation_id !== accepted.operation_id) throw new Error('EXIT_OPERATION_MISMATCH')
        if (operation.error_code || operation.phase === 'failed' || operation.phase === 'cancelled') throw new Error('EXIT_RESTORE_FAILED')
        if (operation.completed) {
          if (operation.phase !== 'completed' || operation.restored !== true) throw new Error('EXIT_RESTORE_UNCONFIRMED')
          this.finish()
          return true
        }
        await this.pause(Math.min(250, Math.max(0, deadline - this.now())))
      }
    } catch (error) {
      const code = error instanceof Error && /^EXIT_[A-Z_]+$/.test(error.message) ? error.message : 'EXIT_RESTORE_UNAVAILABLE'
      this.failed(code)
      return false
    }
  }
}
