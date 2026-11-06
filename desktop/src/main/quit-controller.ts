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
