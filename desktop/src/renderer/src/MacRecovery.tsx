import { opaqueID } from '../../../protocol/client'
import type { ClientAPI, ServiceMutation, ServiceOperation, ServiceSnapshot } from '../../../protocol/client'

export type MacRecoveryRequest = ServiceMutation & { kind: 'exit_restore'; run_ref: string }

function stoppedOrActiveRun(snapshot: ServiceSnapshot | null): snapshot is ServiceSnapshot & { run_ref: string } {
  return snapshot?.service_state === 'local' && opaqueID(snapshot.profile_id) && opaqueID(snapshot.run_ref) &&
    !snapshot.challenge && !snapshot.operation_id && !snapshot.restored &&
    snapshot.takeover_state !== 'idle' && snapshot.takeover_state !== 'restored' && snapshot.takeover_state !== 'recovering'
}

export function macDiagnosticRecoveryRequest(
  displayed: ServiceSnapshot | null,
  fresh: ServiceSnapshot,
  requestID: string,
): MacRecoveryRequest | null {
  if (!stoppedOrActiveRun(displayed) || !stoppedOrActiveRun(fresh) ||
      displayed.profile_id !== fresh.profile_id || displayed.run_ref !== fresh.run_ref) return null
  return {
    kind: 'exit_restore', stop: {}, request_id: requestID, profile_id: fresh.profile_id,
    run_ref: fresh.run_ref, expected_revision: fresh.revision,
  }
}

export function matchesMacDiagnosticRecovery(operation: ServiceOperation, request: MacRecoveryRequest): boolean {
  if (operation.kind !== request.kind || operation.request_id !== request.request_id ||
      operation.profile_id !== request.profile_id || operation.run_ref !== request.run_ref) return false
  if (operation.error) return operation.completed && operation.phase === 'failed' && !operation.restored
  return operation.completed
    ? operation.phase === 'restored' && operation.restored
    : operation.phase === 'recovering' && !operation.restored
}

export async function submitMacDiagnosticRecovery(
  displayed: ServiceSnapshot | null,
  requestID: string,
  api: Pick<ClientAPI, 'snapshot' | 'submit'>,
): Promise<{ request: MacRecoveryRequest; operation: ServiceOperation }> {
  const request = macDiagnosticRecoveryRequest(displayed, await api.snapshot(), requestID)
  if (!request) throw Object.assign(new Error('REVISION_CONFLICT'), { code: 'REVISION_CONFLICT' })
  const operation = await api.submit(request)
  if (!matchesMacDiagnosticRecovery(operation, request)) {
    throw Object.assign(new Error('MAC_RECOVERY_UNCONFIRMED'), { code: 'MAC_RECOVERY_UNCONFIRMED' })
  }
  return { request, operation }
}

export function MacRecovery({ snapshot, busy, recover }: {
  snapshot: ServiceSnapshot | null
  busy: boolean
  recover: () => void
}) {
  let status = '等待读取当前运行。'
  if (snapshot?.service_state === 'local') {
    if (!snapshot.run_ref) {
      status = snapshot.takeover_state === 'idle' && !snapshot.recovery_required && !snapshot.restored &&
        !snapshot.operation_id && !snapshot.challenge
        ? '当前配置没有运行。'
        : '无法绑定待恢复的运行。请使用独立恢复入口。'
    } else if (snapshot.restored && snapshot.takeover_state === 'restored' && !snapshot.recovery_required) {
      status = '管理员已确认本次运行的恢复。'
    } else if (snapshot.takeover_state === 'recovering') {
      status = '等待管理员确认恢复。'
    } else if (snapshot.takeover_state === 'stopped_reported') {
      status = '已收到停止报告。管理员恢复仍待确认。'
    } else {
      status = '当前运行的管理员恢复尚未确认。'
    }
  }
  return <section className="client-card" aria-labelledby="mac-recovery-title">
    <h2 id="mac-recovery-title">当前运行恢复</h2>
    <p role="status">{status}</p>
    <button disabled={busy || !stoppedOrActiveRun(snapshot)} onClick={recover}>验证恢复</button>
  </section>
}
