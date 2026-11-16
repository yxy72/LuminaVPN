import { createElement } from 'react'
import { renderToStaticMarkup } from 'react-dom/server'
import { describe, expect, it, vi } from 'vitest'
import { validateMacLifecycleMutation, type ClientAPI, type ServiceMutation, type ServiceOperation, type ServiceSnapshot } from '../protocol/client'
import { ClientWorkspace } from '../src/renderer/src/ClientWorkspace'
import { MacRecovery, macDiagnosticRecoveryRequest, matchesMacDiagnosticRecovery, submitMacDiagnosticRecovery } from '../src/renderer/src/MacRecovery'

const channel = { desired: false, state: 'unknown', route: 'unknown' }
const idle: ServiceSnapshot = {
  protocol_version: 1, service_state: 'local', takeover_state: 'idle', profile_id: 'profile', revision: 1,
  desired: { company: false, personal: false }, company: channel, personal: channel,
  recovery_required: false, restored: false, auto_connect: false,
}
const running = { ...idle, takeover_state: 'managed_reported', run_ref: 'run-1', revision: 2, recovery_required: true }
const stopped = { ...running, takeover_state: 'stopped_reported', revision: 3, recovery_required: false }
const restored = { ...stopped, takeover_state: 'restored', restored: true }
const recovering = { ...stopped, takeover_state: 'recovering', operation_id: 'restore-operation' }

function view(snapshot: ServiceSnapshot | null, busy = false): string {
  return renderToStaticMarkup(createElement(MacRecovery, { snapshot, busy, recover() {} }))
}

describe('macOS Diagnostics recovery', () => {
  it('keeps the standalone control out of Windows and offline diagnostics', () => {
    const diagnostics = (macosClient: boolean, windowsClient: boolean) =>
      renderToStaticMarkup(createElement(ClientWorkspace, {
        page: 'diagnostics', macosClient, windowsClient, api: {} as ClientAPI, profileID: 'profile',
        configured: true, validationOnly: false, config: null, nodes: null, subscriptions: null,
        checking: false, environmentCheck: null, loadNodes() {}, loadRules() {}, refreshInventory() {},
        async chooseProfile() {}, async restoreDefaultProfile() {}, checkEnvironment() {}, showRecovery() {},
      }))
    expect(diagnostics(true, false)).toContain('当前运行恢复')
    expect(diagnostics(false, true)).toContain('精确运行恢复')
    expect(diagnostics(false, true)).not.toContain('当前运行恢复')
    const offline = diagnostics(false, false)
    expect(offline).toContain('显示独立恢复入口')
    expect(offline).not.toContain('当前运行恢复')
  })

  it('offers verified recovery on an exact current run, including a saved stop report', () => {
    expect(view(running)).toContain('<button>验证恢复</button>')
    expect(view(stopped)).toContain('<button>验证恢复</button>')
    expect(view(stopped)).toContain('已收到停止报告。管理员恢复仍待确认。')
    const verified = view(restored)
    expect(verified).toContain('管理员已确认本次运行的恢复。')
    expect(verified).toContain('<button disabled="">验证恢复</button>')
  })

  it('withholds the action without a bindable local run or while work is pending', () => {
    expect(view(idle)).toContain('当前配置没有运行。')
    expect(view({ ...idle, takeover_state: 'unconfirmed', recovery_required: true })).toContain('请使用独立恢复入口。')
    expect(view(recovering)).toContain('等待管理员确认恢复。')
    for (const snapshot of [idle, recovering, null, { ...running, service_state: 'available' }]) {
      expect(view(snapshot)).toContain('<button disabled="">验证恢复</button>')
    }
    expect(view(running, true)).toContain('<button disabled="">验证恢复</button>')
  })

  it('uses the fresh revision only if it belongs to the displayed profile and run', () => {
    const mutation = macDiagnosticRecoveryRequest(running, stopped, 'restore-request')
    expect(mutation).toEqual({
      kind: 'exit_restore', request_id: 'restore-request', profile_id: 'profile',
      run_ref: 'run-1', expected_revision: 3, stop: {},
    })
    expect(validateMacLifecycleMutation(mutation)).toBe(true)
    for (const fresh of [{ ...stopped, run_ref: 'run-2' }, { ...stopped, profile_id: 'other' }, restored, recovering, idle]) {
      expect(macDiagnosticRecoveryRequest(running, fresh, 'restore-request')).toBeNull()
    }
  })

  it('submits the scoped restore without requesting application exit', async () => {
    const api = {
      snapshot: vi.fn(async () => stopped),
      submit: vi.fn(async (mutation: ServiceMutation): Promise<ServiceOperation> => ({
        kind: mutation.kind, request_id: mutation.request_id, profile_id: mutation.profile_id, run_ref: mutation.run_ref,
        operation_id: 'restore-operation', revision: 4, phase: 'recovering', completed: false, restored: false,
        created_at: '2026-11-16T00:00:00Z', updated_at: '2026-11-16T00:00:00Z',
      })),
      exit: vi.fn(),
    }
    await submitMacDiagnosticRecovery(running, 'restore-request', api)
    expect(api.submit).toHaveBeenCalledOnce()
    expect(api.submit).toHaveBeenCalledWith(expect.objectContaining({ kind: 'exit_restore', run_ref: 'run-1', expected_revision: 3 }))
    expect(api.exit).not.toHaveBeenCalled()
    api.snapshot.mockResolvedValueOnce({ ...stopped, run_ref: 'run-2' })
    await expect(submitMacDiagnosticRecovery(running, 'second-request', api)).rejects.toMatchObject({ code: 'REVISION_CONFLICT' })
    expect(api.submit).toHaveBeenCalledOnce()
  })

  it('requires a matching native restore acknowledgement before reporting success', () => {
    const mutation = macDiagnosticRecoveryRequest(stopped, stopped, 'restore-request')!
    const stamp = '2026-12-01T00:00:00Z'
    const operation: ServiceOperation = {
      kind: mutation.kind, request_id: mutation.request_id, profile_id: mutation.profile_id, run_ref: mutation.run_ref,
      operation_id: 'restore-operation', revision: 4, phase: 'recovering', completed: false, restored: false,
      created_at: stamp, updated_at: stamp,
    }
    expect(matchesMacDiagnosticRecovery(operation, mutation)).toBe(true)
    const completed = { ...operation, phase: 'restored', completed: true, restored: true }
    expect(matchesMacDiagnosticRecovery(completed, mutation)).toBe(true)
    expect(matchesMacDiagnosticRecovery({
      ...operation, phase: 'failed', completed: true,
      error: { code: 'MAC_RECOVERY_UNCONFIRMED', message: 'Unconfirmed', retryable: true },
    }, mutation)).toBe(true)
    for (const mismatched of [
      { ...completed, profile_id: 'other' }, { ...completed, run_ref: 'run-2' }, { ...completed, request_id: 'other-request' },
      { ...completed, phase: 'stopped_reported', restored: false }, { ...completed, restored: false },
    ]) {
      expect(matchesMacDiagnosticRecovery(mismatched, mutation)).toBe(false)
    }
  })
})
