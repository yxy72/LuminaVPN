import { createElement } from 'react'
import { renderToStaticMarkup } from 'react-dom/server'
import { describe, expect, it } from 'vitest'
import type { ServiceSnapshot } from '../protocol/client'
import { MacLifecycle } from '../src/renderer/src/MacLifecycle'

const channels = { company: false, personal: false }
const inactive = { desired: false, route: 'unknown', state: 'unknown' }
const idle: ServiceSnapshot = {
  protocol_version: 1, service_state: 'local', takeover_state: 'idle', profile_id: 'profile', revision: 1,
  desired: channels, company: inactive, personal: inactive, recovery_required: false, restored: false, auto_connect: false,
}
const running = { ...idle, run_ref: 'run', takeover_state: 'ready_reported', recovery_required: true }

function view(snapshot: ServiceSnapshot): string {
  return renderToStaticMarkup(createElement(MacLifecycle, {
    snapshot, configured: true, busy: false, preemptible: false, desired: channels, setDesired() {},
    environment: 'office', setEnvironment() {}, start() {}, setChannel() {}, authenticate() {}, stop() {}, exit() {},
  }))
}

describe('macOS startup environment view', () => {
  it('offers the three environment choices only before starting', () => {
    expect(view(idle)).toContain('启动环境')
    expect(view(idle)).toContain('<option value="office" selected="">办公</option>')
    expect(view(idle)).toContain('共享基础规则')
    expect(view(idle)).toContain('家庭')
    expect(view(running)).not.toContain('启动环境')
  })
  it('separates reported environment selection from application and readiness', () => {
    const pending = view({ ...running, mac_environment: { selected: 'office' } })
    expect(pending).toContain('已选择 办公')
    expect(pending).toContain('已应用 等待报告')
    expect(pending).toContain('等待本次运行的环境应用报告')
    expect(pending).not.toContain('运行报告就绪')
    const other = view({ ...running, mac_environment: { selected: 'office', applied: 'home' } })
    expect(other).toContain('已应用 家庭')
    expect(other).not.toContain('运行报告就绪')
    const applied = view({ ...running, mac_environment: { selected: 'office', applied: 'office' } })
    expect(applied).toContain('已应用 办公')
    expect(applied).toContain('运行报告就绪')
  })
})
