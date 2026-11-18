import { createElement } from 'react'
import { renderToStaticMarkup } from 'react-dom/server'
import { describe, expect, it } from 'vitest'
import type { ServiceSnapshot } from '../protocol/client'
import { ConnectionChannels } from '../src/renderer/src/ChannelProbeStatus'
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
    expect(pending).not.toContain('>已连接<')
    const other = view({ ...running, mac_environment: { selected: 'office', applied: 'home' } })
    expect(other).toContain('已应用 家庭')
    expect(other).not.toContain('>已连接<')
    const applied = view({ ...running, mac_environment: { selected: 'office', applied: 'office' } })
    expect(applied).toContain('办公 · 已应用')
    expect(applied).toContain('>已连接<')
  })
})

describe('macOS saved route evidence', () => {
  it('labels all three routes and keeps path validation separate from service response', () => {
    const checked_at = '2026-11-16T12:00:00Z'
    const snapshot: ServiceSnapshot = {
      ...running,
      direct: {
        desired: true, route: 'direct_reported', state: 'ready_reported',
        probe: { scope: 'system_tun', path_state: 'verified', service_state: 'not_checked', checked_at },
      },
      company: {
        desired: true, route: 'vpn_reported', state: 'unavailable_reported',
        probe: { scope: 'system_tun', path_state: 'verified', service_state: 'failed', checked_at },
      },
      personal: { desired: true, route: 'direct_reported', state: 'degraded_reported', reason: 'all_candidates_failed' },
    }
    const overview = view(snapshot)
    expect(overview).toContain('aria-label="三路出口"')
    expect(overview).toContain('data-tone="ready">路径已验证<')
    expect(overview).toContain('data-tone="warning">服务响应异常<')
    expect(overview).toContain('data-tone="warning">代理不可用<')
    expect(overview).not.toContain('>健康<')
    expect(overview).not.toContain(checked_at)
    const html = renderToStaticMarkup(createElement(ConnectionChannels, { snapshot, details: true }))
    expect(html).toContain('<strong>直连</strong><span>物理网卡</span>')
    expect(html).toContain('路径已验证 · 服务响应异常')
    expect(html).toContain(checked_at)
    expect(html).toContain('候选全部失败，临时直连')
    expect(renderToStaticMarkup(createElement(ConnectionChannels, { details: true, snapshot: {
      ...running,
      personal: { desired: false, route: 'direct_reported', state: 'ready_reported', reason: 'disabled_direct' },
    } }))).toContain('个人通道已关闭，走直连')
  })
})
