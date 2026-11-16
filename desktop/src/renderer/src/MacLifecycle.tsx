import { useState } from 'react'
import type { DesiredChannels, ServiceMutation, ServiceOperation, ServiceSnapshot } from '../../../protocol/client'

type MacStart = Extract<ServiceMutation, { kind: 'takeover_start' }>['start']

const states: Record<string, string> = {
  idle: '当前配置没有运行',
  starting: '正在启动，可查看 macOS 授权提示',
  authenticating: '请在本机 Terminal 完成公司认证',
  applying_company: '正在切换本次运行的公司 VPN',
  authentication_required_reported: '公司会话需要重新认证',
  waiting_for_stop_report: '等待停止报告',
  recovering: '等待管理员恢复',
  restored: '管理员恢复已确认',
  ready_reported: '运行报告就绪',
  managed_reported: '网络接管正在运行',
  starting_reported: '运行正在启动',
  preparing_reported: '正在准备运行',
  connecting_reported: '正在连接',
  stopping_reported: '正在停止',
  stopped_reported: '已收到停止报告',
  recovery_failed_reported: '运行报告恢复失败',
  unconfirmed: '当前运行待确认',
}

export function macOperationText(operation: ServiceOperation): string {
  const actions: Partial<Record<ServiceOperation['kind'], string>> = {
    takeover_start: '连接', channels_set: '公司 VPN', auth_begin: '公司认证', takeover_stop: '停止', exit_restore: '验证恢复', workspace: '配置',
  }
  const progress: Record<string, string> = {
    running: '进行中', authenticating: '等待本机 Terminal', authenticated: '会话已更新', starting: '正在启动，可查看 macOS 授权提示',
    applying_company: '正在应用', company_applied: '已应用到本次运行',
    waiting_for_stop_report: '等待停止报告', recovering: '等待管理员恢复',
    ready_reported: '运行报告就绪',
  managed_reported: '网络接管正在运行', stopped_reported: '已收到停止报告',
    restored: '管理员恢复已确认', completed: '已完成', failed: '未完成', cancelled: '已取消',
  }
  return `${actions[operation.kind] ?? '操作'} · ${progress[operation.phase] ?? '待确认'}`
}

export function MacLifecycle({ snapshot, configured, busy, preemptible, desired, setDesired, start, setCompany, authenticate, stop, exit }: {
  snapshot: ServiceSnapshot | null
  configured: boolean
  busy: boolean
  preemptible: boolean
  desired: DesiredChannels
  setDesired: (desired: DesiredChannels) => void
  start: (request: MacStart) => void
  setCompany: (company: boolean) => void
  authenticate: (runtime: boolean) => void
  stop: () => void
  exit: () => void
}) {
  const [mode, setMode] = useState<'daily' | 'validation'>('daily')
  const [duration, setDuration] = useState('300')
  const state = snapshot?.takeover_state ?? ''
  const seconds = Number(duration)
  const validDuration = Number.isSafeInteger(seconds) && seconds >= 1 && seconds <= 2700
  const local = snapshot?.service_state === 'local'
  const mayStart = local && (state === 'idle' || state === 'restored' || state === 'stopped_reported')
  const canConfigure = !busy && !!mayStart
  const canEditCompany = !busy && local && !!snapshot.run_ref && snapshot.mac_company_control === true
  const showRun = !!snapshot?.run_ref && !mayStart && state !== 'starting' && (state !== 'authenticating' || preemptible)
  const channels = showRun ? snapshot.desired : desired
  const mayStop = local && !!snapshot.run_ref && state !== 'restored' && state !== 'stopped_reported'
  const canAuthenticate = canEditCompany && snapshot.desired.company || canConfigure && configured && desired.company
  return <section className="client-card" aria-labelledby="mac-lifecycle-title">
    <h2 id="mac-lifecycle-title">网络接管</h2>
    <p role="status">{states[state] ?? (snapshot ? '当前运行待确认' : '正在读取网络控制状态')}</p>
    <p>接管期间，关闭公司 VPN 会阻断公司目标，关闭个人代理后个人目标走直连。启动与验证恢复可能需要 macOS 管理员授权。</p>
    <div className="client-actions">
      <label><input type="checkbox" checked={channels.company} disabled={!canConfigure && !canEditCompany}
        onChange={event => {
          if (canEditCompany) setCompany(event.target.checked)
          else setDesired({ ...desired, company: event.target.checked })
        }} />开启公司 VPN</label>
      <label><input type="checkbox" checked={channels.personal} disabled={!canConfigure}
        onChange={event => setDesired({ ...desired, personal: event.target.checked })} />开启个人代理</label>
    </div>
    {showRun && <p>公司：{snapshot.company.route === 'blocked_reported' ? '报告已阻断' : snapshot.company.desired ? '已请求 VPN' : '等待阻断报告'} ·
      个人：{snapshot.personal.route === 'direct_reported' ? '报告走直连' : snapshot.personal.desired ? '已请求代理' : '等待直连报告'}</p>}
    {showRun && <p>个人代理在下次连接时调整。</p>}
    {!configured && <p>请先在工作空间设置中保存有效策略。</p>}
    <div className="client-actions">
      <label>运行模式<select value={mode} disabled={!canConfigure} onChange={event => setMode(event.target.value === 'validation' ? 'validation' : 'daily')}>
        <option value="daily">日用连接</option>
        <option value="validation">限时验证</option>
      </select></label>
      {mode === 'validation' && <label>验证时长（秒）<input type="number" min={1} max={2700} step={1}
        value={duration} required disabled={!canConfigure} onChange={event => setDuration(event.target.value)} /></label>}
    </div>
    <div className="client-actions">
      <button disabled={!canAuthenticate} onClick={() => authenticate(canEditCompany)}>在终端进行公司认证</button>
      <button disabled={!canConfigure || !configured || mode === 'validation' && !validDuration} onClick={() => {
        start(mode === 'daily' ? { mode, channels: desired } : { mode, channels: desired, validation_seconds: seconds })
      }}>连接网络</button>
      <button disabled={!mayStop || busy && !preemptible} onClick={stop}>请求停止</button>
      <button disabled={busy && !preemptible} onClick={exit}>{snapshot?.run_ref && state !== 'restored' ? '验证恢复并退出' : '退出 LuminaVPN'}</button>
    </div>
  </section>
}
