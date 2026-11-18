import { useState } from 'react'
import { Building2, EthernetPort, Globe, ShieldCheck, Terminal } from 'lucide-react'
import { isMacStartEnvironment } from '../../../protocol/client'
import type { DesiredChannels, MacStartEnvironment, ServiceMutation, ServiceOperation, ServiceSnapshot } from '../../../protocol/client'
import { connectionRouteLabel } from './ChannelProbeStatus'

type MacStart = Extract<ServiceMutation, { kind: 'takeover_start' }>['start']

const environmentLabels: Record<MacStartEnvironment, string> = {
  shared: '共享基础规则', office: '办公', home: '家庭',
}

const states: Record<string, string> = {
  idle: '当前配置没有运行',
  starting: '正在启动，可查看 macOS 授权提示',
  authenticating: '请在本机 Terminal 完成公司认证',
  applying_company: '正在切换本次运行的公司 VPN',
  applying_personal: '正在切换本次运行的个人代理',
  authentication_required_reported: '公司会话需要重新认证',
  waiting_for_stop_report: '等待停止报告',
  recovering: '等待管理员恢复',
  restored: '管理员恢复已确认',
  ready_reported: '已连接',
  managed_reported: '网络接管正在运行',
  starting_reported: '运行正在启动',
  preparing_reported: '正在准备运行',
  connecting_reported: '正在连接',
  reconnecting_reported: '正在重新连接',
  degraded_reported: '部分通道异常',
  company_unavailable_reported: '公司 VPN 不可用',
  personal_unavailable_reported: '个人代理不可用',
  network_unavailable_reported: '网络不可用',
  stopping_reported: '正在停止',
  stopped_reported: '已收到停止报告',
  recovery_failed_reported: '运行报告恢复失败',
  unconfirmed: '当前运行待确认',
}

const channelCards = [
  { name: 'direct', label: '直连', Icon: EthernetPort },
  { name: 'company', label: '公司 VPN', Icon: Building2 },
  { name: 'personal', label: '个人代理', Icon: Globe },
] as const

function channelBadge(snapshot: ServiceSnapshot | null, name: typeof channelCards[number]['name']) {
  const phase = snapshot?.takeover_state
  const channel = snapshot?.[name]
  if ((name === 'company' && phase === 'applying_company') || (name === 'personal' && phase === 'applying_personal')) {
    return { label: '切换中', tone: 'neutral' }
  }
  if (name === 'company' && phase === 'authentication_required_reported') return { label: '待认证', tone: 'warning' }
  if (channel?.reason === 'all_candidates_failed') return { label: '代理不可用', tone: 'warning' }
  if (channel?.reason === 'disabled_direct' || (channel?.route === 'blocked_reported' && !channel.desired)) {
    return { label: '已关闭', tone: 'neutral' }
  }
  const probe = channel?.probe
  if (probe?.scope === 'system_tun') {
    if (probe.path_state === 'failed') return { label: '路径异常', tone: 'warning' }
    if (probe.service_state === 'failed') return { label: '服务响应异常', tone: 'warning' }
    if (probe.path_state === 'verified') {
      return { label: probe.service_state === 'healthy' ? '健康' : '路径已验证', tone: 'ready' }
    }
  }
  if (channel?.state === 'unavailable_reported' || channel?.state === 'degraded_reported') {
    return { label: '待检查', tone: 'warning' }
  }
  return { label: '待验证', tone: 'neutral' }
}

export function macOperationText(operation: ServiceOperation): string {
  const actions: Partial<Record<ServiceOperation['kind'], string>> = {
    takeover_start: '连接', channels_set: '通道切换', auth_begin: '公司认证', takeover_stop: '停止', exit_restore: '验证恢复', workspace: '配置',
  }
  const progress: Record<string, string> = {
    running: '进行中', authenticating: '等待本机 Terminal', authenticated: '会话已更新', starting: '正在启动，可查看 macOS 授权提示',
    applying_company: '正在应用公司 VPN', company_applied: '公司 VPN 已应用',
    applying_personal: '正在应用个人代理', personal_applied: '个人代理已应用',
    waiting_for_stop_report: '等待停止报告', recovering: '等待管理员恢复',
    managed_reported: '网络接管已确认', ready_reported: '已收到运行报告', stopped_reported: '已收到停止报告',
    restored: '管理员恢复已确认', completed: '已完成', failed: '未完成', cancelled: '已取消',
  }
  return `${actions[operation.kind] ?? '操作'} · ${progress[operation.phase] ?? '待确认'}`
}

export function MacLifecycle({ snapshot, configured, busy, preemptible, desired, setDesired, environment, setEnvironment, start, setChannel, authenticate, stop, exit }: {
  snapshot: ServiceSnapshot | null
  configured: boolean
  busy: boolean
  preemptible: boolean
  desired: DesiredChannels
  setDesired: (desired: DesiredChannels) => void
  environment: MacStartEnvironment
  setEnvironment: (environment: MacStartEnvironment) => void
  start: (request: MacStart) => void
  setChannel: (channel: keyof DesiredChannels, enabled: boolean) => void
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
  const canEditCompany = !busy && local && !!snapshot?.run_ref && snapshot.mac_company_control === true
  const canEditPersonal = !busy && local && !!snapshot?.run_ref && snapshot.mac_personal_control === true
  const showRun = !!snapshot?.run_ref && !mayStart && state !== 'starting' && (state !== 'authenticating' || preemptible)
  const channels = showRun ? snapshot.desired : desired
  const mayStop = local && !!snapshot.run_ref && state !== 'restored' && state !== 'stopped_reported'
  const canAuthenticate = canEditCompany && snapshot.desired.company || canConfigure && configured && desired.company
  const environmentReport = showRun ? snapshot.mac_environment : undefined
  const waitingForEnvironment = environmentReport && environmentReport.applied !== environmentReport.selected
  const status = waitingForEnvironment && (state === 'ready_reported' || state === 'managed_reported')
    ? '等待本次运行的环境应用报告'
    : states[state] ?? (snapshot ? '当前运行待确认' : '正在读取网络控制状态')
  const rules = environmentReport && (waitingForEnvironment
    ? `已选择 ${environmentLabels[environmentReport.selected]} · 已应用 ${environmentReport.applied ? environmentLabels[environmentReport.applied] : '等待报告'}`
    : `${environmentLabels[environmentReport.selected]} · 已应用`)
  return <section className="client-card mac-takeover" aria-labelledby="mac-lifecycle-title">
    <header className="mac-takeover-header">
      <div className="mac-takeover-title">
        <span className="mac-takeover-symbol"><ShieldCheck size={22} strokeWidth={1.8} aria-hidden="true" /></span>
        <div>
          <h2 id="mac-lifecycle-title">网络接管</h2>
          {rules && <p>{rules}</p>}
        </div>
      </div>
      <p className="mac-takeover-status" role="status" data-ready={state === 'ready_reported' && !waitingForEnvironment}>{status}</p>
    </header>
    <ul className="mac-takeover-channels" aria-label="三路出口">
      {channelCards.map(({ name, label, Icon }) => {
        const badge = channelBadge(showRun ? snapshot : null, name)
        const canEdit = name === 'company' ? canEditCompany : canEditPersonal
        return <li key={name}>
          <div className="mac-takeover-channel-top">
            <span className="mac-takeover-symbol"><Icon size={17} strokeWidth={1.8} aria-hidden="true" /></span>
            <span className="mac-takeover-badge" data-tone={badge.tone}>{badge.label}</span>
          </div>
          <div className="mac-takeover-channel-body">
            <div><strong>{label}</strong><p>{connectionRouteLabel(snapshot, name)}</p></div>
            {name !== 'direct' && <label className="mac-takeover-toggle">
              <input type="checkbox" aria-label={`开启${name === 'company' ? '公司 VPN' : '个人代理'}`}
                checked={channels[name]} disabled={!canConfigure && !canEdit} onChange={event => {
                  if (canEdit) setChannel(name, event.target.checked)
                  else setDesired({ ...desired, [name]: event.target.checked })
                }} />
            </label>}
          </div>
        </li>
      })}
    </ul>
    {showRun && !busy && !canEditPersonal && <p>当前运行无法切换个人代理，可在下次连接时调整。</p>}
    {!configured && <p>请先在工作空间设置中保存有效策略。</p>}
    {mayStart && <details className="client-details">
      <summary>连接选项</summary>
      <div className="client-actions">
        <label>启动环境<select value={environment} disabled={!canConfigure} onChange={event => {
          if (isMacStartEnvironment(event.target.value)) setEnvironment(event.target.value)
        }}>
          <option value="shared">{environmentLabels.shared}</option>
          <option value="office">{environmentLabels.office}</option>
          <option value="home">{environmentLabels.home}</option>
        </select></label>
        <label>运行模式<select value={mode} disabled={!canConfigure} onChange={event => setMode(event.target.value === 'validation' ? 'validation' : 'daily')}>
          <option value="daily">日用连接</option>
          <option value="validation">限时验证</option>
        </select></label>
        {mode === 'validation' && <label>验证时长（秒）<input type="number" min={1} max={2700} step={1}
          value={duration} required disabled={!canConfigure} onChange={event => setDuration(event.target.value)} /></label>}
      </div>
    </details>}
    <footer className="mac-takeover-footer">
      <button className="mac-takeover-quiet" disabled={!canAuthenticate} onClick={() => authenticate(canEditCompany)}>
        <Terminal size={16} aria-hidden="true" />在终端进行公司认证
      </button>
      <div className="client-actions mac-takeover-actions">
        <button className="mac-takeover-quiet" disabled={busy && !preemptible} onClick={exit}>{snapshot?.run_ref && state !== 'restored' ? '验证恢复并退出' : '退出 LuminaVPN'}</button>
        <button className={mayStart ? 'client-primary' : undefined} disabled={!canConfigure || !configured || mode === 'validation' && !validDuration} onClick={() => {
          start(mode === 'daily' ? { mode, channels: desired, environment } : { mode, channels: desired, environment, validation_seconds: seconds })
        }}>连接网络</button>
        <button className={mayStop ? 'client-primary' : undefined} disabled={!mayStop || busy && !preemptible} onClick={stop}>请求停止</button>
      </div>
    </footer>
  </section>
}
