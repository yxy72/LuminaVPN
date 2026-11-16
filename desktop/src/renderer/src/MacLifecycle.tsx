import { useState } from 'react'
import type { ServiceMutation, ServiceOperation, ServiceSnapshot } from '../../../protocol/client'

type MacStart = Extract<ServiceMutation, { kind: 'takeover_start' }>['start']

const states: Record<string, string> = {
  idle: '当前配置没有运行',
  starting: '正在启动，可查看 macOS 授权提示',
  waiting_for_stop_report: '等待停止报告',
  recovering: '等待管理员恢复',
  restored: '管理员恢复已确认',
  ready_reported: '运行报告就绪',
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
    takeover_start: '连接', takeover_stop: '停止', exit_restore: '验证恢复', workspace: '配置',
  }
  const progress: Record<string, string> = {
    running: '进行中', starting: '正在启动，可查看 macOS 授权提示',
    waiting_for_stop_report: '等待停止报告', recovering: '等待管理员恢复',
    ready_reported: '运行报告就绪', stopped_reported: '已收到停止报告',
    restored: '管理员恢复已确认', completed: '已完成', failed: '未完成', cancelled: '已取消',
  }
  return `${actions[operation.kind] ?? '操作'} · ${progress[operation.phase] ?? '待确认'}`
}

export function MacLifecycle({ snapshot, configured, busy, start, stop, exit }: {
  snapshot: ServiceSnapshot | null
  configured: boolean
  busy: boolean
  start: (request: MacStart) => void
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
  const mayStop = local && !!snapshot.run_ref && state !== 'restored' && state !== 'stopped_reported'
  return <section className="client-card" aria-labelledby="mac-lifecycle-title">
    <h2 id="mac-lifecycle-title">网络接管</h2>
    <p role="status">{states[state] ?? (snapshot ? '当前运行待确认' : '正在读取网络控制状态')}</p>
    <p>连接将使用公司 VPN、个人代理和直连规则。启动与验证恢复时可能出现 macOS 管理员授权。</p>
    {!configured && <p>请先在工作空间设置中保存有效策略。</p>}
    <div className="client-actions">
      <label>运行模式<select value={mode} disabled={busy} onChange={event => setMode(event.target.value === 'validation' ? 'validation' : 'daily')}>
        <option value="daily">日用连接</option>
        <option value="validation">限时验证</option>
      </select></label>
      {mode === 'validation' && <label>验证时长（秒）<input type="number" min={1} max={2700} step={1}
        value={duration} required disabled={busy} onChange={event => setDuration(event.target.value)} /></label>}
    </div>
    <div className="client-actions">
      <button disabled={busy || !configured || !mayStart || mode === 'validation' && !validDuration} onClick={() => {
        const channels = { company: true, personal: true }
        start(mode === 'daily' ? { mode, channels } : { mode, channels, validation_seconds: seconds })
      }}>连接网络</button>
      <button disabled={busy || !mayStop} onClick={stop}>请求停止</button>
      <button disabled={busy} onClick={exit}>{snapshot?.run_ref && state !== 'restored' ? '验证恢复并退出' : '退出 LuminaVPN'}</button>
    </div>
  </section>
}
