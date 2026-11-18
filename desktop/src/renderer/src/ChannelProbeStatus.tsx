import type { ServiceChannel, ServiceSnapshot } from '../../../protocol/client'

export function ChannelProbeStatus({ channel }: { channel?: ServiceChannel }) {
  const probe = channel?.probe
  if (!probe || probe.scope !== 'system_tun') return <p>系统路径未确认</p>
  const path = { verified: '路径已验证', failed: '路径失败', unknown: '路径未确认' }
  const service = { healthy: '服务响应正常', failed: '服务响应异常', not_checked: '仅检查路径', unknown: '服务响应未确认' }
  return <p>{path[probe.path_state]} · {service[probe.service_state]} · <time dateTime={probe.checked_at}>{new Date(probe.checked_at).toLocaleTimeString()}</time></p>
}


const channels = [
  ['direct', '直连'], ['company', '公司 VPN'], ['personal', '个人代理'],
] as const

function routeLabel(snapshot: ServiceSnapshot | null, name: typeof channels[number][0], details: boolean): string {
  const channel = snapshot?.[name]
  if (snapshot?.takeover_state === 'applying_personal' && name === 'personal' ||
      snapshot?.takeover_state === 'applying_company' && name === 'company') return '等待切换结果'
  switch (channel?.route) {
    case 'direct':
    case 'direct_reported':
      if (channel.reason === 'all_candidates_failed') return details ? '候选全部失败，临时直连' : '临时直连'
      if (channel.reason === 'disabled_direct') return details ? '个人通道已关闭，走直连' : '通道已关闭 · 直连'
      return name === 'direct' ? '物理网卡' : '直连'
    case 'vpn':
    case 'vpn_reported': return '公司 VPN'
    case 'personal':
    case 'personal_reported': return '个人节点'
    case 'blocked': return '已阻断'
    case 'blocked_reported': return '报告已阻断'
    default: return name === 'personal' && channel?.desired ? '已请求代理 · 待确认' : '出口未确认'
  }
}

export function ConnectionChannels({ snapshot, details = false }: {
  snapshot: ServiceSnapshot | null
  details?: boolean
}) {
  return <ul className={`connection-channels${details ? ' detailed' : ''}`} aria-label="三路出口">
    {channels.map(([name, label]) => {
      const channel = snapshot?.[name]
      return <li key={name}>
        <strong>{label}</strong><span>{routeLabel(snapshot, name, details)}</span>
        {details && <ChannelProbeStatus channel={channel} />}
      </li>
    })}
  </ul>
}
