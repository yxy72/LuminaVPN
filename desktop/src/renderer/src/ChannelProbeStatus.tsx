import type { ServiceChannel } from '../../../protocol/client'

export function ChannelProbeStatus({ channel }: { channel?: ServiceChannel }) {
  const probe = channel?.probe
  if (!probe || probe.scope !== 'system_tun') return <p>系统路径未确认</p>
  const path = { verified: '路径已验证', failed: '路径失败', unknown: '路径未确认' }
  const service = { healthy: '服务响应正常', failed: '服务响应异常', not_checked: '仅检查路径', unknown: '服务响应未确认' }
  return <p>{path[probe.path_state]} · {service[probe.service_state]} · <time dateTime={probe.checked_at}>{new Date(probe.checked_at).toLocaleTimeString()}</time></p>
}
