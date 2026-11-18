import { useState } from 'react'
import type { ServiceChannel } from '../../../protocol/client'
import type { Nodes } from '../../../protocol/types'
import { ChannelProbeStatus } from './ChannelProbeStatus'
import { healthLabels, verifiedHealthState } from './node-health'

const regions = new Intl.DisplayNames(['zh-CN'], { type: 'region', fallback: 'none' })
const protocols: Record<string, string> = { vless: 'VLESS', hysteria2: 'Hysteria 2' }
const candidateStates = { pending: '检查中', healthy: '通过', failed: '失败', unknown: '待确认' }

export function NodeInventory({ nodes, savedNode, channel, load, refresh, measure, measuring, canMeasure }: {
  nodes: Nodes | null
  savedNode?: string | null
  channel?: ServiceChannel
  load: (offset: number) => void
  refresh: () => void
  measure: () => void
  measuring: boolean
  canMeasure: boolean
}) {
  const [query, setQuery] = useState('')
  const [sortByLatency, setSortByLatency] = useState(false)
  const health = channel?.health_epoch === channel?.health?.epoch ? channel?.health : undefined
  const candidates = health?.candidates.filter(c =>
    c.epoch === health.epoch && c.config_revision === health.config_revision &&
    c.node_set_revision === health.node_set_revision && health.expected_candidate_ids.includes(c.id))
  const state = channel?.state
  const candidateState = state === 'all_candidates_failed'
    ? health ? verifiedHealthState({ ...health, state, candidates: health.candidates.map(candidate => ({
      ...candidate, failure_scope: candidate.failure_scope === 'node' ? 'node' : undefined,
    })) }) : 'unknown'
    : state === 'off' || state === 'config_empty' || state === 'pending' || state === 'ready' ? state : 'unknown'
  const reported = state === 'ready_reported' && channel?.route === 'personal_reported' ? '报告显示个人代理已就绪'
    : channel?.reason === 'disabled_direct' ? '个人通道已关闭' : undefined
  const entries = (nodes?.items ?? []).map(node => ({
    ...node, area: node.region && /^[A-Z]{2}$/.test(node.region) ? regions.of(node.region) : undefined,
    protocol: protocols[node.type] ?? '未知',
  }))
  const search = query.trim().toLocaleLowerCase()
  const visible = entries.filter(node => [node.id, node.area, node.region, node.protocol]
    .some(value => value?.toLocaleLowerCase().includes(search)))
  if (sortByLatency) visible.sort((a, b) => (a.latency_ms ?? Infinity) - (b.latency_ms ?? Infinity))
  const measuredAt = nodes?.latency_checked_at
  return <section className="client-card">
    <h2>节点选择与健康</h2>
    <div className="node-health-summary">
      <strong>{reported ?? healthLabels[candidateState]}</strong>
      <span>自动选点</span>
      {savedNode && <span>保存记录中的选择 <code>{savedNode}</code></span>}
      <ChannelProbeStatus channel={channel} />
    </div>
    {!!candidates?.length && <details className="client-details">
      <summary>本次运行的候选检查（{candidates.length}）</summary>
      <ul className="client-list-scroll" tabIndex={0} aria-label="运行候选结果">
        {candidates.map(candidate => <li key={candidate.id}>
          <code>{candidate.id}</code> · {candidateStates[candidate.state]}
          {candidate.state === 'failed' && candidate.failure_scope === 'node' && ' · 节点路径失败'}
        </li>)}
      </ul>
    </details>}
    <div className="node-inventory-toolbar">
      <label>搜索本页节点<input type="search" placeholder="地区、协议或编号" value={query}
        onChange={event => setQuery(event.target.value)} /></label>
      <div className="client-actions">
        <button disabled={!canMeasure || !nodes?.total} onClick={measure}>
          {measuring ? '正在测延迟…' : '测量节点延迟'}
        </button>
        <button onClick={refresh}>刷新库存</button>
      </div>
    </div>
    {measuredAt && <p>最近测速 <time dateTime={measuredAt}>{new Date(measuredAt).toLocaleTimeString()}</time></p>}
    <div className="client-table-scroll" key={nodes?.offset} tabIndex={0} role="region" aria-label="本机节点库存">
      <table className="client-table">
        <thead><tr><th scope="col">地区标注</th><th scope="col">编号</th><th scope="col">协议</th>
          <th scope="col" aria-sort={sortByLatency ? 'ascending' : 'none'}>
            <button className="node-latency-sort" onClick={() => setSortByLatency(!sortByLatency)}>延迟（ms）{sortByLatency ? ' ↑' : ''}</button>
          </th>
        </tr></thead>
        <tbody>{visible.map(node => <tr key={node.id}>
          <td>{node.area ?? '未标注'}</td><td><code>{node.id}</code></td><td>{node.protocol}</td>
          <td className="node-latency-value">{node.latency_ms ?? (node.latency_state === 'failed' ? '未通过' : '—')}</td>
        </tr>)}</tbody>
      </table>
      {!visible.length && <p className="client-table-empty">{nodes ? nodes.total ? '本页没有匹配的节点' : '尚无节点，请导入或同步来源' : '正在读取本机节点'}</p>}
    </div>
    <div className="client-pagination">
      <span>{nodes?.total ? `${nodes.offset + 1}–${nodes.offset + nodes.items.length} / ${nodes.total} 个节点` : `${nodes?.total ?? '—'} 个节点`}</span>
      <div className="client-actions">
        <button disabled={!nodes || nodes.offset === 0} onClick={() => { if (nodes) load(Math.max(0, nodes.offset - nodes.limit)) }}>上一页</button>
        <button disabled={!nodes || nodes.offset + nodes.items.length >= nodes.total} onClick={() => { if (nodes) load(nodes.offset + nodes.limit) }}>下一页</button>
      </div>
    </div>
  </section>
}
