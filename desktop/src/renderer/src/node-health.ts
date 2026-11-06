export type CandidateState = 'pending' | 'healthy' | 'failed' | 'unknown'
export interface NodeHealthRound {
  epoch: string; config_revision: string; node_set_revision: string; expected_candidate_ids: string[]
  state: 'off' | 'config_empty' | 'pending' | 'ready' | 'all_candidates_failed' | 'unknown'
  candidates: { id: string; state: CandidateState; epoch: string; config_revision: string; node_set_revision: string; failure_scope?: 'node' | 'target' | 'control' }[]
}
// This guards presentation only. Routing and fallback remain service-owned.
export function verifiedHealthState(round: NodeHealthRound): NodeHealthRound['state'] {
  if (round.state === 'off' || round.state === 'config_empty') return round.state
  if (!round.epoch || !round.config_revision || !round.node_set_revision) return 'unknown'
  if (round.state !== 'all_candidates_failed') return round.state
  const expected = new Set(round.expected_candidate_ids)
  if (!expected.size || expected.size !== round.expected_candidate_ids.length || expected.size !== round.candidates.length ||
    new Set(round.candidates.map(c => c.id)).size !== round.candidates.length || round.candidates.some(c => !expected.has(c.id))) return 'unknown'
  return round.candidates.every(c => c.state === 'failed' && c.failure_scope === 'node' && c.epoch === round.epoch &&
    c.config_revision === round.config_revision && c.node_set_revision === round.node_set_revision) ? 'all_candidates_failed' : 'unknown'
}
export const healthLabels = { off: '个人通道已关闭', config_empty: '尚未配置候选节点', pending: '候选节点验证中', ready: '已有健康节点', all_candidates_failed: '本轮全部候选独立失败', unknown: '健康证据尚未确认' }
