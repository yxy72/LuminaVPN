import { describe, it, expect } from 'vitest'
import { verifiedHealthState, type NodeHealthRound } from '../src/renderer/src/node-health'
const round: NodeHealthRound = { epoch: 'e', config_revision: 'c', node_set_revision: 'n', expected_candidate_ids: ['a'], state: 'all_candidates_failed', candidates: [{ id: 'a', state: 'failed', failure_scope: 'node', epoch: 'e', config_revision: 'c', node_set_revision: 'n' }] }
describe('candidate evidence presentation', () => {
  it('accepts only a nonempty independently failed current round', () => expect(verifiedHealthState(round)).toBe('all_candidates_failed'))
  it('empty, unknown, pending, target/control failures or an old epoch cannot mean all failed', () => {
    expect(verifiedHealthState({ ...round, candidates: [] })).toBe('unknown')
    expect(verifiedHealthState({ ...round, expected_candidate_ids: ['a','b'] })).toBe('unknown')
    expect(verifiedHealthState({ ...round, expected_candidate_ids: ['other'] })).toBe('unknown')
    expect(verifiedHealthState({ ...round, expected_candidate_ids: ['a','a'] })).toBe('unknown')
    for (const change of [{ state: 'pending' }, { state: 'unknown' }, { epoch: 'old' }, { config_revision: 'old' }, { node_set_revision: 'old' }, { failure_scope: 'target' }, { failure_scope: 'control' }]) {
      expect(verifiedHealthState({ ...round, candidates: [{ ...round.candidates[0], ...change }] } as NodeHealthRound)).toBe('unknown')
    }
  })
})
