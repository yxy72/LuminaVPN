import { readFileSync } from 'node:fs'
import { resolve } from 'node:path'
import { describe, expect, it } from 'vitest'
import { validateRequest, validateResult } from '../protocol/validation'
import { ageChannel } from '../src/renderer/src/evidence'
import type { Channel } from '../protocol/types'

const fixtures = JSON.parse(readFileSync(resolve('protocol/fixtures.json'), 'utf8'))
describe('desktop boundary', () => {
  it('accepts the shared fabricated contract', () => {
    expect(() => validateRequest(fixtures.hello_request.method, fixtures.hello_request.params)).not.toThrow()
    expect(validateResult('state.get', fixtures.state)).toBe(true)
  })
  it('rejects file paths, unknown methods and oversized pagination', () => {
    expect(() => validateRequest('state.get', { profile: '/private/canary' })).toThrow()
    expect(() => validateRequest('connection.start', {})).toThrow()
    expect(() => validateRequest('nodes.list', { limit: 101 })).toThrow()
    expect(() => validateRequest('config.get', { offset: -1 })).toThrow()
    expect(() => validateRequest('state.get', null)).toThrow()
  })
  it('rejects a malformed state and a backend offering unexpected writes', () => {
    expect(validateResult('state.get', { ...fixtures.state, runtime_liveness: 'live' })).toBe(false)
    expect(validateResult('session.hello', { capabilities: { connection_start: true } })).toBe(false)
  })
})
describe('local evidence aging', () => {
  const now = Date.parse('2026-11-02T04:00:00Z')
  const channel = fixtures.state.status.channels.personal as Channel
  it('ages evidence while the control interface is silent', () => {
    const old = ageChannel(channel, now + 90001)
    expect(old.state).toBe('unknown'); expect(old.path_state).toBe('unknown'); expect(old.service_state).toBe('unknown')
    expect(channel.state).toBe('ready')
  })
  it('rejects future timestamps and missing evidence', () => {
    expect(ageChannel(channel, now - 1).state).toBe('unknown')
    expect(ageChannel(undefined, now).state).toBe('unknown')
  })
  it('preserves service rejection separately from a verified path', () => {
    const rejected = { ...channel, state: 'unavailable', reason: 'http_status_rejected', service_state: 'failed' }
    expect(ageChannel(rejected, now).path_state).toBe('verified')
    expect(ageChannel(rejected, now).service_state).toBe('failed')
  })
})
