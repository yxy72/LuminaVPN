import { describe, expect, it, vi } from 'vitest'
import type { Environment } from '../protocol/types'
import { EnvironmentChecks } from '../src/renderer/src/environment'

function deferred() {
  let resolve!: (value: Environment) => void
  let reject!: (error: Error) => void
  const promise = new Promise<Environment>((yes, no) => { resolve = yes; reject = no })
  return { promise, resolve, reject }
}

function view() {
  const state: { environment: Environment | null; error: unknown; checking: boolean } = {
    environment: null, error: null, checking: false
  }
  return {
    state,
    handlers: {
      started() { state.checking = true; state.error = null },
      succeeded(result: Environment) { state.environment = result },
      failed(error: unknown) { state.error = error },
      finished() { state.checking = false }
    }
  }
}

const result = (id: string): Environment => ({
  checked_at: '2026-11-05T00:00:00Z', read_only: true,
  checks: [{ id, label: 'Local policy', state: 'passed', message: 'Fixture' }]
})

describe('environment checks across profile selection', () => {
  it('ignores an old success while a profile is being selected', async () => {
    const checks = new EnvironmentChecks(), pending = deferred(), screen = view()
    const running = checks.run(() => pending.promise, screen.handlers)
    checks.beginProfileSelection()
    screen.state.checking = false
    pending.resolve(result('old-profile'))
    await running
    expect(screen.state).toEqual({ environment: null, error: null, checking: false })
  })

  it('an old error and finally cannot finish the new profile check', async () => {
    const checks = new EnvironmentChecks(), old = deferred(), next = deferred(), screen = view()
    const prior = checks.run(() => old.promise, screen.handlers)
    checks.beginProfileSelection()
    checks.endProfileSelection()
    const current = checks.run(() => next.promise, screen.handlers)
    old.reject(new Error('old-profile-error'))
    await prior
    expect(screen.state).toEqual({ environment: null, error: null, checking: true })
    next.resolve(result('new-profile'))
    await current
    expect(screen.state).toEqual({ environment: result('new-profile'), error: null, checking: false })
  })

  it('a late old success cannot replace a completed new profile check', async () => {
    const checks = new EnvironmentChecks(), pending = deferred(), screen = view()
    const prior = checks.run(() => pending.promise, screen.handlers)
    checks.beginProfileSelection()
    checks.endProfileSelection()
    await checks.run(async () => result('new-profile'), screen.handlers)
    pending.resolve(result('old-profile'))
    await prior
    expect(screen.state.environment).toEqual(result('new-profile'))
    expect(screen.state.checking).toBe(false)
  })

  it('does not read during selection and allows checking after cancellation', async () => {
    const checks = new EnvironmentChecks(), screen = view()
    const read = vi.fn(async () => result('unchanged-profile'))
    expect(checks.beginProfileSelection()).toBe(true)
    expect(checks.beginProfileSelection()).toBe(false)
    await checks.run(read, screen.handlers)
    expect(read).not.toHaveBeenCalled()
    expect(screen.state.checking).toBe(false)
    checks.endProfileSelection()
    await checks.run(read, screen.handlers)
    expect(read).toHaveBeenCalledOnce()
    expect(screen.state.environment).toEqual(result('unchanged-profile'))
    expect(screen.state.checking).toBe(false)
  })
})
