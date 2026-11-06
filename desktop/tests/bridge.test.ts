import { EventEmitter } from 'node:events'
import { describe, expect, it, vi } from 'vitest'
import { readFileSync } from 'node:fs'
import { resolve } from 'node:path'

const harness = vi.hoisted(() => ({ spawn: vi.fn() }))
vi.mock('node:child_process', () => ({ spawn: harness.spawn }))
import { Bridge } from '../src/main/bridge'
import { READ_METHODS } from '../protocol/types'

const state = JSON.parse(readFileSync(resolve('protocol/fixtures.json'), 'utf8')).state
const hello = { protocol_major: 1, session_id: 'fixture', build: { version: '0.2.0-preview.2', os: 'darwin', arch: 'arm64', go_version: 'fixture' }, mode: 'native', capabilities: { read_only: true, connection_start: false, connection_stop: false, config_write: false, native_lifecycle: true, methods: [...READ_METHODS] } }

function child(malformed = false) {
  const process = new EventEmitter() as EventEmitter & { stdin: EventEmitter & { write: (frame: string, cb: (error?: Error) => void) => boolean; end: () => void }; stdout: EventEmitter; stderr: EventEmitter; kill: ReturnType<typeof vi.fn>; callbacks: ((error?: Error) => void)[] }
  process.stdout = new EventEmitter(); process.stderr = new EventEmitter(); process.callbacks = []; process.kill = vi.fn()
  process.stdin = Object.assign(new EventEmitter(), {
    end: vi.fn(), write(frame: string, callback: (error?: Error) => void) {
      process.callbacks.push(callback)
      const request = JSON.parse(frame)
      queueMicrotask(() => process.stdout.emit('data', Buffer.from(JSON.stringify({ id: request.id, result: request.method === 'session.hello' ? hello : malformed ? { private: 'rejected-canary' } : state }) + '\n')))
      return true
    }
  })
  return process
}

describe('read-only bridge lifecycle', () => {
  it('starts once, handshakes and preserves string request IDs', async () => {
    const fake = child(); harness.spawn.mockReturnValue(fake)
    const bridge = new Bridge('/fixed/backend', '/fixed/runtime', undefined, hello.build.version)
    try { const result = await bridge.request('state.get'); expect(result).toEqual(state); expect(harness.spawn.mock.calls.at(-1)?.[1]).toContain('serve') }
    finally { bridge.close() }
  })
  it('a late write error from the prior child cannot kill a replacement', async () => {
    const old = child(), next = child(); harness.spawn.mockReturnValueOnce(old).mockReturnValueOnce(next)
    const bridge = new Bridge('/fixed/backend', '/fixed/runtime', undefined, hello.build.version)
    try {
      await bridge.request('state.get'); old.emit('exit', 1)
      await bridge.request('state.get'); old.callbacks.at(-1)!(new Error('private-late-error'))
      expect(next.kill).not.toHaveBeenCalled(); expect(await bridge.request('state.get')).toEqual(state)
    } finally { bridge.close() }
  })
  it('rejects malformed DTOs without exposing their raw contents', async () => {
    const fake = child(true); harness.spawn.mockReturnValue(fake)
    const bridge = new Bridge('/fixed/backend', '/fixed/runtime', undefined, hello.build.version)
    try { await expect(bridge.request('state.get')).rejects.toMatchObject({ code: 'INVALID_PROTOCOL' }); expect(fake.kill).toHaveBeenCalled() }
    finally { bridge.close() }
  })
})
