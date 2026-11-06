import { spawn, type ChildProcessWithoutNullStreams } from 'node:child_process'
import { TextDecoder } from 'node:util'
import { isRecord, validateRequest, validateResult } from '../../protocol/validation'
import type { BridgeMethod } from '../../protocol/validation'

const FRAME_LIMIT = 1 << 20
export class DesktopError extends Error {
  constructor(public readonly code: string) { super(code) }
}
type Pending = { method: BridgeMethod; resolve: (value: unknown) => void; reject: (error: Error) => void; timer: ReturnType<typeof setTimeout> }

export class Bridge {
  private child: ChildProcessWithoutNullStreams | null = null
  private pending = new Map<string, Pending>()
  private bytes = Buffer.alloc(0)
  private nextID = 0
  private starting: Promise<void> | null = null
  private disposed = false
  constructor(private binary: string, private runtime: string, private profile: string | undefined, private version: string) {}

  async start(): Promise<void> {
    if (this.disposed) throw new DesktopError('CONTROL_DISCONNECTED')
    if (this.starting) return this.starting
    if (this.child) return
    this.starting = this.launch()
    try { await this.starting } finally { this.starting = null }
  }
  private async launch(): Promise<void> {
    const args = ['desktop', 'serve', '--runtime', this.runtime]
    if (this.profile) args.push('--profile', this.profile)
    const env = { ...process.env }
    for (const key of ['NODE_OPTIONS', 'ELECTRON_RUN_AS_NODE', 'DYLD_INSERT_LIBRARIES', 'LD_PRELOAD']) delete env[key]
    const child = spawn(this.binary, args, { shell: false, windowsHide: true, stdio: ['pipe', 'pipe', 'pipe'], env })
    this.child = child
    this.bytes = Buffer.alloc(0)
    child.stderr.on('data', () => {}) // Drain without copying raw backend errors into logs.
    child.stdout.on('data', (chunk: Buffer) => {
      if (this.child !== child) return
      this.bytes = Buffer.concat([this.bytes, chunk])
      for (;;) {
        const end = this.bytes.indexOf(10)
        if (end < 0) break
        if (end > FRAME_LIMIT) { this.fail('INVALID_PROTOCOL'); return }
        const frame = this.bytes.subarray(0, end)
        this.bytes = this.bytes.subarray(end + 1)
        try {
          const value: unknown = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(frame))
          if (!isRecord(value) || typeof value.id !== 'string' || value.id.length > 128) throw new Error()
          const p = this.pending.get(value.id)
          if (!p) continue // Expired reads cannot complete a later operation.
          clearTimeout(p.timer); this.pending.delete(value.id)
          if ('error' in value && !('result' in value)) {
            if (!isRecord(value.error) || typeof value.error.code !== 'string' || !/^[A-Z_]{1,64}$/.test(value.error.code)) { p.reject(new DesktopError('INVALID_PROTOCOL')); this.fail('INVALID_PROTOCOL'); return }
            p.reject(new DesktopError(value.error.code))
          } else if ('result' in value && !('error' in value) && validateResult(p.method, value.result)) p.resolve(value.result)
          else { p.reject(new DesktopError('INVALID_PROTOCOL')); this.fail('INVALID_PROTOCOL'); return }
        } catch { this.fail('INVALID_PROTOCOL'); return }
      }
      if (this.bytes.length > FRAME_LIMIT) this.fail('INVALID_PROTOCOL')
    })
    child.on('error', () => { if (this.child === child) this.fail('CONTROL_UNAVAILABLE') })
    child.on('exit', () => { if (this.child === child) this.fail('CONTROL_DISCONNECTED') })
    child.stdin.on('error', () => { if (this.child === child) this.fail('CONTROL_DISCONNECTED') })
    try { await this.send('session.hello', { protocol_major: 1, app_version: this.version }) }
    catch (e) { this.fail('CONTROL_UNAVAILABLE'); throw e }
  }
  async request(method: BridgeMethod, params: Record<string, unknown> = {}): Promise<unknown> {
    validateRequest(method, params)
    await this.start()
    return this.send(method, params)
  }
  private send(method: BridgeMethod, params: Record<string, unknown>): Promise<unknown> {
    if (!this.child) return Promise.reject(new DesktopError('CONTROL_DISCONNECTED'))
    const child = this.child
    if (this.pending.size >= 16) return Promise.reject(new DesktopError('BUSY'))
    const id = String(++this.nextID)
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => { if (this.child === child) this.fail('READ_TIMEOUT') }, 5500)
      this.pending.set(id, { method, resolve, reject, timer })
      child.stdin.write(JSON.stringify({ id, method, params }) + '\n', error => { if (error && this.child === child) this.fail('CONTROL_DISCONNECTED') })
    })
  }
  private fail(code: string): void {
    const child = this.child; this.child = null
    for (const p of this.pending.values()) { clearTimeout(p.timer); p.reject(new DesktopError(code)) }
    this.pending.clear(); this.bytes = Buffer.alloc(0)
    // This child is the ordinary IPC proxy. Network operations belong to the
    // service and survive this proxy's EOF, timeout or termination.
    child?.stdin.end(); child?.kill()
  }
  close(): void { this.disposed = true; this.fail('CONTROL_DISCONNECTED') }
}
