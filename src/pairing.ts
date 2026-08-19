import { randomInt, randomBytes } from 'node:crypto'
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { PAIRING_CODE_LENGTH, PAIRING_CODE_TTL_MS, PAIRING_MAX_ATTEMPTS, type SessionInfo } from '@firefly0621/dsh-remote-protocol'

interface PairingRecord {
  deviceId: string
  expiresAt: number
  attempts: number
  consumed: boolean
}

/** In-memory short-lived pairing codes; a restart clears them by design. */
export class PairingStore {
  private readonly codes = new Map<string, PairingRecord>()
  /** Test seam: current time in ms; defaults to Date.now(). */
  private nowMs = () => Date.now()
  /** Test seam: move the clock forward (used by pairing.spec). */
  advanceClock(ms: number): void {
    const base = this.nowMs()
    this.nowMs = () => base + ms
  }

  /** Mint one 6-digit code bound to a device, replacing any older one. */
  issue(deviceId: string): { code: string; expiresAt: number } {
    const now = this.nowMs()
    // Reap expired codes so an idle registry never grows.
    for (const [code, record] of this.codes) {
      if (now > record.expiresAt) this.codes.delete(code)
    }
    const code = String(randomInt(0, 1_000_000)).padStart(PAIRING_CODE_LENGTH, '0')
    const expiresAt = now + PAIRING_CODE_TTL_MS
    this.codes.set(code, { deviceId, expiresAt, attempts: 0, consumed: false })
    return { code, expiresAt }
  }

  /** Return the bound deviceId while the code is valid, else undefined. */
  verify(code: string): string | undefined {
    const record = this.codes.get(code)
    if (record === undefined) return undefined
    if (record.consumed) return undefined
    if (this.nowMs() > record.expiresAt) {
      this.codes.delete(code)
      return undefined
    }
    record.attempts += 1
    if (record.attempts > PAIRING_MAX_ATTEMPTS) {
      this.codes.delete(code)
      return undefined
    }
    return record.deviceId
  }

  /** Invalidate a code after a successful pairing. */
  consume(code: string): void {
    this.codes.delete(code)
  }
}

/** Random opaque session tokens bound to one device; persisted when a data dir is given. */
export class SessionStore {
  private readonly sessions = new Map<string, { deviceId: string; deviceName: string; createdAt: number }>()
  private readonly file: string | undefined

  constructor(dataDir?: string) {
    if (dataDir !== undefined) {
      this.file = join(dataDir, 'sessions.json')
      this.load()
    }
  }

  /** Mint a 256-bit hex token bound to a device. */
  create(deviceId: string, deviceName: string): string {
    const token = randomBytes(32).toString('hex')
    this.sessions.set(token, { deviceId, deviceName, createdAt: Date.now() })
    this.persist()
    return token
  }

  /** Resolve a token to its bound device, or undefined. */
  resolve(token: string): { deviceId: string; deviceName: string } | undefined {
    return this.sessions.get(token)
  }

  /** Every bound session of one device, in creation order. */
  list(deviceId: string): SessionInfo[] {
    return [...this.sessions]
      .filter(([, session]) => session.deviceId === deviceId)
      .map(([sessionId, session]) => ({ sessionId, deviceName: session.deviceName, createdAt: session.createdAt }))
  }

  /** Drop one session token; returns whether it existed. */
  revoke(token: string): boolean {
    const existed = this.sessions.delete(token)
    if (existed) this.persist()
    return existed
  }

  /** Load persisted sessions from disk, when a data dir was configured. */
  private load(): void {
    if (this.file === undefined) return
    let raw: string
    try {
      raw = readFileSync(this.file, 'utf8')
    } catch {
      return // first run: no file yet
    }
    try {
      const parsed = JSON.parse(raw) as Array<{ sessionId: string; deviceId: string; deviceName: string; createdAt: number }>
      for (const record of parsed) {
        if (typeof record.sessionId === 'string' && typeof record.deviceId === 'string') {
          this.sessions.set(record.sessionId, {
            deviceId: record.deviceId,
            deviceName: record.deviceName,
            createdAt: record.createdAt,
          })
        }
      }
    } catch {
      // A corrupt file must not kill the relay; fresh state replaces it on next write.
    }
  }

  /** Write all sessions to disk synchronously (small file; called on change). */
  private persist(): void {
    if (this.file === undefined) return
    const records = [...this.sessions].map(([sessionId, session]) => ({ sessionId, ...session }))
    mkdirSync(dirname(this.file), { recursive: true })
    writeFileSync(this.file, JSON.stringify(records, null, 2))
  }
}
