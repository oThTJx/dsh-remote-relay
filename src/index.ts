import { createServer as createHttpServer, type IncomingMessage, type Server as HttpServer } from 'node:http'
import { createServer as createHttpsServer, type Server as HttpsServer } from 'node:https'
import { randomUUID, timingSafeEqual } from 'node:crypto'
import { readFile } from 'node:fs/promises'
import { WebSocketServer, WebSocket } from 'ws'
import {
  HEARTBEAT_INTERVAL_MS,
  HEARTBEAT_TIMEOUT_MS,
  parseMessage,
  serializeMessage,
  type Envelope,
  type EventPayload,
} from '@firefly0621/dsh-remote-protocol'
import { PairingStore, SessionStore } from './pairing.ts'

/** Security invariants (kept fixed, not deployment-configurable). */
const PAIR_FAILURE_LIMIT = 10
const PAIR_FAILURE_WINDOW_MS = 60_000
const PAIR_BLOCK_MS = 600_000
const MAX_SOCKETS_PER_IP = 32
const PENDING_REQUEST_TTL_MS = 30_000
/** Auto-registered devices (first-seen-wins) and sessions per device stay bounded. */
const MAX_DEVICES = 1_024
const MAX_SESSIONS_PER_DEVICE = 32

/** Constant-time secret comparison; empty or differing-length secrets compare false. */
function secretsEqual(a: string, b: string): boolean {
  const left = Buffer.from(a)
  const right = Buffer.from(b)
  return left.length > 0 && left.length === right.length && timingSafeEqual(left, right)
}

/** Server configuration; port 0 picks an OS-assigned port for tests. */
export interface RelayConfig {
  port: number
  /** Production requires TLS; tests run plaintext on loopback. */
  requireTls: boolean
  /** deviceId → long-lived secret, from deployment env. */
  deviceSecrets: Record<string, string>
  /**
   * Accept the first hello for an unknown deviceId and bind it to that secret
   * (first-seen-wins). Off by default: explicit deployments stay locked down,
   * and plugin-generated random deviceIds make claiming a vacant id useless.
   */
  allowAutoRegister?: boolean
  /** Directory for durable session storage; absent keeps sessions in memory. */
  dataDir?: string
  /** When true, per-IP caps use the leftmost `X-Forwarded-For` address (trusted reverse proxy only). */
  trustProxy?: boolean
  tlsCert?: string
  tlsKey?: string
}

/** Resolve the client IP for rate limits; optionally honor `X-Forwarded-For` behind a trusted proxy. */
function clientIp(request: IncomingMessage, trustProxy: boolean): string {
  if (trustProxy) {
    const forwarded = request.headers['x-forwarded-for']
    const raw = Array.isArray(forwarded) ? forwarded[0] : forwarded
    if (typeof raw === 'string' && raw.length > 0) {
      const first = raw.split(',')[0]?.trim()
      if (first !== undefined && first.length > 0) return first
    }
  }
  return request.socket.remoteAddress ?? 'unknown'
}

interface DeviceConnection {
  socket: WebSocket
  name: string
}

/** One app request awaiting the device's response. */
interface PendingRequest {
  /** The app socket to deliver the reply to. */
  socket: WebSocket
  /** The device the request was routed to; failed when that device disconnects. */
  deviceId: string
  /** Replies past this point are dropped and the app told the request timed out. */
  expiresAt: number
}

/** Per-IP `pair` failure accounting; a blocked IP is rejected until `blockedUntil`. */
interface PairFailureWindow {
  count: number
  windowStart: number
  blockedUntil: number
}

/**
 * Minimal WebSocket relay: devices authenticate with a long-lived secret,
 * apps pair with a short code, and requests route between them.
 */
export class RelayServer {
  private http: HttpServer | HttpsServer | undefined
  private wss: WebSocketServer | undefined
  private readonly devices = new Map<string, DeviceConnection>()
  private readonly deviceSecrets = new Map<string, string>()
  private readonly allowAutoRegister: boolean
  private readonly sockets = new Set<WebSocket>()
  private readonly pairings = new PairingStore()
  private readonly sessions: SessionStore
  /** request id → the app socket waiting for the device's response. */
  private readonly pending = new Map<string, PendingRequest>()
  /** session token → the app socket bound to it (device→app `event` pushes). */
  private readonly sessionSockets = new Map<string, WebSocket>()
  private readonly lastSeen = new Map<WebSocket, number>()
  /** Source IP of each socket, and per-IP open-socket counts (DoS caps). */
  private readonly socketIps = new Map<WebSocket, string>()
  private readonly ipSocketCounts = new Map<string, number>()
  private readonly ipPairFailures = new Map<string, PairFailureWindow>()
  private heartbeatTimer: NodeJS.Timeout | undefined
  private listening = false

  constructor(private readonly config: RelayConfig) {
    for (const [deviceId, secret] of Object.entries(config.deviceSecrets)) this.deviceSecrets.set(deviceId, secret)
    this.allowAutoRegister = config.allowAutoRegister ?? false
    this.sessions = new SessionStore(config.dataDir)
  }

  /** How many devices are currently registered. */
  deviceCount(): number {
    return this.devices.size
  }

  /** The port in use (OS-assigned when config.port was 0). */
  get port(): number {
    const address = this.wss?.address()
    return typeof address === 'object' && address !== null ? address.port : this.config.port
  }

  /** Start listening and accept device/app connections. */
  async start(): Promise<void> {
    if (this.listening) return
    let http: HttpServer | HttpsServer
    if (this.config.requireTls) {
      if (!this.config.tlsCert || !this.config.tlsKey) {
        throw new Error('relay: requireTls needs tlsCert and tlsKey')
      }
      http = createHttpsServer({
        cert: await readFile(this.config.tlsCert),
        key: await readFile(this.config.tlsKey),
      })
    } else {
      http = createHttpServer()
    }
    this.http = http
    this.wss = new WebSocketServer({ server: http, maxPayload: 1_048_576 })
    this.wss.on('connection', (socket, request) => { this.handleConnection(socket, request) })
    this.heartbeatTimer = setInterval(() => { this.reap() }, HEARTBEAT_INTERVAL_MS)
    await new Promise<void>((resolve, reject) => {
      http.once('error', reject)
      http.listen(this.config.port, () => {
        http.off('error', reject)
        this.listening = true
        resolve()
      })
    })
  }

  /** Close the server and every tracked socket. */
  async close(): Promise<void> {
    if (!this.listening) return
    if (this.heartbeatTimer !== undefined) clearInterval(this.heartbeatTimer)
    this.heartbeatTimer = undefined
    for (const socket of this.sockets) socket.terminate()
    this.sockets.clear()
    this.devices.clear()
    this.pending.clear()
    this.sessionSockets.clear()
    this.lastSeen.clear()
    await new Promise<void>((resolve) => {
      this.wss?.close(() => { resolve() })
    })
    await new Promise<void>((resolve) => {
      this.http?.close(() => { resolve() })
    })
    this.listening = false
  }

  private handleConnection(socket: WebSocket, request: IncomingMessage): void {
    const ip = clientIp(request, this.config.trustProxy ?? false)
    this.socketIps.set(socket, ip)
    const open = this.ipSocketCounts.get(ip) ?? 0
    if (open >= MAX_SOCKETS_PER_IP) {
      socket.close(1008, 'too many connections from one address')
      return
    }
    this.ipSocketCounts.set(ip, open + 1)
    this.sockets.add(socket)
    socket.on('message', (data) => {
      this.touch(socket)
      let message: Envelope
      try {
        message = parseMessage(Buffer.from(data as ArrayBuffer).toString())
      } catch (error) {
        this.reply(socket, { type: 'error', payload: { code: 'protocol.invalid', message: (error as Error).message } })
        return
      }
      this.dispatch(socket, message)
    })
    socket.on('close', () => {
      this.sockets.delete(socket)
      this.socketIps.delete(socket)
      const remaining = (this.ipSocketCounts.get(ip) ?? 1) - 1
      if (remaining <= 0) this.ipSocketCounts.delete(ip)
      else this.ipSocketCounts.set(ip, remaining)
      this.deregister(socket)
    })
    socket.on('error', () => { socket.terminate() })
  }

  /** True while the IP is under a pair-failure block. */
  private pairBlocked(ip: string): boolean {
    return (this.ipPairFailures.get(ip)?.blockedUntil ?? 0) > Date.now()
  }

  /** Count one failed `pair` for the source IP; crossing the budget blocks it. */
  private notePairFailure(ip: string): void {
    const now = Date.now()
    const entry = this.ipPairFailures.get(ip)
    if (entry === undefined || now - entry.windowStart > PAIR_FAILURE_WINDOW_MS) {
      this.ipPairFailures.set(ip, { count: 1, windowStart: now, blockedUntil: 0 })
      return
    }
    entry.count += 1
    if (entry.count >= PAIR_FAILURE_LIMIT) {
      entry.count = 0
      entry.blockedUntil = now + PAIR_BLOCK_MS
    }
  }

  /** Record activity so the heartbeat reaper can identify silent peers. */
  private touch(socket: WebSocket): void {
    this.lastSeen.set(socket, Date.now())
  }

  /** Terminate and deregister any connection silent past the timeout; fail expired pending requests. */
  private reap(): void {
    const now = Date.now()
    for (const [socket, seen] of this.lastSeen) {
      if (now - seen <= HEARTBEAT_TIMEOUT_MS) continue
      this.deregister(socket)
      socket.terminate()
    }
    for (const [id, pending] of this.pending) {
      if (now <= pending.expiresAt) continue
      this.pending.delete(id)
      this.reply(pending.socket, { id, type: 'error', payload: { code: 'request.timeout', message: 'device did not answer' } })
    }
  }

  /** Remove a socket from every registry (devices, pending, sessionSockets, lastSeen). */
  private deregister(socket: WebSocket): void {
    for (const [deviceId, connection] of this.devices) {
      if (connection.socket !== socket) continue
      this.devices.delete(deviceId)
      // The device is gone: fail every request awaiting its reply so the app
      // does not hang until the pending TTL.
      for (const [id, pending] of this.pending) {
        if (pending.deviceId !== deviceId) continue
        this.pending.delete(id)
        this.reply(pending.socket, { id, type: 'error', payload: { code: 'device.offline', message: 'device not connected' } })
      }
    }
    for (const [id, pending] of this.pending) {
      if (pending.socket === socket) this.pending.delete(id)
    }
    for (const [token, bound] of this.sessionSockets) {
      if (bound === socket) this.sessionSockets.delete(token)
    }
    this.lastSeen.delete(socket)
  }

  /** The deviceId owning a socket, or undefined when the socket is not a device. */
  private deviceIdOf(socket: WebSocket): string | undefined {
    for (const [deviceId, connection] of this.devices) {
      if (connection.socket === socket) return deviceId
    }
    return undefined
  }

  private dispatch(socket: WebSocket, message: Envelope): void {
    switch (message.type) {
      case 'hello': {
        const deviceId = message.deviceId
        const secret = (message.payload as { deviceSecret?: unknown }).deviceSecret
        if (typeof deviceId !== 'string' || typeof secret !== 'string') {
          this.log(`auth failed for device ${String(deviceId)}`)
          this.reply(socket, { type: 'error', payload: { code: 'auth.failed', message: 'bad device secret' } })
          socket.close()
          return
        }
        const known = this.deviceSecrets.get(deviceId)
        if (known !== undefined) {
          if (!secretsEqual(secret, known)) {
            this.log(`auth failed for device ${deviceId}`)
            this.reply(socket, { type: 'error', payload: { code: 'auth.failed', message: 'bad device secret' } })
            socket.close()
            return
          }
        } else if (!this.allowAutoRegister) {
          this.log(`auth failed for device ${deviceId}`)
          this.reply(socket, { type: 'error', payload: { code: 'auth.failed', message: 'bad device secret' } })
          socket.close()
          return
        } else if (this.deviceSecrets.size >= MAX_DEVICES) {
          this.log(`auth rejected for device ${deviceId}: device registry is full`)
          this.reply(socket, { type: 'error', payload: { code: 'auth.failed', message: 'bad device secret' } })
          socket.close()
          return
        } else {
          this.deviceSecrets.set(deviceId, secret)
        }
        const previous = this.devices.get(deviceId)
        if (previous !== undefined && previous.socket !== socket) {
          this.reply(previous.socket, { type: 'error', payload: { code: 'device.replaced', message: 're-registered elsewhere' } })
          previous.socket.close()
        }
        this.devices.set(deviceId, { socket, name: deviceId })
        this.log(`device ${deviceId} registered${known === undefined ? ' (auto-registered)' : ''}`)
        // The relay mints a fresh pairing code for every (re)registration and
        // hands it to the device, which displays it to the user.
        const { code, expiresAt } = this.pairings.issue(deviceId)
        this.reply(socket, { type: 'pairing.issue', deviceId, payload: { code, expiresAt } })
        break
      }
      case 'pair': {
        // 6-digit codes are brute-forceable; budget failures per source IP.
        const ip = this.socketIps.get(socket) ?? 'unknown'
        if (this.pairBlocked(ip)) {
          this.reply(socket, { type: 'error', payload: { code: 'pair.blocked', message: 'too many failed pairing attempts; try again later' } })
          socket.close()
          return
        }
        const { pairingCode } = message.payload as { pairingCode: string }
        const deviceId = this.pairings.verify(pairingCode)
        if (deviceId === undefined) {
          this.log('pair rejected: bad or expired pairing code')
          this.notePairFailure(ip)
          this.reply(socket, { type: 'error', payload: { code: 'pair.invalid', message: 'bad or expired pairing code' } })
          return
        }
        this.pairings.consume(pairingCode)
        this.ipPairFailures.delete(ip)
        if (this.sessions.list(deviceId).length >= MAX_SESSIONS_PER_DEVICE) {
          this.reply(socket, { type: 'error', payload: { code: 'sessions.full', message: 'too many sessions for this device' } })
          return
        }
        const connection = this.devices.get(deviceId)
        if (connection === undefined) {
          this.reply(socket, { type: 'error', payload: { code: 'device.offline', message: 'device not connected' } })
          return
        }
        const token = this.sessions.create(deviceId, connection.name)
        this.sessionSockets.set(token, socket)
        this.log(`session paired for device ${deviceId}`)
        this.reply(socket, { type: 'pair-result', deviceId, payload: { token, deviceId, deviceName: connection.name } })
        break
      }
      case 'request': {
        const { token, method, params } = message.payload as { token: string; method: string; params: unknown }
        const target = message.deviceId
        const session = target === undefined ? undefined : this.sessions.resolve(token)
        if (session === undefined || session.deviceId !== target) {
          this.reply(socket, {
            ...(message.id === undefined ? {} : { id: message.id }),
            type: 'error',
            payload: { code: 'auth.failed', message: 'token does not bind this device' },
          })
          return
        }
        const device = this.devices.get(target)
        if (device === undefined) {
          this.reply(socket, {
            ...(message.id === undefined ? {} : { id: message.id }),
            type: 'error',
            payload: { code: 'device.offline', message: 'device not connected' },
          })
          return
        }
        const id = message.id ?? randomUUID()
        this.pending.set(id, { socket, deviceId: target, expiresAt: Date.now() + PENDING_REQUEST_TTL_MS })
        this.reply(device.socket, { type: 'request', id, deviceId: target, payload: { method, params } })
        break
      }
      case 'resume': {
        const token = (message.payload as { token?: unknown }).token
        if (typeof token !== 'string') {
          this.reply(socket, { type: 'error', payload: { code: 'auth.failed', message: 'invalid token' } })
          return
        }
        const session = this.sessions.resolve(token)
        if (session === undefined) {
          this.reply(socket, { type: 'error', payload: { code: 'auth.failed', message: 'invalid token' } })
          return
        }
        this.sessionSockets.set(token, socket)
        this.reply(socket, {
          type: 'pair-result',
          deviceId: session.deviceId,
          payload: { token, deviceId: session.deviceId, deviceName: session.deviceName },
        })
        break
      }
      case 'sessions.list': {
        const deviceId = this.deviceIdOf(socket)
        if (deviceId === undefined) {
          this.reply(socket, {
            ...(message.id === undefined ? {} : { id: message.id }),
            type: 'error',
            payload: { code: 'auth.failed', message: 'device not authenticated' },
          })
          return
        }
        this.reply(socket, {
          ...(message.id === undefined ? {} : { id: message.id }),
          type: 'sessions.list',
          payload: { sessions: this.sessions.list(deviceId) },
        })
        break
      }
      case 'sessions.revoke': {
        const deviceId = this.deviceIdOf(socket)
        const sessionId = (message.payload as { sessionId?: unknown }).sessionId
        if (deviceId === undefined) {
          this.reply(socket, {
            ...(message.id === undefined ? {} : { id: message.id }),
            type: 'error',
            payload: { code: 'auth.failed', message: 'device not authenticated' },
          })
          return
        }
        if (typeof sessionId !== 'string') {
          this.reply(socket, {
            ...(message.id === undefined ? {} : { id: message.id }),
            type: 'error',
            payload: { code: 'payload.invalid', message: 'sessionId must be a string' },
          })
          return
        }
        // A device revokes only its own sessions; foreign tokens stay live.
        const owned = this.sessions.resolve(sessionId)?.deviceId === deviceId
        this.reply(socket, {
          ...(message.id === undefined ? {} : { id: message.id }),
          type: 'sessions.revoke',
          payload: { sessionId, revoked: owned && this.sessions.revoke(sessionId) },
        })
        if (owned) this.sessionSockets.delete(sessionId)
        break
      }
      case 'event': {
        // Device → relay → app: forward to every app session bound to the
        // device. Events are one-way pushes (e.g. chat stream deltas); the
        // relay validates only the event name and passes the payload through.
        const deviceId = this.deviceIdOf(socket)
        if (deviceId === undefined) {
          this.reply(socket, { type: 'error', payload: { code: 'auth.failed', message: 'device not authenticated' } })
          return
        }
        const event = (message.payload as EventPayload).event
        if (typeof event !== 'string') {
          this.reply(socket, { type: 'error', payload: { code: 'payload.invalid', message: 'event must be a string' } })
          return
        }
        const forwarded: Envelope = { type: 'event', payload: message.payload }
        for (const info of this.sessions.list(deviceId)) {
          const bound = this.sessionSockets.get(info.sessionId)
          if (bound !== undefined) this.reply(bound, forwarded)
        }
        break
      }
      case 'response': {
        const id = message.id
        if (id === undefined) return
        const waiting = this.pending.get(id)
        // Only the device the request was routed to may answer it; anything
        // else is a forged reply and is dropped.
        if (waiting === undefined || this.deviceIdOf(socket) !== waiting.deviceId) return
        this.pending.delete(id)
        this.reply(waiting.socket, { type: 'response', id, payload: message.payload })
        break
      }
      case 'error': {
        // Device → relay → app: an error is a terminal reply to a pending
        // request, correlated by the same id as `response`.
        const id = message.id
        if (id === undefined) return
        const waiting = this.pending.get(id)
        if (waiting === undefined || this.deviceIdOf(socket) !== waiting.deviceId) return
        this.pending.delete(id)
        this.reply(waiting.socket, { type: 'error', id, payload: message.payload })
        break
      }
      case 'ping': {
        this.reply(socket, { type: 'pong', payload: {} })
        break
      }
      case 'pong':
        // A pong is itself activity; the reaper's lastSeen already covers it.
        break
      default:
        break
    }
  }

  private reply(socket: WebSocket, message: Envelope): void {
    if (socket.readyState === WebSocket.OPEN) socket.send(serializeMessage(message))
  }

  /** One-line lifecycle log to stderr; never includes secrets or tokens. */
  private log(line: string): void {
    console.error(`[relay] ${line}`)
  }
}
