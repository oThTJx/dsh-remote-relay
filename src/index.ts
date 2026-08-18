import { createServer as createHttpServer, type Server as HttpServer } from 'node:http'
import { createServer as createHttpsServer, type Server as HttpsServer } from 'node:https'
import { randomUUID } from 'node:crypto'
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
  tlsCert?: string
  tlsKey?: string
}

interface DeviceConnection {
  socket: WebSocket
  name: string
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
  private readonly pending = new Map<string, WebSocket>()
  /** session token → the app socket bound to it (device→app `event` pushes). */
  private readonly sessionSockets = new Map<string, WebSocket>()
  private readonly lastSeen = new Map<WebSocket, number>()
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
    this.wss = new WebSocketServer({ server: http })
    this.wss.on('connection', (socket) => { this.handleConnection(socket) })
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

  private handleConnection(socket: WebSocket): void {
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
      this.deregister(socket)
    })
    socket.on('error', () => { socket.terminate() })
  }

  /** Record activity so the heartbeat reaper can identify silent peers. */
  private touch(socket: WebSocket): void {
    this.lastSeen.set(socket, Date.now())
  }

  /** Terminate and deregister any connection silent past the timeout. */
  private reap(): void {
    const now = Date.now()
    for (const [socket, seen] of this.lastSeen) {
      if (now - seen <= HEARTBEAT_TIMEOUT_MS) continue
      this.deregister(socket)
      socket.terminate()
    }
  }

  /** Remove a socket from every registry (devices, pending, sessionSockets, lastSeen). */
  private deregister(socket: WebSocket): void {
    for (const [deviceId, connection] of this.devices) {
      if (connection.socket === socket) this.devices.delete(deviceId)
    }
    for (const [id, waiting] of this.pending) {
      if (waiting === socket) this.pending.delete(id)
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
        const known = deviceId === undefined ? undefined : this.deviceSecrets.get(deviceId)
        if (typeof deviceId !== 'string' || typeof secret !== 'string' || (secret !== known && !(this.allowAutoRegister && known === undefined))) {
          this.reply(socket, { type: 'error', payload: { code: 'auth.failed', message: 'bad device secret' } })
          socket.close()
          return
        }
        if (known === undefined) this.deviceSecrets.set(deviceId, secret)
        const previous = this.devices.get(deviceId)
        if (previous !== undefined && previous.socket !== socket) {
          this.reply(previous.socket, { type: 'error', payload: { code: 'device.replaced', message: 're-registered elsewhere' } })
          previous.socket.close()
        }
        this.devices.set(deviceId, { socket, name: deviceId })
        // The relay mints a fresh pairing code for every (re)registration and
        // hands it to the device, which displays it to the user.
        const { code, expiresAt } = this.pairings.issue(deviceId)
        this.reply(socket, { type: 'pairing.issue', deviceId, payload: { code, expiresAt } })
        break
      }
      case 'pair': {
        const { pairingCode } = message.payload as { pairingCode: string }
        const deviceId = this.pairings.verify(pairingCode)
        if (deviceId === undefined) {
          this.reply(socket, { type: 'error', payload: { code: 'pair.invalid', message: 'bad or expired pairing code' } })
          return
        }
        this.pairings.consume(pairingCode)
        const connection = this.devices.get(deviceId)
        if (connection === undefined) {
          this.reply(socket, { type: 'error', payload: { code: 'device.offline', message: 'device not connected' } })
          return
        }
        const token = this.sessions.create(deviceId, connection.name)
        this.sessionSockets.set(token, socket)
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
        this.pending.set(id, socket)
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
          this.reply(socket, { type: 'error', payload: { code: 'auth.failed', message: 'device not authenticated' } })
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
          this.reply(socket, { type: 'error', payload: { code: 'auth.failed', message: 'device not authenticated' } })
          return
        }
        if (typeof sessionId !== 'string') {
          this.reply(socket, { type: 'error', payload: { code: 'payload.invalid', message: 'sessionId must be a string' } })
          return
        }
        this.reply(socket, {
          ...(message.id === undefined ? {} : { id: message.id }),
          type: 'sessions.revoke',
          payload: { sessionId, revoked: this.sessions.revoke(sessionId) },
        })
        this.sessionSockets.delete(sessionId)
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
        if (waiting === undefined) return
        this.pending.delete(id)
        this.reply(waiting, { type: 'response', id, payload: message.payload })
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
}
