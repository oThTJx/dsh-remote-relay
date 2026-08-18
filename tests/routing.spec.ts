import { afterEach, describe, expect, it } from 'vitest'
import WebSocket from 'ws'
import { RelayServer } from '../src/index.ts'
import { parseMessage, serializeMessage, type Envelope } from '@firefly0621/dsh-remote-protocol'

/** Resolve with the next parsed message matching `match`; reject on transport error. */
function nextMessage(socket: WebSocket, match: (message: Envelope) => boolean): Promise<Envelope> {
  return new Promise<Envelope>((resolve, reject) => {
    const handler = (data: unknown): void => {
      let message: Envelope
      try {
        message = parseMessage(Buffer.from(data as ArrayBuffer).toString())
      } catch (error) {
        reject(error instanceof Error ? error : new Error(String(error)))
        return
      }
      if (match(message)) {
        socket.off('message', handler)
        resolve(message)
      }
    }
    socket.on('message', handler)
    socket.on('error', (error) => { reject(error instanceof Error ? error : new Error(String(error))) })
  })
}

describe('relay request routing', () => {
  let relay: RelayServer | undefined
  afterEach(async () => { await relay?.close(); relay = undefined })

  async function startRelay(): Promise<RelayServer> {
    relay = new RelayServer({ port: 0, requireTls: false, deviceSecrets: { 'my-pc': 's' } })
    await relay.start()
    return relay
  }

  function connect(relay: RelayServer): WebSocket {
    return new WebSocket(`ws://127.0.0.1:${relay.port}`)
  }

  async function pairApp(server: RelayServer, device: WebSocket): Promise<{ app: WebSocket; token: string }> {
    device.send(serializeMessage({ type: 'hello', deviceId: 'my-pc', payload: { deviceSecret: 's' } }))
    const issue = await nextMessage(device, message => message.type === 'pairing.issue')
    const code = (issue.payload as { code: string }).code
    const app = connect(server)
    await new Promise<void>((resolve) => { app.on('open', () => { resolve() }) })
    app.send(serializeMessage({ type: 'pair', payload: { pairingCode: code } }))
    const result = await nextMessage(app, message => message.type === 'pair-result')
    return { app, token: (result.payload as { token: string }).token }
  }

  it('forwards a request to the device and relays the response back', async () => {
    const server = await startRelay()
    const device = connect(server)
    await new Promise<void>((resolve) => { device.on('open', () => { resolve() }) })
    const { app, token } = await pairApp(server, device)

    app.send(serializeMessage({
      type: 'request', id: 'req-1', deviceId: 'my-pc',
      payload: { token, method: 'plugin.list', params: {} },
    }))
    const forwarded = await nextMessage(device, message => message.type === 'request')
    expect(forwarded.id).toBe('req-1')
    expect((forwarded.payload as { method: string }).method).toBe('plugin.list')
    // The forwarded request must not carry the app's session token.
    expect((forwarded.payload as { token?: string }).token).toBeUndefined()

    device.send(serializeMessage({ type: 'response', id: 'req-1', payload: { result: { entries: [] } } }))
    const echoed = await nextMessage(app, message => message.type === 'response')
    expect(echoed.id).toBe('req-1')
    expect((echoed.payload as { result: unknown }).result).toEqual({ entries: [] })
  })

  it('rejects a request whose token does not bind the target device', async () => {
    const server = await startRelay()
    const device = connect(server)
    await new Promise<void>((resolve) => { device.on('open', () => { resolve() }) })
    const { app, token } = await pairApp(server, device)

    app.send(serializeMessage({
      type: 'request', id: 'req-2', deviceId: 'other-pc',
      payload: { token, method: 'plugin.list', params: {} },
    }))
    const error = await nextMessage(app, message => message.type === 'error')
    expect((error.payload as { code: string }).code).toBe('auth.failed')
  })

  it('reports device.offline when the device is gone', async () => {
    const server = await startRelay()
    const device = connect(server)
    await new Promise<void>((resolve) => { device.on('open', () => { resolve() }) })
    const { app, token } = await pairApp(server, device)
    device.close()
    await new Promise<void>((resolve) => { device.on('close', () => { resolve() }) })
    await new Promise(resolve => setTimeout(resolve, 10))

    app.send(serializeMessage({
      type: 'request', id: 'req-3', deviceId: 'my-pc',
      payload: { token, method: 'plugin.list', params: {} },
    }))
    const error = await nextMessage(app, message => message.type === 'error')
    expect((error.payload as { code: string }).code).toBe('device.offline')
  })

  it('resumes a session with its stored token, no new code', async () => {
    const server = await startRelay()
    const device = connect(server)
    await new Promise<void>((resolve) => { device.on('open', () => { resolve() }) })
    const { token } = await pairApp(server, device)

    const again = connect(server)
    await new Promise<void>((resolve) => { again.on('open', () => { resolve() }) })
    again.send(serializeMessage({ type: 'resume', payload: { token } }))
    const result = await nextMessage(again, message => message.type === 'pair-result')
    expect((result.payload as { token: string }).token).toBe(token)
    again.close()
  })

  it('rejects resume with an invalid token', async () => {
    const server = await startRelay()
    const app = connect(server)
    await new Promise<void>((resolve) => { app.on('open', () => { resolve() }) })
    app.send(serializeMessage({ type: 'resume', payload: { token: 'bogus' } }))
    const error = await nextMessage(app, message => message.type === 'error')
    expect((error.payload as { code: string }).code).toBe('auth.failed')
    app.close()
  })

  it('lists and revokes sessions from the device socket', async () => {
    const server = await startRelay()
    const device = connect(server)
    await new Promise<void>((resolve) => { device.on('open', () => { resolve() }) })
    const { token } = await pairApp(server, device)

    device.send(serializeMessage({ type: 'sessions.list', id: 'sl-1', payload: {} }))
    const list = await nextMessage(device, message => message.type === 'sessions.list')
    expect(list.id).toBe('sl-1')
    const sessions = (list.payload as { sessions: Array<{ sessionId: string }> }).sessions
    expect(sessions.map(session => session.sessionId)).toContain(token)

    device.send(serializeMessage({ type: 'sessions.revoke', id: 'sr-1', payload: { sessionId: token } }))
    const revoke = await nextMessage(device, message => message.type === 'sessions.revoke')
    expect(revoke.id).toBe('sr-1')
    expect((revoke.payload as { revoked: boolean }).revoked).toBe(true)

    // The revoked token no longer resumes.
    const again = connect(server)
    await new Promise<void>((resolve) => { again.on('open', () => { resolve() }) })
    again.send(serializeMessage({ type: 'resume', payload: { token } }))
    const error = await nextMessage(again, message => message.type === 'error')
    expect((error.payload as { code: string }).code).toBe('auth.failed')
    again.close()
  })

  it('rejects sessions.list from an unauthenticated socket', async () => {
    const server = await startRelay()
    const stranger = connect(server)
    await new Promise<void>((resolve) => { stranger.on('open', () => { resolve() }) })
    stranger.send(serializeMessage({ type: 'sessions.list', payload: {} }))
    const error = await nextMessage(stranger, message => message.type === 'error')
    expect((error.payload as { code: string }).code).toBe('auth.failed')
    stranger.close()
  })

  it('pushes a device event to every app session bound to the device', async () => {
    const server = await startRelay()
    const device = connect(server)
    await new Promise<void>((resolve) => { device.on('open', () => { resolve() }) })
    const { app, token } = await pairApp(server, device)

    device.send(serializeMessage({
      type: 'event',
      payload: { event: 'chat/chunk', payload: { text: 'hel' } },
    }))
    const pushed = await nextMessage(app, message => message.type === 'event')
    expect(pushed.payload).toEqual({ event: 'chat/chunk', payload: { text: 'hel' } })

    // A resumed session on a fresh socket still receives pushes.
    const resumed = connect(server)
    await new Promise<void>((resolve) => { resumed.on('open', () => { resolve() }) })
    resumed.send(serializeMessage({ type: 'resume', payload: { token } }))
    await nextMessage(resumed, message => message.type === 'pair-result')
    device.send(serializeMessage({
      type: 'event',
      payload: { event: 'chat/done', payload: { text: 'hello' } },
    }))
    const done = await nextMessage(resumed, message => message.type === 'event')
    expect((done.payload as { event: string }).event).toBe('chat/done')

    // The revoked token's old socket stops receiving pushes after revoke.
    device.send(serializeMessage({ type: 'sessions.revoke', id: 'sr-2', payload: { sessionId: token } }))
    await nextMessage(device, message => message.type === 'sessions.revoke')
    let received = false
    app.on('message', () => { received = true })
    device.send(serializeMessage({ type: 'event', payload: { event: 'chat/chunk', payload: { text: 'x' } } }))
    await new Promise<void>((resolve) => { setTimeout(resolve, 100) })
    expect(received).toBe(false)
    resumed.close()
  })

  it('rejects an event without an event name from an unauthenticated socket', async () => {
    const server = await startRelay()
    const stranger = connect(server)
    await new Promise<void>((resolve) => { stranger.on('open', () => { resolve() }) })
    stranger.send(serializeMessage({ type: 'event', payload: { payload: { text: 'x' } } }))
    const error = await nextMessage(stranger, message => message.type === 'error')
    expect((error.payload as { code: string }).code).toBe('auth.failed')
    stranger.close()
  })
})
