import { afterEach, describe, expect, it } from 'vitest'
import WebSocket from 'ws'
import { RelayServer } from '../src/index.ts'
import { PairingStore, SessionStore } from '../src/pairing.ts'
import { parseMessage, serializeMessage, type Envelope } from '@firefly0621/dsh-remote-protocol'
import { PAIRING_CODE_TTL_MS } from '@firefly0621/dsh-remote-protocol'

/** Resolve with the next parsed message on a socket; reject on transport error. */
function nextMessage(socket: WebSocket): Promise<Envelope> {
  return new Promise<Envelope>((resolve, reject) => {
    socket.on('message', (data) => {
      try {
        resolve(parseMessage(Buffer.from(data as ArrayBuffer).toString()))
      } catch (error) {
        reject(error instanceof Error ? error : new Error(String(error)))
      }
    })
    socket.on('error', (error) => { reject(error instanceof Error ? error : new Error(String(error))) })
  })
}

describe('pairing store', () => {
  it('issues a 6-digit code bound to one device', () => {
    const store = new PairingStore()
    const issued = store.issue('my-pc')
    expect(issued.code).toMatch(/^\d{6}$/)
    expect(store.verify(issued.code)).toBe('my-pc')
  })

  it('consumes a code after one use', () => {
    const store = new PairingStore()
    const { code } = store.issue('my-pc')
    expect(store.verify(code)).toBe('my-pc')
    store.consume(code)
    expect(store.verify(code)).toBeUndefined()
  })

  it('invalidates a code after max attempts', () => {
    const store = new PairingStore()
    const { code } = store.issue('my-pc')
    for (let i = 0; i < 5; i += 1) expect(store.verify(code)).toBe('my-pc')
    // The 6th pairing attempt exhausts the per-code attempt budget.
    expect(store.verify(code)).toBeUndefined()
  })

  it('rejects an expired code', () => {
    const store = new PairingStore()
    const { code } = store.issue('my-pc')
    store.advanceClock(PAIRING_CODE_TTL_MS + 1)
    expect(store.verify(code)).toBeUndefined()
  })
})

describe('session store', () => {
  it('creates and resolves a token-bound session', () => {
    const store = new SessionStore()
    const token = store.create('my-pc', 'my-pc')
    expect(token).toMatch(/^[0-9a-f]{64}$/)
    expect(store.resolve(token)).toEqual({ deviceId: 'my-pc', deviceName: 'my-pc', createdAt: expect.any(Number) })
    expect(store.resolve('nope')).toBeUndefined()
  })

  it('lists and revokes sessions per device', () => {
    const store = new SessionStore()
    const token = store.create('my-pc', 'my-pc')
    store.create('other', 'other')
    expect(store.list('my-pc').map(session => session.sessionId)).toEqual([token])
    expect(store.revoke(token)).toBe(true)
    expect(store.list('my-pc')).toEqual([])
    expect(store.revoke(token)).toBe(false)
  })
})

describe('relay pairing flow', () => {
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

  it('pairs an app with a device-issued code', async () => {
    const server = await startRelay()
    const device = connect(server)
    await new Promise<void>((resolve) => { device.on('open', () => { resolve() }) })
    device.send(serializeMessage({ type: 'hello', deviceId: 'my-pc', payload: { deviceSecret: 's' } }))
    const issue = await nextMessage(device)
    const code = (issue.payload as { code: string }).code
    expect(code).toMatch(/^\d{6}$/)

    const app = connect(server)
    await new Promise<void>((resolve) => { app.on('open', () => { resolve() }) })
    app.send(serializeMessage({ type: 'pair', payload: { pairingCode: code } }))
    const result = await nextMessage(app)
    expect(result.type).toBe('pair-result')
    const payload = result.payload as { token: string; deviceId: string; deviceName: string }
    expect(payload.deviceId).toBe('my-pc')
    expect(payload.token).toMatch(/^[0-9a-f]{64}$/)
  })

  it('rejects an invalid pairing code', async () => {
    const server = await startRelay()
    const app = connect(server)
    await new Promise<void>((resolve) => { app.on('open', () => { resolve() }) })
    app.send(serializeMessage({ type: 'pair', payload: { pairingCode: '000000' } }))
    const result = await nextMessage(app)
    expect(result.type).toBe('error')
    expect((result.payload as { code: string }).code).toBe('pair.invalid')
  })
})
