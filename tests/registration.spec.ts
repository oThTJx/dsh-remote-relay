import { afterEach, describe, expect, it } from 'vitest'
import WebSocket from 'ws'
import { RelayServer } from '../src/index.ts'
import { parseMessage, serializeMessage, type Envelope } from '@firefly0621/dsh-remote-protocol'

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

describe('relay device registration', () => {
  let relay: RelayServer | undefined

  afterEach(async () => {
    await relay?.close()
    relay = undefined
  })

  async function startRelay(deviceSecrets: Record<string, string>): Promise<RelayServer> {
    relay = new RelayServer({
      port: 0,
      requireTls: false,
      deviceSecrets,
    })
    await relay.start()
    return relay
  }

  function connect(relay: RelayServer): WebSocket {
    return new WebSocket(`ws://127.0.0.1:${relay.port}`)
  }

  it('accepts a device with a valid secret and registers it', async () => {
    const server = await startRelay({ 'my-pc': 'secret-1' })
    const socket = connect(server)
    await new Promise<void>((resolve) => { socket.on('open', () => { resolve() }) })
    socket.send(serializeMessage({ type: 'hello', deviceId: 'my-pc', payload: { deviceSecret: 'secret-1' } }))

    const reply = await nextMessage(socket)
    expect(reply.type).toBe('pairing.issue')
    expect(server.deviceCount()).toBe(1)
    socket.close()
  })

  it('rejects a device with a bad secret', async () => {
    const server = await startRelay({ 'my-pc': 'secret-1' })
    const socket = connect(server)
    await new Promise<void>((resolve) => { socket.on('open', () => { resolve() }) })
    socket.send(serializeMessage({ type: 'hello', deviceId: 'my-pc', payload: { deviceSecret: 'wrong' } }))

    const reply = await nextMessage(socket)
    expect(reply.type).toBe('error')
    expect((reply.payload as { code: string }).code).toBe('auth.failed')
    expect(server.deviceCount()).toBe(0)
  })

  it('replaces an existing device connection on re-registration', async () => {
    const server = await startRelay({ 'my-pc': 'secret-1' })
    const first = connect(server)
    await new Promise<void>((resolve) => { first.on('open', () => { resolve() }) })
    first.send(serializeMessage({ type: 'hello', deviceId: 'my-pc', payload: { deviceSecret: 'secret-1' } }))
    await nextMessage(first)

    const second = connect(server)
    await new Promise<void>((resolve) => { second.on('open', () => { resolve() }) })
    second.send(serializeMessage({ type: 'hello', deviceId: 'my-pc', payload: { deviceSecret: 'secret-1' } }))

    const replaced = await nextMessage(first)
    expect(replaced.type).toBe('error')
    expect((replaced.payload as { code: string }).code).toBe('device.replaced')
    expect(server.deviceCount()).toBe(1)
  })

  it('auto-registers an unknown device when allowAutoRegister is on', async () => {
    relay = new RelayServer({ port: 0, requireTls: false, deviceSecrets: {}, allowAutoRegister: true })
    await relay.start()
    const socket = connect(relay)
    await new Promise<void>((resolve) => { socket.on('open', () => { resolve() }) })
    socket.send(serializeMessage({ type: 'hello', deviceId: 'new-device', payload: { deviceSecret: 's3cret' } }))

    const reply = await nextMessage(socket)
    expect(reply.type).toBe('pairing.issue')
    expect(relay.deviceCount()).toBe(1)
    socket.close()
  })

  it('still rejects an unknown device when auto-register is off', async () => {
    const server = await startRelay({})
    const socket = connect(server)
    await new Promise<void>((resolve) => { socket.on('open', () => { resolve() }) })
    socket.send(serializeMessage({ type: 'hello', deviceId: 'ghost', payload: { deviceSecret: 'x' } }))

    const reply = await nextMessage(socket)
    expect(reply.type).toBe('error')
    expect((reply.payload as { code: string }).code).toBe('auth.failed')
    expect(server.deviceCount()).toBe(0)
    socket.close()
  })
})
