import { afterEach, describe, expect, it } from 'vitest'
import { mkdtemp, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
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

function connect(relay: RelayServer): WebSocket {
  return new WebSocket(`ws://127.0.0.1:${relay.port}`)
}

describe('relay session persistence', () => {
  let dir: string | undefined
  afterEach(async () => {
    if (dir !== undefined) await rm(dir, { recursive: true, force: true })
    dir = undefined
  })

  it('survives a relay restart when a data dir is configured', async () => {
    dir = await mkdtemp(join(tmpdir(), 'dsh-relay-'))
    const first = new RelayServer({ port: 0, requireTls: false, deviceSecrets: { 'my-pc': 's' }, dataDir: dir })
    await first.start()
    const device = connect(first)
    await new Promise<void>((resolve) => { device.on('open', () => { resolve() }) })
    device.send(serializeMessage({ type: 'hello', deviceId: 'my-pc', payload: { deviceSecret: 's' } }))
    const issue = await nextMessage(device, message => message.type === 'pairing.issue')
    const app = connect(first)
    await new Promise<void>((resolve) => { app.on('open', () => { resolve() }) })
    app.send(serializeMessage({ type: 'pair', payload: { pairingCode: (issue.payload as { code: string }).code } }))
    const result = await nextMessage(app, message => message.type === 'pair-result')
    const token = (result.payload as { token: string }).token
    app.close()
    device.close()
    await first.close()

    const second = new RelayServer({ port: 0, requireTls: false, deviceSecrets: { 'my-pc': 's' }, dataDir: dir })
    await second.start()
    const again = connect(second)
    await new Promise<void>((resolve) => { again.on('open', () => { resolve() }) })
    again.send(serializeMessage({ type: 'resume', payload: { token } }))
    const resumed = await nextMessage(again, message => message.type === 'pair-result')
    expect((resumed.payload as { token: string }).token).toBe(token)
    again.close()
    await second.close()
  })
})
