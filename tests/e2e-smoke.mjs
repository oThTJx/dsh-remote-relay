/**
 * End-to-end smoke against the real relay bin: register a device, pair an app
 * with the minted code, and round-trip a request/response.
 *
 * Run: node apps/relay-server/tests/e2e-smoke.mjs  (requires a running relay)
 */
import WebSocket from 'ws'

const RELAY = process.env.RELAY_URL ?? 'ws://127.0.0.1:18787'

function connect() {
  return new Promise((resolve, reject) => {
    const socket = new WebSocket(RELAY)
    socket.on('open', () => resolve(socket))
    socket.on('error', reject)
  })
}

function nextMessage(socket, match) {
  return new Promise((resolve, reject) => {
    const handler = (data) => {
      let message
      try {
        message = JSON.parse(data.toString())
      } catch (error) {
        reject(error)
        return
      }
      if (match(message)) {
        socket.off('message', handler)
        resolve(message)
      }
    }
    socket.on('message', handler)
    socket.on('error', reject)
  })
}

const device = await connect()
device.send(JSON.stringify({ type: 'hello', deviceId: 'my-pc', payload: { deviceSecret: 'test-secret-123' } }))
const issue = await nextMessage(device, (message) => message.type === 'pairing.issue')
console.log('pairing code:', issue.payload.code)

const app = await connect()
app.send(JSON.stringify({ type: 'pair', payload: { pairingCode: issue.payload.code } }))
const pair = await nextMessage(app, (message) => message.type === 'pair-result' || message.type === 'error')
if (pair.type === 'error') throw new Error(`pair failed: ${pair.payload.message}`)
console.log('paired with device:', pair.payload.deviceId)

app.send(JSON.stringify({
  type: 'request',
  id: 'smoke-1',
  deviceId: pair.payload.deviceId,
  payload: { token: pair.payload.token, method: 'plugin.list', params: {} },
}))
const forwarded = await nextMessage(device, (message) => message.type === 'request')
console.log('device received request:', forwarded.payload.method, 'token stripped:', forwarded.payload.token === undefined)

device.send(JSON.stringify({ type: 'response', id: forwarded.id, payload: { result: { entries: [] } } }))
const echoed = await nextMessage(app, (message) => message.type === 'response')
console.log('app received response for:', echoed.id)

device.close()
app.close()
console.log('E2E SMOKE OK')
