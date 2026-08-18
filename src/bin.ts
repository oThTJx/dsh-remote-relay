import { RelayServer } from './index.ts'

const port = Number(process.env.PORT ?? 8787)
const requireTls = process.env.NODE_ENV === 'production'
const allowAutoRegister = process.env.DSH_RELAY_ALLOW_AUTO_REGISTER === '1'
const secretsText = process.env.DSH_RELAY_DEVICE_SECRETS ?? ''
const deviceSecrets: Record<string, string> = {}
for (const pair of secretsText.split(',')) {
  if (pair.length === 0) continue
  const [deviceId, secret, ...rest] = pair.split(':')
  if (deviceId === undefined || secret === undefined || rest.length > 0) {
    throw new Error(`relay: malformed DSH_RELAY_DEVICE_SECRETS entry "${pair}" (expected deviceId:secret)`)
  }
  deviceSecrets[deviceId] = secret
}

const relayConfig: {
  port: number
  requireTls: boolean
  allowAutoRegister: boolean
  deviceSecrets: Record<string, string>
  tlsCert?: string
  tlsKey?: string
} = {
  port,
  requireTls,
  allowAutoRegister,
  deviceSecrets,
}
if (process.env.TLS_CERT !== undefined) relayConfig.tlsCert = process.env.TLS_CERT
if (process.env.TLS_KEY !== undefined) relayConfig.tlsKey = process.env.TLS_KEY

const relay = new RelayServer(relayConfig)
await relay.start()
console.log(`dsh-remote-relay listening on :${relay.port}`)
