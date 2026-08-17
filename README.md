# @firefly0621/dsh-remote-relay

Standalone WebSocket relay for the dsh remote-control capability. Devices (dsh hosts running `@firefly0621/dsh-remote-control`) connect outbound with a long-lived secret; mobile apps pair with a short-lived code; the relay routes request/response messages between them. The PC behind NAT never needs an inbound port — it dials out, exactly like the OpenClaw/Claw mobile-control pattern.

The relay is a single-process Node service with no harness dependency. It does not persist anything: device registrations, pairing codes, and sessions live in memory and are cleared on restart.

## Configuration (environment variables)

| Variable | Default | Meaning |
|---|---|---|
| `PORT` | `8787` | Listening port |
| `NODE_ENV` | — | `production` requires TLS (refuses plaintext WS) |
| `DSH_RELAY_DEVICE_SECRETS` | — | Comma-separated `deviceId:secret` pairs; the device registry |
| `TLS_CERT` / `TLS_KEY` | — | PEM cert/key paths; required when `NODE_ENV=production` |

## Deployment (systemd on a VPS)

```ini
[Unit]
Description=dsh remote relay
After=network.target

[Service]
WorkingDirectory=/opt/dsh-relay
ExecStart=/usr/bin/node /opt/dsh-relay/lib/bin.js
Environment=NODE_ENV=production
Environment=PORT=8787
Environment=DSH_RELAY_DEVICE_SECRETS=my-pc:CHANGE_ME_LONG_RANDOM
Environment=TLS_CERT=/etc/letsencrypt/live/relay.example.com/fullchain.pem
Environment=TLS_KEY=/etc/letsencrypt/live/relay.example.com/privkey.pem
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
```

Generate the device secret with `openssl rand -hex 32`. Front with a real certificate (Let's Encrypt) — the relay never serves plaintext WS in production.

## Security notes

- **Auth is two-layered**: the device secret proves "this is the registered host"; the pairing code proves "the phone user is at the keyboard of that host". The relay forwards requests only between a paired app and its bound device.
- **The relay is a dumb pipe**: it never inspects command payloads and never persists message content. Compromising the relay exposes routing metadata, not settings values — though settings reads still transit it, so TLS is mandatory.
- **Pairing codes**: 6 digits, 10-minute TTL, one-time use, max 5 wrong attempts. Rotated by the device on every relay (re)registration.
- **Heartbeats**: peers ping every 30s; a silent connection is dropped after 60s.

## Protocol

Defined in [`@firefly0621/dsh-remote-protocol`](../../packages/remote/protocol/README.md) — this package only implements the relay side.
