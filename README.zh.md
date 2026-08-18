# @firefly0621/dsh-remote-relay

[English](README.md) | 中文

dsh 远程控制能力的独立 WebSocket 中继。设备（运行 `@firefly0621/dsh-remote-control` 的 dsh 主机）用长期 secret 出站连接；手机 App 用短时效配对码配对；中继在两者之间路由请求/响应消息。NAT 后的电脑无需入站端口——它主动拨出，与 OpenClaw/小龙虾（Claw）手机控制模式一致。

中继是单进程 Node 服务，无 harness 依赖。设备注册与配对码存在内存中、重启即清空；设置 `DSH_RELAY_DATA_DIR` 后 **App 会话持久化**，已配对的手机用存储的 token 恢复，无需重新配对。

## 配置（环境变量）

| 变量 | 默认值 | 含义 |
|---|---|---|
| `PORT` | `8787` | 监听端口 |
| `NODE_ENV` | — | `production` 强制 TLS（拒绝明文 WS） |
| `DSH_RELAY_DEVICE_SECRETS` | — | 逗号分隔的 `deviceId:secret` 对，即设备注册表 |
| `DSH_RELAY_ALLOW_AUTO_REGISTER` | — | `1` 接受未知随机 `deviceId` 的首次 hello 并绑定（插件的零配置模式） |
| `DSH_RELAY_DATA_DIR` | — | 持久化会话存储目录；缺省时会话仅存内存 |
| `TLS_CERT` / `TLS_KEY` | — | PEM 证书/密钥路径；`NODE_ENV=production` 时必填 |

## 部署（VPS 上的 systemd）

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

用 `openssl rand -hex 32` 生成设备密钥，前置真实证书（Let's Encrypt）——生产环境下中继绝不提供明文 WS。

## 安全说明

- **认证分两层**：设备 secret 证明"这是已注册的主机"；配对码证明"手机用户正坐在该主机的键盘前"。中继只在一对已配对 App 与其绑定设备之间转发请求。
- **`DSH_RELAY_ALLOW_AUTO_REGISTER` 先到先得**：未知 `deviceId` 以其首次 hello 携带的 secret 绑定。插件生成的 deviceId 是随机 128 位值，抢占空位无利可图；共享中继请关闭该开关。
- **会话控制权在设备侧**：绑定的设备可以列出（`sessions.list`）和吊销（`sessions.revoke`）其 App 会话；被吊销的 token 无法恢复会话。
- **中继是哑管道**：它从不检查命令载荷、从不持久化消息内容。中继被攻破只暴露路由元数据，而非设置值——但设置读取仍会经过它，因此 TLS 是强制的。
- **配对码**：6 位、10 分钟有效、一次性、最多 5 次错误尝试。设备每次（重新）注册时轮换。
- **心跳**：对端每 30s ping；静默 60s 的连接被断开。

## 协议

定义于 [`@firefly0621/dsh-remote-protocol`](https://github.com/oThTJx/dsh-remote-protocol)——本包只实现中继侧。
