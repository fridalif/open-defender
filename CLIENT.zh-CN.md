# open-defender 代理：消息参考

本文说明代理（`open-defender/pkg/connector`）发送的内容及其期望收到的响应。

传输方式：到 `exporter.endpoint_address` 的单一 WebSocket 连接。每个帧都是端到端加密的 JSON `Envelope`（AES 密钥使用 RSA-OAEP/SHA-256 加密，消息体使用 AES-256-GCM 加密，帧布局为 `[RSA(aes_key)][12-byte nonce][ciphertext]`）。

---

## 1. 密钥与身份

| | |
|---|---|
| 代理密钥对 | RSA-2048，在每个会话的 `connect()` 中生成，**绝不持久化** |
| 服务器密钥 | 来自已下载 `config.yaml` 的 `exporter.endpoint_rsa_public_key`，base64 编码的 PKCS#1 |
| 身份 | `exporter.user_id` + `exporter.config_id`，随每个信封发送 |
| 代理 → 服务器 | 使用服务器密钥加密 |
| 服务器 → 代理 | 使用在 `system/hello` 中交付的会话公钥加密 |

由于密钥对按会话生成，重新连接后上一会话的所有消息都无法解密；磁盘上没有长期有效的代理密钥。

> 代理**未经过身份验证**：`user_id` 和 `config_id` 是标识符而非密钥。任何持有 `config.yaml` 副本的人都可冒充此代理。请参见 TODO.md 中的“Аутентификация агента”。

---

## 2. 消息交换

```text
        代理                                      服务器（仪表板）
          |                                              |
          |  WebSocket dial: exporter.endpoint_address   |
          |--------------------------------------------->|
          |                                              |
  会话 RSA |  system/hello            task_id 0           |
  密钥创建 |  payload.public_key = 会话公钥              |
          |--------------------------------------------->|
          |                                              |
          |           config/set_config   task_id N      |  必须在
          |<---------------------------------------------|  30 秒内到达
          |  system/ack   task_id N   status ok | error  |
          |--------------------------------------------->|
          |                                              |
  ====================== 会话已建立 ======================
          |                                              |
          |  alert/raised   task_id 0   单个事件         |  无确认，
          |--------------------------------------------->|  不重发
          |                                              |
          |           config/get_config   task_id M      |
          |<---------------------------------------------|
          |  config/config   task_id M                   |
          |--------------------------------------------->|
          |                                              |
          |           config/set_config   task_id K      |
          |<---------------------------------------------|
          |  system/ack   task_id K                      |
          |--------------------------------------------->|
          |  配置不同 -> 写入 config.yaml，
          |  重启；新会话、新密钥对
          |                                              |
          |           ping   每 30 秒                    |
          |<---------------------------------------------|
          |  pong                                        |
          |--------------------------------------------->|
          |                                              |
```

双线以上为固定的握手过程：`hello`、`set_config`、`ack`。双线以下顺序自由：监控器一产生告警，代理便推送；同时它会响应服务器发送的任何内容。双向的所有帧都是加密信封；仅方向决定使用哪把密钥（见第 1 节）。

---

## 3. 由代理发送

### 3.1 `system/hello`：开启会话

```json
{
  "version": 2,
  "task_id": 0,
  "service": "system",
  "operation": "hello",
  "configuration_id": "<exporter.config_id>",
  "user_id": "<exporter.user_id>",
  "payload": {
    "public_key": "<会话公钥的 base64 PKCS#1>",
    "agent_version": "v1.3.0"
  }
}
```

**期望：**30 秒内收到 `config/set_config`。其他任何内容都会中止会话。

### 3.2 `system/ack`：任务结果

```json
{
  "version": 2,
  "task_id": 42,
  "service": "system",
  "operation": "ack",
  "configuration_id": "...",
  "user_id": "...",
  "payload": { "status": "ok", "error": "" }
}
```

当配置无法解析、验证失败或无法写入磁盘时，`status` 为 `error`，并填充 `error`。`task_id` 与请求相同；握手时为 `0`。

**期望：**无。

### 3.3 `config/config`：对 `get_config` 的响应

```json
{
  "version": 2,
  "task_id": 42,
  "service": "config",
  "operation": "config",
  "configuration_id": "...",
  "user_id": "...",
  "payload": { "config": { "ssh_monitor": { "mode": "logger", ... }, ... } }
}
```

消息体为序列化为 JSON 的运行中 `config.yaml`。JSON 键与 YAML 键相同（`pkg/config/model.go` 同时带有 `yaml` 和 `json` 标记），因此往返传输得以实现。

**期望：**无。

### 3.4 `alert/raised`：安全事件

```json
{
  "version": 2,
  "task_id": 0,
  "service": "alert",
  "operation": "raised",
  "configuration_id": "...",
  "user_id": "...",
  "payload": {
    "events": [
      {
        "source": "ssh_monitor",
        "ip": "203.0.113.7",
        "message": "ssh_monitor -> found offenders ip 203.0.113.7 while scanning syslog: /var/log/auth.log-sshd",
        "happened_at": "2026-07-24T10:15:00Z",
        "details": { "engine": "syslog", "source": "/var/log/auth.log" }
      }
    ]
  }
}
```

每个信封只包含一个事件。**期望：**无；交付至多一次，没有确认也不会重发。

#### 事件来源

| `source` | 触发条件 | 额外字段 |
|---|---|---|
| `ssh_monitor` | 在 `window_seconds` 内，同一 IP 有 `tries` 次 SSH 登录失败 | `details.engine`、`details.source` |
| `web_brute_monitor` | 同上，但针对 Web 服务器登录页 | 同上 |
| `web_recon_monitor` | 同上，但针对不存在路径的请求 | 同上 |
| `database_monitor` | 同上，但针对数据库登录失败 | 同上 |
| `network_antirecon` | eBPF 发现端口扫描或访问黑名单端口 | 无 |
| `resource_monitor` | CPU / RAM / 流量 / 磁盘越过阈值 | `severity`（`warning` 或 `alert`）、`details.metric`、`details.value`、`details.unit`、`details.limit` |
| `ip_ban` | IP 确实已被防火墙封禁 | 无 |

`severity` 仅会为 `resource_monitor` 设置。仪表板的严重性级别由连接器分配，而非代理。

---

## 4. 由代理接收

### 4.1 `config/set_config`

```json
{
  "version": 2,
  "task_id": 42,
  "service": "config",
  "operation": "set_config",
  "payload": { "config": { ... } }
}
```

按以下顺序处理：

1. 解码至 `config.New()` 基础配置，使载荷中缺少的键保持代理自身的默认值，而不是成为零值。
2. **使用本地值覆盖 `exporter`。** 在下载 `config.yaml` 之前，仪表板保存的 exporter 部分为空；按原样应用会抹去端点地址和密钥，使代理失联。
3. **将 `ip_whitelist` 与本机地址合并。** 仪表板配置开始时白名单为空；按原样应用可能使 blocker 模式的监控器封禁主机自身。
4. 执行 `Validate()`。失败时不写入任何内容，ack 带有 `status: "error"`。
5. 与运行中的配置比较。若相同，则确认 `ok`，不执行其他操作。这样可防止在每次握手重连时重启代理。
6. 否则，写入 `config.yaml`，发送 ack，然后请求重启。

**响应：**`system/ack`。

### 4.2 `config/get_config`

```json
{
  "version": 2,
  "task_id": 42,
  "service": "config",
  "operation": "get_config",
  "payload": {}
}
```

**响应：**携带运行中配置的 `config/config`。

### 4.3 其他所有内容

记录到日志并忽略；会话保持打开。

---

## 5. 收到新配置时重启

从**服务器**到达且确实与运行中配置不同的配置，会通过上下文重启监控器：

```text
connector.applyConfig()      写入 config.yaml
connector.requestRestart()   通知 monitorHub.restart，然后调用 cancel()
        |
        v
上下文已取消 -> 所有监控器、eBPF 程序和连接器本身均停止
        |
monitorHub.runCycle() 返回，wg.Wait() 已完成
        |
monitorHub.RunMonitoring() 发现重启信号
        |  从磁盘重新加载 config.yaml
        |  创建新的 ctx/cancel 和 WaitGroup
        v
runCycle() 启动全部监控器和新的连接器会话
```

连接器绝不会自行写入共享的 `*config.Config`；它只写入文件。在所有监控器停止后，`RunMonitoring` 才重新加载，因此在结构体被替换时没有任何代码会读取它。

重启意味着新会话：新的 RSA 密钥对和新的 `system/hello`。

---

## 6. 时间与限制

| | 值 | 说明 |
|---|---|---|
| 连接超时 | 15 秒 | |
| 握手读取预算 | 30 秒 | 每条消息 |
| 读取截止时间 | 90 秒 | 每次服务器 ping 都会刷新 |
| 写入截止时间 | 15 秒 | |
| 最大帧大小 | 1 MB | `SetReadLimit` |
| 重连退避 | 5 秒；每次失败增加 10 秒，最大 100 秒 | 成功连接后重置 |
| 导出队列 | 1024 个信封 | 队列满时会丢弃事件，监控器绝不阻塞 |

服务器每 30 秒 ping 一次；75 秒未收到 pong 后会断开会话。代理由 ping 处理程序响应 ping，因此 `readLoop` 必须持续运行，会话才能存活。

---

## 7. 故障行为

| 情况 | 代理行为 |
|---|---|
| 端点不可访问 | 永久以退避方式重试 |
| `endpoint_rsa_public_key` 错误 | 记录日志并重试；在配置修复前绝不连接 |
| 握手返回的内容不是 `set_config` | 关闭并重试 |
| 载荷中的配置无效 | 以 `status: "error"` 确认，继续使用旧配置运行 |
| 服务器关闭连接 | `serve()` 返回，会话从 `connect()` 重新开始 |
| 发送通道关闭 | 取消根上下文并停止代理 |
| `exporter.enabled: false` | 连接器永不启动，事件不会入队 |
