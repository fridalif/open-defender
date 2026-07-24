# open-defender agent — message reference

What the agent (`open-defender/pkg/connector`) sends and what it expects back.

Transport: a single WebSocket to `exporter.endpoint_address`. Every frame is a
JSON `Envelope` encrypted end to end (RSA-OAEP/SHA-256 for the AES key,
AES-256-GCM for the body, frame layout `[RSA(aes_key)][12-byte nonce][ciphertext]`).

---

## 1. Keys and identity

| | |
|---|---|
| Agent key pair | RSA-2048, generated in `connect()` **on every session**, never persisted |
| Server key | `exporter.endpoint_rsa_public_key`, base64 PKCS#1, from the downloaded `config.yaml` |
| Identity | `exporter.user_id` + `exporter.config_id`, sent in every envelope |
| Agent → server | encrypted with the server key |
| Server → agent | encrypted with the session public key handed over in `system/hello` |

Because the key pair is per session, a reconnect makes every message from the
previous session undecryptable — there is no long-lived agent secret on disk.

> The agent is **not authenticated**: `user_id` and `config_id` are identifiers,
> not secrets. Anyone holding a copy of `config.yaml` can impersonate this agent.
> See TODO.md, "Аутентификация агента".

---

## 2. Sent by the agent

### 2.1 `system/hello` — opens the session

```json
{
  "version": 2,
  "task_id": 0,
  "service": "system",
  "operation": "hello",
  "configuration_id": "<exporter.config_id>",
  "user_id": "<exporter.user_id>",
  "payload": {
    "public_key": "<base64 PKCS#1 of the session public key>",
    "agent_version": "v1.3.0"
  }
}
```

**Expects:** `config/set_config` within 30 s. Anything else aborts the session.

### 2.2 `system/ack` — result of a task

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

`status` is `error` with a filled `error` when the configuration could not be
parsed, failed validation or could not be written to disk. `task_id` mirrors the
request; it is `0` for the handshake.

**Expects:** nothing.

### 2.3 `config/config` — answer to `get_config`

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

The body is the running `config.yaml` serialised to JSON. The JSON keys equal
the YAML keys (`pkg/config/model.go` carries both `yaml` and `json` tags), which
is what makes the round trip work at all.

**Expects:** nothing.

### 2.4 `alert/raised` — a security event

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

One event per envelope. **Expects:** nothing — delivery is at-most-once, there
is no acknowledgement and no resend.

#### Event sources

| `source` | Raised when | Extra fields |
|---|---|---|
| `ssh_monitor` | `tries` failed SSH logins from one ip within `window_seconds` | `details.engine`, `details.source` |
| `web_brute_monitor` | same, login pages of the web server | same |
| `web_recon_monitor` | same, requests for paths that are not there | same |
| `database_monitor` | same, failed database logins | same |
| `network_antirecon` | eBPF sees a port scan or a hit on a blacklisted port | — |
| `resource_monitor` | cpu / ram / traffic / disk crossed a limit | `severity` (`warning` or `alert`), `details.metric`, `details.value`, `details.unit`, `details.limit` |
| `ip_ban` | an ip was actually banned by the firewall | — |

`severity` is only ever set for `resource_monitor`. Severity levels for the
dashboard are assigned by the connector, not by the agent.

---

## 3. Received by the agent

### 3.1 `config/set_config`

```json
{
  "version": 2,
  "task_id": 42,
  "service": "config",
  "operation": "set_config",
  "payload": { "config": { ... } }
}
```

Handling, in order:

1. Decode into a `config.New()` base, so keys missing from the payload keep the
   agent's own defaults instead of becoming zero values.
2. **Overwrite `exporter` with the local one.** The dashboard stores an exporter
   section that is empty until a `config.yaml` is downloaded, so applying it
   verbatim would erase the endpoint address and key and strand the agent.
3. **Union `ip_whitelist` with the machine's own addresses.** A dashboard
   configuration starts with an empty whitelist; applying it verbatim would let
   a blocker-mode monitor ban the host itself.
4. `Validate()`. On failure nothing is written and the ack carries `status: "error"`.
5. Compare with the running configuration. If equal — ack `ok`, nothing else
   happens. This is what stops the handshake from restarting the agent on every
   reconnect.
6. Otherwise write `config.yaml`, send the ack, then request a restart.

**Replies:** `system/ack`.

### 3.2 `config/get_config`

```json
{
  "version": 2,
  "task_id": 42,
  "service": "config",
  "operation": "get_config",
  "payload": {}
}
```

**Replies:** `config/config` carrying the running configuration.

### 3.3 Anything else

Logged and ignored; the session stays open.

---

## 4. Restart on a new configuration

A configuration that arrived **from the server** and actually differs from the
running one restarts the monitors through the context:

```
connector.applyConfig()   writes config.yaml
connector.requestRestart()  signals monitorHub.restart, then cancel()
        │
        ▼
ctx cancelled -> every monitor, the eBPF program and the connector itself stop
        │
monitorHub.runCycle() returns, wg.Wait() has drained
        │
monitorHub.RunMonitoring() sees the restart signal
        │  reloads config.yaml from disk
        │  builds a fresh ctx/cancel and WaitGroup
        ▼
runCycle() starts every monitor and a new connector session
```

The connector never writes the shared `*config.Config` itself — it only writes
the file. The reload happens in `RunMonitoring` after every monitor has stopped,
so nothing reads the struct while it is being replaced.

A restart means a new session: new RSA key pair, new `system/hello`.

---

## 5. Timings and limits

| | Value | Notes |
|---|---|---|
| Dial timeout | 15 s | |
| Handshake read budget | 30 s | per message |
| Read deadline | 90 s | refreshed by every server ping |
| Write deadline | 15 s | |
| Max frame | 1 MB | `SetReadLimit` |
| Reconnect backoff | 5 s, +10 s per failure, capped at 100 s | reset after a successful connect |
| Export queue | 1024 envelopes | full queue drops events, monitors never block |

The server pings every 30 s and drops the session after 75 s without a pong. The
agent answers pings from its ping handler, so `readLoop` must keep running for
the session to survive.

---

## 6. Failure behaviour

| Situation | What the agent does |
|---|---|
| Endpoint unreachable | retries with backoff, forever |
| Bad `endpoint_rsa_public_key` | logs and retries; never connects until the config is fixed |
| Handshake returns something other than `set_config` | closes and retries |
| Config in the payload is invalid | acks with `status: "error"`, keeps running the old config |
| Server closes the connection | `serve()` returns, session restarts from `connect()` |
| Send channel closed | cancels the root context and stops the agent |
| `exporter.enabled: false` | the connector is never started, events are not queued |
