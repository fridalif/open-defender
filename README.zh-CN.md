# Open Defender

![coverage](https://img.shields.io/endpoint?url=https://gist.githubusercontent.com/fridalif/7fa26c09b8c489d79bbbaf8d53726345/raw/open-defender-coverage.json)

![open-defender.jpg](./open-defender.webp)

一款用于 Linux 服务器监控和安全审计的开源综合工具。

代理可选择通过端到端加密的 WebSocket 连接将事件导出至 **Light Defender Dashboard**：可在一个位置查看所有服务器的事件，无需逐台登录。该功能默认关闭，且绝非必需。若 `config.yaml` 中没有 `exporter` 部分，代理将完全独立运行，不会连接任何地方；即使启用后仪表板不可访问，也绝不会阻塞检测或封禁。协议参见 [CLIENT.zh-CN.md](./CLIENT.zh-CN.md)，产品页面位于 [light-defender.ru/open-defender](https://light-defender.ru/open-defender)。

目标：

- [x] 服务安装
- [x] SSH 监控（防暴力破解）
- [x] Web 监控（防侦察 + 防暴力破解）
- [x] 数据库监控（防暴力破解）
- [x] 资源监控；发生过载时显示资源占用最高的进程
- [ ] eBPF 监控
  - [x] 网络监控（防侦察）
  - [ ] 命令执行（可封禁特定用户）
  - [ ] 新的内核模块（可封禁）
  - [ ] 新的 Crontab（可封禁）
  - [ ] 新的服务（可封禁）
  - [ ] 在 `.*rc`、`.profile` 及其他文件中新增记录
- [ ] ...
- [ ] 安全审计模式
  - [ ] 弱配置
  - [ ] 弱密码
  - [ ] ...

## 安装

### 快速安装

将适合当前架构的最新版本下载至 `/usr/bin/open-defender`：

```sh
ARCH=$(uname -m)
case "$ARCH" in
  x86_64)        ARCH=amd64 ;;
  i386|i686)     ARCH=386 ;;
  aarch64|arm64) ARCH=arm64 ;;
  armv7l|armv6l) ARCH=arm32 ;;
  *) echo "未知架构：$ARCH"; exit 1 ;;
esac
sudo curl -L -o /usr/bin/open-defender \
  https://github.com/fridalif/open-defender/releases/latest/download/open-defender_$ARCH
sudo chmod +x /usr/bin/open-defender
```

然后将其安装为 systemd 服务并启动：

```sh
sudo open-defender -i
```

服务读取 `/etc/open-defender/config.yaml`；使用 `-t` 检查配置，使用 `-s` 查看已启用的监控器（见下方[使用方法](#使用方法)）。以后可通过 `sudo open-defender -u` 获取新版本。

## 使用方法

```
用法：open-defender [选项]

选项：
  -i, --install    将 open-defender 安装为 systemd 服务并启动
  -u, --update     从最新 GitHub 发行版更新已安装的二进制文件
  -t, --test       检查当前配置后退出
  -s, --status     输出已启用的监控器后退出
  -r, --restart    重启 open-defender 服务
  -h, --help       输出此消息
```

`-t`、`-s` 和 `-h` 无需 root 权限，其他选项需要 root 权限。

### 已启用的监控器 (`-s`)

```sh
open-defender -s
```

```
/etc/open-defender/config.yaml

MONITOR           MODE     ENGINE   SOURCE                   TRIES
ssh_monitor       blocker  syslog   /var/log/auth.log        5 in 300s, ban 900s
database_monitor  logger   journal  postgresql               5 in 300s
resource_monitor  enabled  -        /var/log/open-defender/  cpu 60/90, ram 60/90

disabled: web_recon_monitor, web_brute_monitor
```

保留为 `mode: disabled` 的监控器不会启动，因此只会列在底部。`SOURCE` 是 `syslog` 引擎的日志文件，或 `journal` 与 `docker` 引擎的单元。资源监控器的阈值以 `warning/alert` 显示；值为零的阈值已禁用且不会显示。与 `-t` 一样，配置只会被读取，绝不会被重写。

### 检查配置 (`-t`)

读取 `/etc/open-defender/config.yaml`，一次报告发现的全部问题；若存在任何问题，则以非零状态退出。配置只会被读取，绝不会被重写，因此可安全地在正在运行的安装环境中执行：

```sh
open-defender -t
```

它会检测未知的 `mode` 或 `engine`、无法编译或不含 `(?P<ip>...)` 组的 `pattern`、无法读取的 `log_path`、缺失的 `unit_name`、值为零的 `tries`、`window_seconds` 或 `ban_seconds`、高于 `alert` 的 `warning` 阈值，以及 `ip_whitelist` 中不是地址的条目。保留为 `disabled` 的监控器会被跳过，因为它不会启动。

### 更新 (`-u`)

```sh
sudo open-defender -u
```

最新版本取自仓库中的 [version.txt](./version.txt)，架构则从正在运行的二进制文件获取（`amd64`、`386`、`arm64`、`arm32`）；两者均作为建议值提供：按空行接受建议，输入任何内容则覆盖建议。如果任一值无法确定，程序会直接询问。

随后将从 `https://github.com/fridalif/open-defender/releases/download/<version>/open-defender_<arch>` 获取发行版，停止服务，替换 `/usr/bin/open-defender` 的二进制文件，再重新启动服务。下载发生在停止服务之前；先前的二进制文件会被保留，若新版本无法启动则会恢复。

### 重启 (`-r`)

```sh
sudo open-defender -r
```

## 代理协议

代理与导出器端点通过 WebSocket 交换的消息、信封格式、加密方式及全部操作均记录在 [CLIENT.zh-CN.md](./CLIENT.zh-CN.md) 中。

## 构建

需要 Go 1.25+ 和 C 编译器（`gcc`），因为 SQLite 驱动程序是 cgo 包。

将二进制文件构建到 `build/open-defender`：

```sh
make build
```

### 测试

```sh
make test          # 运行全部测试
make test-verbose  # 同上，并输出每个测试的结果
make test-race     # 在竞态检测器下运行测试
make cover         # 运行测试并输出按函数统计的覆盖率报告
make cover-html    # 同上，然后在浏览器中打开覆盖率报告
make vet           # 运行 go vet
make check         # go vet + 测试
make clean         # 删除构建产物并清除测试缓存
```
