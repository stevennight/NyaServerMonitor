# NyaServerMonitor

一个面向自有服务器的主节点/子节点服务监控初版。主节点负责管理员登录、节点生命周期、指标历史和面板展示；子节点主动采集本机状态并上报。

## 架构

```text
浏览器 -> controller -> SQLite
                  ^
                  |
          HTTPS/HTTP POST report
          WSS control channel
                  |
              node agent
```

子节点没有监听管理端口。node 只主动连接主节点：指标历史仍通过签名 HTTP 上报，node WebSocket 另外承载心跳、实时网络遥测、更新状态和已签名 node 更新包；管理员监控页通过认证 SSE 接收实时遥测。主节点不能通过本项目向子节点发送 shell、脚本、任意配置或任意命令；健康检查配置保存在子节点本地。

初版已包含：

- CPU 使用率、系统负载、内存、Swap、物理磁盘、网络接口、运行时间、进程数。
- 子节点本地 HTTP、TCP、ICMP ping、TLS 健康检查及延迟、丢包率、证书到期时间和错误摘要。
- 节点注册、长期 token 展示、显式 token 轮换、撤销、恢复、在线/离线判断。
- 节点出口 IP（以上报连接来源为准）和本机网卡 IP 展示；出口 IP、国家/地区支持人工覆盖，人工值不会被后续上报覆盖，清空后恢复自动值。
- 公网出口 IP 变化时仅识别一次国家/地区；GeoIP 地址可通过 `NYASM_GEOIP_URL` 或 `--geoip-url` 配置，默认使用 `https://ipwho.is/{ip}`。
- WebSocket 控制通道和 Ed25519 签名 node 更新，固定 systemd updater 原子替换并重启 node。
- HMAC 请求签名、时间窗口、nonce 防重放、凭据哈希存储、严格 JSON 白名单和报告大小限制。
- 管理员 PBKDF2 密码哈希、登录限速、可选 TOTP、审计日志。
- SQLite 指标历史、自动清理、时间桶降采样、活动告警和嵌入式中文面板。

## 本地运行

需要 Go 1.26。首次初始化主节点：

```powershell
$env:GOCACHE = "D:\Projects\Self\Software\NyaServerMonitor\.gocache"
go run ./cmd/controller --listen :8080 --data ./data
```

访问 `http://127.0.0.1:8080`，创建管理员后，在“管理后台”中的“节点管理”页面创建节点。创建响应会提供安装命令；在目标 Linux 节点上以 sudo-capable 用户执行即可自动下载探针、写入配置、安装 systemd 服务和固定 updater 并启动。节点详情的“生成安装命令”只读取既有 token，不会隐式轮换；“轮换凭据”仍是单独的安全操作。

也可以使用创建响应中的环境文件手动部署：

```powershell
$env:NYASM_CONTROLLER = "http://127.0.0.1:8080"
$env:NYASM_NODE_ID = "node_xxx"
$env:NYASM_NODE_TOKEN = "<一次性 token>"
go run ./cmd/node
```

安装命令只在管理员登录后的创建、安装命令查看或凭据轮换响应中出现。`/install.sh`、`/downloads/nyasm-node` 和签名清单是公开下载端点，但不包含任何节点 token；生产环境必须使用 HTTPS。controller 默认从 `/usr/local/bin/nyasm-node` 提供 node 二进制，签名更新还要求 `NYASM_NODE_BINARY_DIR` 中存在两种目标架构、manifest、manifest 签名、公钥标识和二进制签名文件。

生产环境应使用 HTTPS。HTTP 只允许本机回环地址；`--insecure-skip-verify` 仅作为显式开发选项，不能用于生产。探针安装脚本当前仍以 root 安装并运行主 systemd 服务，这是为了完整读取进程信息并使用 ICMP；更新由固定的 root updater service 执行，服务没有远程执行能力，且保留了 systemd 文件系统和权限限制。

首页默认是公开状态页，不要求登录。公开页展示管理员配置的节点名称、地区、分组、标签、在线/离线状态、CPU/内存/磁盘百分比、探针版本和服务检查汇总；节点详情弹窗还提供不含 IP、主机名、网卡名或检查目标的聚合历史图表。管理员登录后，根路径仍然是监控首页，会显示完整节点状态、IP 和详细指标；节点创建、凭据轮换、撤销/恢复及审计日志位于 `/admin` 管理后台。

节点详情中的“出口 IP”是 controller 从节点主动上报连接看到的来源地址，通常代表节点的公网出口地址；节点本机采集的网卡 IP 单独展示，可能是内网地址。若部署了反向代理，controller 看到的地址可能是代理地址，此时可在节点编辑中填写人工 IP 覆盖。人工国家/地区覆盖同样只有在管理员清空后才会恢复自动识别。

未登录状态下成功返回的数据只有公开状态、公开节点聚合指标和初始化状态。除 `GET /api/public/dashboard`、`GET /api/public/nodes/{id}/metrics`、`GET /api/setup/status`、登录/初始化及子节点报告接口外，所有 API（包括私有指标、告警和通知渠道接口）都要求管理员会话；直接访问 `/admin` 未登录时只显示登录表单，不加载私有数据。

公开状态页仍会暴露资产数量、节点名称和可用性，节点名称不要包含域名、IP、机房、业务密钥或其他内部信息。若监控面板不应被互联网访问，应在反向代理、VPN 或防火墙层限制访问；公开页的 `noindex` 和短缓存不能替代访问控制。

子节点健康检查文件示例：

```json
[
  {
    "id": "homepage",
    "name": "Homepage",
    "type": "http",
    "target": "https://example.com",
    "timeout_seconds": 5,
    "expected_status": 200
  },
  {
    "id": "database",
    "name": "Database",
    "type": "tcp",
    "target": "127.0.0.1:5432",
    "timeout_seconds": 3
  },
  {
    "id": "gateway-ping",
    "name": "Gateway ping",
    "type": "ping",
    "target": "1.1.1.1",
    "timeout_seconds": 2,
    "attempts": 3
  },
  {
    "id": "certificate",
    "name": "Public certificate",
    "type": "tls",
    "target": "https://example.com",
    "timeout_seconds": 5
  }
]
```

探针支持 `http`、`tcp`、`ping` 和 `tls`，不会执行命令，不会解析或执行检查配置中的脚本。`ping` 使用 ICMP echo，默认 3 次并统计丢包率；非 root 用户需要系统允许非特权 ICMP（例如 Linux 的 `net.ipv4.ping_group_range`），否则该检查会报告为不可用。`tls` 会执行 TLS 握手并记录证书指纹、到期时间和版本，不上传证书内容。

告警规则在管理后台的“告警管理”中维护。默认包含节点离线、服务失败、CPU/内存/磁盘阈值、延迟、丢包和 TLS 证书告警。通知渠道的目标和密钥使用 `NYASM_NOTIFICATION_KEY` 加密保存；未配置该变量时仍会记录告警事件，但不能创建通知渠道。

国家/地区识别由 controller 在有效展示 IP 变化时异步调用配置的 GeoIP 服务，并把最后一次识别过的 IP 写入数据库；同一 IP 的普通心跳和报告不会重复调用。GeoIP 服务会收到节点公网 IP；如不希望使用外部服务，可启动时传入 `--geoip-url ""`，也可以配置自己的兼容接口。

## 数据库选择

当前 controller 使用 SQLite，数据库位于数据目录中的 `nyasm.db`，并通过单写连接、忙等待、指标保留策略和时间桶降采样控制并发与查询返回量。对于单实例、自有服务器监控和几十到数百个节点，这比额外维护 PostgreSQL 更简单可靠。只有在需要 controller 多副本、多个写入进程、很高的指标写入量或集中式数据库运维时，才建议迁移 PostgreSQL；当前数据访问集中在 `internal/controller/store`，后续可以替换存储实现。

## Docker 主节点

部署配置位于 `deploy/docker`，不需要额外指定 `--env-file` 或 `-f`。数据使用项目根目录的 `./data` bind mount，迁移时直接复制项目根目录的 `data` 即可。

```bash
cd deploy/docker
cp .env.example .env
# 编辑 .env，至少设置 NYASM_PUBLIC_URL；通知功能需要设置 NYASM_NOTIFICATION_KEY。
docker compose up -d --build
```

更新已发布的 GHCR 镜像时，把 `.env` 中的 `NYASM_IMAGE` 和 `NYASM_VERSION` 改为对应版本，然后执行：

```bash
cd deploy/docker
docker compose pull
docker compose up -d
```

主节点容器会以只读根文件系统运行，只有项目根目录的 `./data` 可写；容器启动入口会先修正该目录权限，再降权为专用 `nyasm` 用户运行 controller。不要给主节点挂载 Docker socket，不要把宿主机根目录、SSH key 或任何控制面凭据挂进容器。

如果已有旧 named volume，需要迁移一次：先停止 compose，使用 `docker volume ls` 找到旧卷，再将旧卷内容复制到项目根目录 `data`，之后启动新的 compose 配置。旧版本产生的 `deploy/docker/data` 也不要与新的根目录 `data` 混用。新的配置不会再创建 named volume。

反向代理可使用 [deploy/caddy/Caddyfile](deploy/caddy/Caddyfile)，生产环境必须使用 HTTPS。

## CI 与发布

GitHub Actions 位于 `.github/workflows`：PR 和 `main`/`master` push 会执行 gofmt、Go 测试、race 测试、vet、Linux amd64/arm64 构建、Compose 校验和 Docker 构建。

推送 `v*` 标签会创建 GitHub Release，发布 controller/node 的 Linux amd64/arm64 二进制、签名 manifest、每架构 node 二进制签名和 SHA256 校验文件，并将包含签名清单和两种 node 二进制的 controller 镜像推送到 GHCR。CI 需要配置 `NYASM_UPDATE_SIGNING_KEY` 和对应的 `NYASM_UPDATE_PUBLIC_KEY` secrets；公钥编译进 controller/node，私钥只在 CI 签名步骤使用。镜像内置 `NYASM_NODE_BINARY_DIR`，所以 amd64 controller 可以为 arm64 子节点提供正确的探针二进制。

## 安全边界

报告请求使用以下签名串：

```text
METHOD
PATH
TIMESTAMP
NONCE
SHA256(BODY)
```

签名密钥是 token 的 SHA-256 派生值，数据库保存派生值；如果配置 `NYASM_NODE_TOKEN_KEY`，还会保存 AES-GCM 加密 token，用于管理员重新生成安装命令。数据库和 key 都必须作为机密备份；旧数据库只有哈希，无法恢复旧 token，迁移后需要显式轮换一次。token 轮换后旧 token 立即失效；撤销节点后报告和 WebSocket 都会被拒绝。主节点收到的报告和实时遥测字段都有固定 Go 结构、大小限制和时间校验，未知报告字段、过大数组、异常数值和过期请求都会被拒绝。

主控更新流程是固定且单向授权的：管理员请求某个版本后，controller 通过 node 主动建立的 WebSocket 下发版本、manifest、manifest 签名和公钥标识；node 先验证 Ed25519 签名、版本、当前平台、SHA256 和文件大小，再写入受保护的更新请求文件。固定的 `nyasm-node-update.path` 只会调用固定的 `nyasm-node update`，下载固定 controller 路径的 gzip 二进制，完成校验后原子替换 `/usr/local/bin/nyasm-node` 并重启固定的 `nyasm-node` 服务。控制消息没有 shell、脚本、任意 URL、任意路径、配置或回滚字段。

WebSocket 不是报告的唯一通道：指标历史仍走 `POST /api/agent/v1/report`，这样报告签名、防重放和 HTTP 限制保持不变；node WebSocket 以默认 2 秒间隔发送轻量网络遥测，controller 只在内存中保留最新值并通过认证的 `GET /api/telemetry/stream` SSE 推送给管理员页面。node 始终主动出站连接，主控不需要访问 node 的 SSH、HTTP 或管理端口。

详细边界见 [docs/security.md](docs/security.md)。

## 验证

```powershell
$env:GOCACHE = "D:\Projects\Self\Software\NyaServerMonitor\.gocache"
go test ./...
go build ./cmd/controller ./cmd/node
```

节点的配置只走主动上报，主节点宕机期间探针会持续重试；主节点恢复后无需接受任何来自主节点的执行指令即可继续工作。
