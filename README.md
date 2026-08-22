# NyaServerMonitor

一个面向自有服务器的主节点/子节点服务监控初版。主节点负责管理员登录、节点生命周期、指标历史和面板展示；子节点主动采集本机状态并上报。

## 架构

```text
浏览器 -> controller -> SQLite
                  ^
                  |
          HTTPS/HTTP POST report
                  |
              node agent
```

子节点没有监听管理端口，也没有 WebSocket 控制通道。主节点不能通过本项目向子节点发送 shell、脚本、配置或更新命令。健康检查配置保存在子节点本地，主节点只接收检查结果。

初版已包含：

- CPU 使用率、系统负载、内存、Swap、磁盘根分区、网络接口、运行时间、进程数。
- 子节点本地 HTTP/TCP 健康检查及延迟、状态、错误摘要。
- 节点注册、一次性 token 展示、token 轮换、撤销、恢复、在线/离线判断。
- HMAC 请求签名、时间窗口、nonce 防重放、凭据哈希存储、严格 JSON 白名单和报告大小限制。
- 管理员 PBKDF2 密码哈希、登录限速、可选 TOTP、审计日志。
- SQLite 指标历史、自动清理和嵌入式中文面板。

## 本地运行

需要 Go 1.26。首次初始化主节点：

```powershell
$env:GOCACHE = "D:\Projects\Self\Software\NyaServerMonitor\.gocache"
go run ./cmd/controller --listen :8080 --data ./data
```

访问 `http://127.0.0.1:8080`，创建管理员后，在“管理后台”中的“节点管理”页面创建节点。创建响应中的环境文件只展示本次 token；把它写入探针机器后运行：

```powershell
$env:NYASM_CONTROLLER = "http://127.0.0.1:8080"
$env:NYASM_NODE_ID = "node_xxx"
$env:NYASM_NODE_TOKEN = "<一次性 token>"
go run ./cmd/node
```

生产环境应使用 HTTPS。HTTP 只适合本机开发；`--insecure-skip-verify` 仅作为显式开发选项，不能用于生产。

首页默认是公开状态页，不要求登录。公开页只展示管理员配置的节点名称、在线/离线状态、CPU/内存/磁盘百分比和服务检查汇总，不展示 IP、主机名、系统版本、标签分组、网络流量、运行时间、探针版本、检查目标或节点 ID。管理员登录后，根路径仍然是监控首页，会显示完整节点状态、IP 和详细指标；节点创建、凭据轮换、撤销/恢复及审计日志位于 `/admin` 管理后台。

未登录状态下成功返回的数据只有公开状态和初始化状态。除 `GET /api/public/dashboard`、`GET /api/setup/status`、登录/初始化及子节点报告接口外，所有 API 都要求管理员会话；直接访问 `/admin` 未登录时只显示登录表单，不加载私有数据。

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
  }
]
```

探针只支持 `http` 和 `tcp`，不会执行命令，不会解析或执行检查配置中的脚本。

## Docker 主节点

```bash
docker compose --env-file deploy/docker/.env -f deploy/docker/docker-compose.yml up -d
```

复制 `deploy/docker/.env.example` 为 `.env`，至少设置公开 HTTPS URL 和镜像版本。不要给主节点挂载 Docker socket，不要把宿主机根目录、SSH key 或任何控制面凭据挂进容器。

## 安全边界

报告请求使用以下签名串：

```text
METHOD
PATH
TIMESTAMP
NONCE
SHA256(BODY)
```

签名密钥是 token 的 SHA-256 派生值，数据库只保存派生值。token 轮换后旧 token 立即失效；撤销节点后报告会被拒绝。主节点收到的报告字段是固定 Go 结构，未知字段、过大数组、异常数值和过期时间都会被拒绝。

详细边界见 [docs/security.md](docs/security.md)。

## 验证

```powershell
$env:GOCACHE = "D:\Projects\Self\Software\NyaServerMonitor\.gocache"
go test ./...
go build ./cmd/controller ./cmd/node
```

节点的配置只走主动上报，主节点宕机期间探针会持续重试；主节点恢复后无需接受任何来自主节点的执行指令即可继续工作。
