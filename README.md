# OpenResty WAF

一个适配于任意 OpenResty 的 Web 应用防火墙：通过 Lua 规则接入，自动检测、拦截、阻断并记录流量；内置 Web 管理后台，支持可视化配置拦截规则与接入常见规则库（OWASP CRS 等）。

## 核心特性

- **嵌入式接入**：纯 Lua 组件，挂载到任意 OpenResty 的 `access_by_lua` / `header_filter_by_lua` / `log_by_lua` 阶段，无需重新编译 Nginx。
- **规则热更新**：规则经 Redis 下发，worker 内共享内存缓存 + 版本原子切换，配置变更不中断连接；版本单调校验 + 规则集结构校验（坏规则集拒载），发布历史快照支持一键回滚。
- **完整防护能力**：SQLi / XSS / RCE / LFI / SSRF / 协议异常 / 敏感文件泄露 / 恶意 UA 与扫描器 / 文件上传检测（含超大上传落盘流式检测）；多层编码解码（base64/hex/HTML 实体）抗绕过、HPP 参数污染、IPv6 CIDR、API 安全（敏感端点/GraphQL 内省/XXE）、DLP 响应体敏感数据防泄露。
- **访问控制与限流**：IP / UA / Cookie / Header / URL / Args 黑白名单、CC 防刷（支持 UA/无 Cookie 维度计数）、人机验证（JS 工作量证明，无 JS 的 bot 无法通过）。
- **Bot 管理**：爬虫/客户端指纹规则组（搜索引擎爬虫/客户端库/监控探针），配合触发规则 豁免/挑战/限流/直接拦截 四级策略。
- **自动封禁与处置**：攻击事件一键封禁（临时/永久，时效条目 ip|unix_ts 到期自动解封；支持 IP+UA 维度）、封禁管理页、同 IP 高频攻击自动临时封禁（阈值/窗口/时长可配，白名单豁免）。
- **事件处置闭环**：事件标记误报（计入规则命中率统计）、一键豁免（生成 host+路径豁免规则）、一键封禁、事件/流量 CSV 导出。
- **运维可观测**：引擎心跳在线状态与规则同步状态、实时 QPS 监控（秒级曲线）、告警通知（Webhook/钉钉/企业微信/飞书/邮件，事件风暴/引擎离线，可联动自动回滚最近规则发布）、操作审计日志（谁在何时改了什么）。
- **面板安全加固**：访问 IP 白名单（`ADMIN_ALLOWED_IPS`）、CSRF 双提交校验、安全响应头、登录会话管理与强制下线、Redis 密码不回显。
- **隐私合规**：攻击证据入库前敏感信息脱敏（密码/令牌字段与手机号/身份证等正则打码，字段与正则后台可配）。
- **品牌化**：挑战页标题/公司/联系方式可配置；响应安全头（HSTS/CSP 等）自动加固，移除 Server/X-Powered-By 等泄露头。
- **灵活工作模式**：监控（仅记录）/ 拦截 / 放行，可全局一键切换；检测异常 fail-open，检测耗时 watchdog 超阈值强制放行。
- **Web 管理后台**：仪表盘、规则管理（含在线调试、导入导出、发布历史与回滚）、事件检索与一键封禁、封禁管理、站点管理、账号安全（TOTP 双因子 + 登录防爆破）、版本健康信息。

## 目录结构

```
openresty-waf/
├── plan/                  # 项目计划与调研
├── waf/                   # Lua WAF 引擎（OpenResty 侧）
│   ├── init.lua           #   初始化入口
│   ├── access.lua         #   access_by_lua 检测入口
│   ├── log.lua            #   log_by_lua 日志入口
│   ├── rule_engine/       #   规则引擎（运算符/变量/变换/动作）
│   ├── detectors/         #   检测器（sqli/xss/rce/cc/challenge...）
│   └── ruleset/           #   内置规则集（JSON）
├── admin/                 # 管理后台（Go + Gin + GORM）
├── web/                   # 管理前端（Vue3 + Vite + shadcn/vue）
└── deploy/                # Docker 部署编排
```

## 技术栈

| 端 | 技术 |
|---|---|
| WAF 引擎 | OpenResty + LuaJIT（纯 Lua，lua-resty-core / lua-resty-lock / lua-resty-redis） |
| 管理后台 | Go + Gin + GORM + MySQL/SQLite + Redis |
| 管理前端 | Vue3 + Vite + TypeScript + shadcn/vue + Pinia + ECharts |

## Git 提交规范

提交信息遵循 `type(scope): 中文描述` 格式（已配置全局模板与 commit-msg 校验）：

- type：`feat` / `fix` / `docs` / `style` / `refactor` / `perf` / `test` / `build` / `ci` / `chore` / `revert`
- scope：必须有且只能有一个（如 `waf-engine`、`admin-api`、`web-ui`）
- 每个最小可分单元提交一次

示例：`feat(waf-engine): 新增 SQL 注入检测模块`

## 快速开始

### 管理后台（单容器一键启动）

```bash
docker compose up -d --build
```

浏览器打开 http://\<host\>:18081（默认账号 `admin / admin123`，可用 `ADMIN_INIT_PASSWORD` 覆盖），
首次使用会进入**引导页**：

1. **配置 Redis**：填写你已有 Redis 实例的连接信息（规则热下发 / 攻击事件队列），后台先做连通性测试。
2. **接入本机 OpenResty**：在运行 OpenResty 的服务器上执行引导页给出的一键命令，
   自动下载 WAF Lua 组件、生成 `config_local.lua`（Redis 连接）与 `nginx.conf` 接入片段，
   挂载 `init/access/log` 三个阶段即可生效。

```
┌─────────────┐     引导接入      ┌──────────────────────────────┐
│ 单容器管理后台 │ ───────────────► │ 本机已部署的 OpenResty          │
│ (Go+Vue,18081)│   下载组件/脚本    │  + /opt/waf (Lua 组件)        │
└──────┬──────┘                   │  + nginx.conf 挂载            │
       │ 规则下发/事件消费          │                                │
       ▼                          └──────────────┬───────────────┘
  你已有的 Redis ◄───────────────────────────────┘ 事件上报/规则热更
```

### 使用 GHCR 镜像

main 分支 / `v*` 标签 push 后，GitHub Actions 自动构建并推送到
`ghcr.io/<owner>/openresty-waf`（linux/amd64）：

```bash
docker pull ghcr.io/<owner>/openresty-waf:latest
docker run -d --name waf-admin -p 18081:8081 \
  -v waf-data:/data \
  -e ADMIN_INIT_PASSWORD=your-password \
  -e ADMIN_JWT_SECRET=your-secret \
  ghcr.io/<owner>/openresty-waf:latest
```

### 手动部署

**1. 管理后台**：`cd admin && go build -o waf-admin . && ./waf-admin`，打开引导页完成配置。

**2. WAF 引擎（接入本机任意 OpenResty）**：引导页下载组件到 `/opt/waf`，在 `nginx.conf` 挂载

```nginx
lua_package_path "/opt/waf/?.lua;;";
lua_shared_dict waf_rule    20m;
lua_shared_dict waf_counter 50m;
init_by_lua_file         /opt/waf/init.lua;
init_worker_by_lua_file  /opt/waf/init.lua;   # Redis 规则热更新
access_by_lua_file       /opt/waf/access.lua;
log_by_lua_file          /opt/waf/log.lua;
# 可选（响应检测：状态码/响应体拦截与泄露监控）
header_filter_by_lua_file /opt/waf/header_filter.lua;
body_filter_by_lua_file   /opt/waf/body_filter.lua;
```

**3. 管理前端（开发模式）**：`cd web && npm install && npm run dev`

更多：性能基准见 `docs/benchmark.md`，人机验证接入见 `docs/challenge.md`，慢速攻击与连接层加固见 `docs/hardening.md`。

## License

MIT
