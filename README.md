# OpenResty WAF

一个适配于任意 OpenResty 的 Web 应用防火墙：通过 Lua 规则接入，自动检测、拦截、阻断并记录流量；内置 Web 管理后台，支持可视化配置拦截规则与接入常见规则库（OWASP CRS 等）。

## 核心特性

- **嵌入式接入**：纯 Lua 组件，挂载到任意 OpenResty 的 `access_by_lua` / `header_filter_by_lua` / `log_by_lua` 阶段，无需重新编译 Nginx。
- **规则热更新**：规则经 Redis 下发，worker 内共享内存缓存 + 版本原子切换，配置变更不中断连接。
- **完整防护能力**：SQLi / XSS / RCE / LFI / SSRF / 协议异常 / 敏感文件泄露 / 恶意 UA 与扫描器 / 文件上传检测。
- **访问控制与限流**：IP / UA / Cookie / Header / URL / Args 黑白名单、CC 防刷、人机验证。
- **灵活工作模式**：监控（仅记录）/ 拦截 / 放行，可全局一键切换，检测异常时 fail-open。
- **Web 管理后台**：仪表盘、规则管理（含在线调试、导入导出）、事件检索与一键处置、站点管理、TOTP 认证。

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

### Docker 一键部署（推荐）

```bash
docker compose up -d --build
```

| 入口 | 地址 | 说明 |
|---|---|---|
| 管理后台 | http://\<host\>:18081 | Go 后台 + Vue3 前端（单二进制，内嵌页面） |
| WAF 网关 | http://\<host\>/ | OpenResty 前置检测，反代到管理后台 |
| Redis | compose 内部 redis:6379 | 规则热下发 / 事件队列 |

- 默认账号：`admin / admin123`（可用 `ADMIN_INIT_PASSWORD` 环境变量覆盖）
- 修改 `ADMIN_JWT_SECRET` 后再生产使用

### 手动部署

**1. WAF 引擎（任意 OpenResty）**：在 `nginx.conf` 挂载

```nginx
lua_package_path "/opt/waf/?.lua;;";
lua_shared_dict waf_rule    20m;
lua_shared_dict waf_counter 50m;
init_by_lua_file         /opt/waf/init.lua;
init_worker_by_lua_file  /opt/waf/init.lua;   # 启用 Redis 规则热更新
access_by_lua_file       /opt/waf/access.lua;
log_by_lua_file          /opt/waf/log.lua;
```

**2. 管理后台**

```bash
cd admin && go build -o waf-admin . && ./waf-admin
# 前端页面构建后可嵌入（见 admin/internal/webui）
```

**3. 管理前端（开发模式）**

```bash
cd web && npm install && npm run dev   # 默认代理 /api 到 :18081
```

更多：性能基准见 `docs/benchmark.md`，人机验证接入见 `docs/challenge.md`。

## License

MIT
