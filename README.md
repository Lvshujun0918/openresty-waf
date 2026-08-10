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

> 开发中，文档待完善。

## License

MIT
