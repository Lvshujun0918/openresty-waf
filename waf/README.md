# WAF Lua 引擎（OpenResty 侧）

纯 Lua 实现，挂载到任意 OpenResty 的以下阶段即可生效：

```nginx
lua_package_path "/opt/waf/?.lua;;";
lua_shared_dict waf_rule    20m;   # 规则缓存/版本
lua_shared_dict waf_counter 50m;   # 频控/统计计数
init_by_lua_file   /opt/waf/init.lua;
access_by_lua_file /opt/waf/access.lua;
log_by_lua_file    /opt/waf/log.lua;
# 响应检测（可选）
header_filter_by_lua_file /opt/waf/header_filter.lua;
body_filter_by_lua_file   /opt/waf/body_filter.lua;
```

## 目录结构

```
waf/
├── init.lua            # 初始化入口（加载配置/规则/共享内存）
├── access.lua          # access_by_lua 检测编排入口
├── header_filter.lua   # header_filter_by_lua 响应检测（状态码拦截）
├── body_filter.lua     # body_filter_by_lua 响应体检测与拦截页替换
├── log.lua             # log_by_lua 异步日志/统计入口
├── config.lua          # 全局配置（模式、阈值、路径、依赖开关）
├── storage.lua         # 共享内存 + Redis 读写封装
├── ip_region.lua       # ip2region xdb 归属地查询（可选）
├── libinjection_ffi.lua# libinjection 语义检测 FFI 绑定（可选）
├── rule_engine/        # 规则引擎
│   ├── engine.lua      #   规则执行器（phase 过滤/仲裁/异常打分）
│   ├── operators.lua   #   运算符：REGEX/PM/EQUALS/CONTAINS/CIDR...
│   ├── variables.lua   #   变量：URI_ARGS/POST_ARGS/HEADERS/BODY/RESPONSE_*
│   ├── transforms.lua  #   变换链：url_decode/lowercase/去注释/空白压缩
│   ├── actions.lua     #   动作：BLOCK/DROP/ACCEPT/REDIRECT/SCORE/LOG_ONLY
│   ├── trigger.lua     #   触发规则（CC/人机验证/豁免）
│   └── util.lua        #   JSON 结构化/静态路径剪枝工具
├── detectors/          # 检测器
│   ├── cc.lua          #   CC 频控（shared dict 计数 + 封禁）
│   ├── challenge.lua   #   人机验证（basic/geetest/gitee）
│   └── upload.lua      #   文件上传检测（后缀/Content-Type 黑名单）
├── libinjection/       # libinjection C 源码（scripts/build-libinjection.sh 编译）
└── t/                  # 单元测试（mock + run.lua，纯 luajit 可跑）
```

## IP 归属地（可选）

引擎内置纯 Lua 的 ip2region xdb 解析器（`ip_region.lua`，兼容 v2/v3 格式），
命中攻击日志会附带 country / province / city 归属地，后台可展示地理分布。

- 数据文件：将 `ip2region_v4.xdb` 放入 **`/opt/waf/`**（与 WAF 配置同目录，经 bind mount 下发）
- 缺省路径：`/opt/waf/ip2region_v4.xdb`（引擎容器重建无需重新放置）
- 缺失时自动降级：攻击日志不带归属地，不影响防护功能

## 规则集来源

规则完全由管理后台经 Redis 下发（`waf:rule:ruleset` + `waf:rule:version`），
引擎启动时不加载任何内置规则。Redis 规则集为空（后台未发布 / 加载失败）时，
access 阶段按 **fail-closed** 策略拦截全部流量，防止"无规则裸奔"。

- 规则热更新：引擎每 5s 轮询版本号，变化时原子切换（先写规则集后写版本号）
- 回滚保护：Redis 规则集结构非法时拒绝加载，保持当前生效规则集
- 后台重种：`SeedVersion` 变更后重启 admin 会删除 `is_seed` 规则并重新插入

## 设计约定

- 纯 Lua 5.1（LuaJIT）语法，不依赖 C 模块。
- 依赖的第三方库均为纯 Lua 的 `lua-resty-*` 系列。
- 所有模块通过 `require` 加载，模块返回 table。
