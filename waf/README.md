# WAF Lua 引擎（OpenResty 侧）

纯 Lua 实现，挂载到任意 OpenResty 的以下阶段即可生效：

```nginx
lua_package_path "/opt/waf/?.lua;;";
lua_shared_dict waf_rule    20m;   # 规则缓存/版本
lua_shared_dict waf_counter 50m;   # 频控/统计计数
init_by_lua_file   /opt/waf/init.lua;
access_by_lua_file /opt/waf/access.lua;
log_by_lua_file    /opt/waf/log.lua;
```

## 目录结构

```
waf/
├── init.lua            # 初始化入口（加载配置/规则/共享内存）
├── access.lua          # access_by_lua 检测编排入口
├── header_filter.lua   # header_filter_by_lua 响应检测（可选）
├── log.lua             # log_by_lua 异步日志/统计入口
├── config.lua          # 全局配置（模式、阈值、路径、依赖开关）
├── storage.lua         # 共享内存 + Redis 读写封装
├── rule_engine/        # 规则引擎
│   ├── engine.lua      #   规则执行器（phase/offset 跳转/链）
│   ├── operators.lua   #   运算符：REGEX/PM/EQUALS/CONTAINS/CIDR...
│   ├── variables.lua   #   变量集合：URI_ARGS/POST_ARGS/HEADERS/COOKIE/BODY...
│   ├── transforms.lua  #   变换链：url_decode/lowercase/多重解码
│   └── actions.lua     #   动作：BLOCK/DROP/ACCEPT/REDIRECT/SCORE...
├── detectors/          # 检测器
│   ├── sqli.lua  xss.lua  rce.lua  lfi.lua  ssrf.lua
│   ├── protocol.lua    #   协议异常
│   ├── leak.lua        #   敏感文件/目录泄露
│   ├── cc.lua          #   频控（shared dict 令牌桶）
│   ├── challenge.lua   #   人机验证（JS/Cookie）
│   └── upload.lua      #   文件上传检测
├── ip.lua  ua.lua  header.lua   # 名单/UA/Header 检查
├── semisense.lua       # 语义增强探测（可选，libinjection 风格）
└── ruleset/            # 内置规则集（JSON）
    ├── sqli.json  xss.json  rce.json  lfi.json  ...
    └── whitelist.json
```

## IP 归属地（可选）

引擎内置纯 Lua 的 ip2region xdb 解析器（`ip_region.lua`，兼容 v2/v3 格式），
命中攻击日志会附带 country / province / city 归属地，后台可展示地理分布。

- 数据文件：将 `ip2region_v4.xdb` 放入 **`/opt/waf/`**（与 WAF 配置同目录，经 bind mount 下发）
- 缺省路径：`/opt/waf/ip2region_v4.xdb`（引擎容器重建无需重新放置）
- 缺失时自动降级：攻击日志不带归属地，不影响防护功能

## 设计约定

- 纯 Lua 5.1（LuaJIT）语法，不依赖 C 模块。
- 依赖的第三方库均为纯 Lua 的 `lua-resty-*` 系列。
- 所有模块通过 `require` 加载，模块返回 table。
