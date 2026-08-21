-- config.lua
-- WAF 全局配置模块。
-- 所有可调参数集中于此，init.lua 启动时加载并广播到共享内存。

local _M = {}

-- ============================================================================
-- 基本参数
-- ============================================================================

-- 引擎版本号：随事件上报（engine_version 字段），供后台「配置页」核对下发状态
_M.version = "0.6.0"

-- 运行模式:
--   "active"  拦截模式（命中即阻断）
--   "detect"  监控模式（仅记录攻击日志，不阻断）
--   "off"     放行模式（旁路，不执行检测）
_M.mode = "active"

-- 异常分阈值（SCORE 动作累计，参考雷池 1.5/3.0 两级风险分级）：
--   score_warn = 5        达到记录警告事件（不阻断）
--   score_threshold = 10  达到阻断（弱特征规则均 +1，需 10 条同时命中才拦截，
--                         避免正常遥测流量命中多条宽正则叠加误报）
_M.score_warn = 5
_M.score_threshold = 10

-- WAF 挂载路径前缀（用于生成拦截页面中的提示，可留空）
_M.base_path = "/waf"

-- 说明：检测能力完全由规则集驱动（内置 + 后台下发），无模块级开关；
-- 需要关闭某类检测请在后台规则管理页停用对应规则组。

-- ============================================================================
-- 检测控制
-- ============================================================================
_M.detection = {
    -- 豁免路径前缀（按前缀匹配）：命中时跳过规则引擎检测，
    -- 用于规避 JSON API 等场景的误报（IP 黑白名单 / CC 防刷 / 人机验证仍生效）
    exclude_paths = {},
    -- 静态资源剪枝：命中后缀/前缀时跳过规则引擎检测（其余防护仍生效），
    -- 大幅降低静态文件请求的检测开销
    skip_static = {
        ext = { ".js", ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg",
                ".ico", ".webp", ".avif", ".woff", ".woff2", ".ttf", ".eot",
                ".map", ".mp3", ".mp4", ".webm" },
        prefix = {},
    },
    -- IP 地理信息：有 /opt/waf/ip2region.xdb 时记录国家/省市（log 阶段查询）
    geo = true,
    -- 响应体检测缓冲上限（字节）：body_filter 累积响应体后一次性检测，
    -- 防大响应撑爆内存；增大可提升 DLP 检测覆盖，同时增加内存开销
    response_body_buffer = 8192,
    -- 检测 watchdog（毫秒）：access 阶段检测总耗时超过该阈值时强制放行，
    -- 灾难性回溯/极端慢规则的最后防线（0 表示关闭）
    watchdog_ms = 10,
    -- 响应安全头加固（header_filter 阶段生效，需挂载 header_filter.lua）：
    --   add: 添加/覆盖响应头（如 HSTS/CSP/X-Frame-Options）
    --   remove: 移除泄露头（如 Server / X-Powered-By）
    response_headers = {
        add = {
            ["X-Content-Type-Options"] = "nosniff",
            ["X-Frame-Options"]       = "SAMEORIGIN",
            ["Referrer-Policy"]       = "strict-origin-when-cross-origin",
        },
        remove = { "X-Powered-By" },
    },
    -- 攻击证据脱敏（隐私合规）：请求头/请求体入库前打码。
    --   fields: 敏感键名（JSON/form 形式 "key=value" 或 "key":"value"，值整体打码）
    --   regex:  额外正则打码（命中部分替换为 ***），如手机号/身份证
    evidence_mask = {
        enabled = true,
        fields = { "password", "passwd", "pwd", "token", "secret",
                   "authorization", "access_key", "private_key", "cookie" },
        regex = { [[1[3-9]\d{9}]], "\\d{17}[\\dXx]" },
    },
}

-- ============================================================================
-- 共享内存字典（需与 nginx.conf 中 lua_shared_dict 声明一致）
-- ============================================================================
_M.dict = {
    rules   = "waf_rule",    -- 规则缓存与版本号
    counter = "waf_counter", -- 频控计数 / 统计
}

-- ============================================================================
-- Redis（规则热下发 / 攻击事件缓冲）
-- ============================================================================
_M.redis = {
    -- 支持环境变量覆盖（Docker 部署时指向 compose 的 redis 服务）
    host            = os.getenv("WAF_REDIS_HOST") or "127.0.0.1",
    port            = 6379,
    db              = 0,
    password        = nil,   -- 无密码留 nil
    timeout         = 1000,  -- 连接/读写超时（ms）
    pool_size       = 100,
    keepalive_timeout = 60000,
}

-- 规则热更新：后台写 Redis，worker 轮询版本号后原子切换
_M.rule_refresh = {
    enabled       = true,
    interval      = 5,      -- 轮询间隔（秒）
    version_key   = "waf:rule:version",     -- 规则集全局版本号
    ruleset_key   = "waf:rule:ruleset",     -- 完整规则集（JSON）
    -- 运行配置热更新（后台统一管理，取代直接改本文件）
    config_version_key = "waf:config:version",
    config_data_key    = "waf:config:data",
    -- 触发规则（host/UA/请求头/IP 等条件筛选，命中执行人机验证/豁免/CC）
    trigger_rules_key   = "waf:trigger:rules",   -- 触发规则集（JSON）
    trigger_version_key = "waf:trigger:version", -- 触发规则版本号
    -- 爬虫画像库（UA + IP 段验证；后台发布热更新）
    bot_profiles_key   = "waf:bot:profiles",
    bot_profiles_version_key = "waf:bot:version",
    event_key     = "waf:event:list",       -- 攻击事件队列（LPUSH）
    stat_key      = "waf:stat:counter",     -- 统计计数
}

-- ============================================================================
-- 爬虫识别与恶意指纹
-- ============================================================================
_M.bot = {
    enabled      = true,           -- 启用爬虫识别与统计（仅统计，拦截走触发规则/名单）
    fingerprint  = true,           -- 启用 HTTP 客户端指纹计算（恶意指纹库比对 + 爬虫统计）
    report_key   = "waf:bot:list", -- 爬虫访问记录队列（后台消费展示）
}

-- ============================================================================
-- 引擎健康心跳与实时统计上报（后台「引擎状态 / 实时监控」数据源）
-- ============================================================================

-- 心跳：init_worker 定时器周期性写入 Redis（含引擎/规则/配置版本号），
-- 后台据此判断引擎在线状态与「规则是否已实际加载」
_M.heartbeat = {
    enabled    = true,
    interval   = 10,            -- 心跳间隔（秒）
    ttl        = 30,            -- 心跳键 TTL（秒），超过视为离线
    key_prefix = "waf:heartbeat:",
}

-- 实时统计：log 阶段按秒级窗口在共享内存计数，
-- init_worker 定时器每秒聚合写入 Redis 列表（后台实时监控曲线）
_M.stats = {
    enabled        = true,
    flush_interval = 1,      -- 聚合 flush 间隔（秒）
    live_key       = "waf:stats:live",  -- 实时统计列表（JSON 秒级窗口）
    retention      = 3600,   -- 保留条数（≈1 小时）
}

-- ============================================================================
-- 规则耗时画像
-- ============================================================================
-- worker 内聚合每条规则评估次数/耗时，定时批量上报后台聚合展示
_M.rule_perf = {
    enabled   = true,
    interval  = 60,                   -- 上报周期（秒）
    redis_key = "waf:ruleperf:list",  -- 后台消费队列
}

-- ============================================================================
-- 命中缓存
-- ============================================================================
-- 同一请求指纹（规则版本+模式+方法+host+IP+URI+请求头）的规则引擎判定短时缓存，
-- 重复请求跳过规则扫描；仅缓存引擎段判定，名单/触发规则/CC/人机验证照常执行
_M.hit_cache = {
    enabled = true,
    ttl     = 10,  -- 判定缓存时长（秒）
}

-- ============================================================================
-- CC 防刷
-- ============================================================================
_M.cc = {
    backend       = "shared",  -- shared（单机共享内存）| redis（集群精确限流，每请求一次 Redis INCR）
    rate          = "100/60",  -- 每 60 秒内同一 IP 同 URI 最多 100 次
    ban_duration  = 300,       -- 触发后封禁时长（秒）
    ban_key_prefix= "waf:cc:ban:",
    counter_prefix= "waf:cc:cnt:",
}

-- ============================================================================
-- 人机验证
--   mode = "basic"     基础 JS Challenge（自包含，无第三方依赖）
--   mode = "geetest"   极验验证码（GT4）
--   mode = "gitee"     Gitee 验证码（与极验 GT4 协议兼容）
-- 触发时机：CC 超限且请求未通过验证时，返回验证页而非直接拦截。
-- ============================================================================
_M.challenge = {
    enabled       = true,
    mode          = "basic",   -- "basic" | "geetest" | "gitee"
    cookie_name   = "waf_pass",
    cookie_secret = "openresty-waf-change-me",   -- 生产环境务必修改
    cookie_ttl    = 300,       -- 通过验证后的放行时长（秒）
    page_path     = "/__waf_challenge__",
    verify_path   = "/__waf_challenge_verify__",
    -- basic 模式工作量证明难度（哈希前导零位数，平均 2^bits 次哈希；0 关闭）
    pow_bits      = 20,
    -- 同 IP 挑战页签发限频：窗口内签发超过 issue_limit 次直接拒绝渲染（444）
    issue_limit   = 20,
    issue_window  = 60,
    -- 高级验证码（geetest / gitee）配置
    captcha = {
        id         = "",       -- captcha_id
        key        = "",       -- captcha_key
        verify_api = "https://gcaptcha4.geetest.com/validate",
        sdk        = "https://static.geetest.com/v4/gt4.js",
    },
    -- 品牌化（挑战页标题与页脚公司/联系方式，后台可配置；空字段自动隐藏）
    brand = {
        title   = "",          -- 页面标题（空用默认「安全验证」）
        company = "",          -- 公司/站点名（页脚展示）
        contact = "",          -- 联系方式（页脚展示）
    },
}

-- ============================================================================
-- 拦截响应
-- ============================================================================
_M.block = {
    status   = 403,
    html     = [[<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>访问已被拦截</title>
<style>
  * { margin: 0; padding: 0; box-sizing: border-box; }
  html, body { height: 100%; }
  body {
    font-family: "PingFang SC", "Helvetica Neue", "Microsoft YaHei", Arial, sans-serif;
    background: linear-gradient(135deg, #1e293b 0%, #0f172a 100%);
    display: flex; align-items: center; justify-content: center;
    min-height: 100vh; padding: 20px; color: #334155;
  }
  .card {
    background: #ffffff; border-radius: 16px;
    width: 92%; max-width: 520px; padding: 48px 40px 36px;
    text-align: center; position: relative;
    box-shadow: 0 24px 64px rgba(0, 0, 0, 0.35);
  }
  .icon {
    width: 76px; height: 76px; margin: 0 auto 24px;
    display: flex; align-items: center; justify-content: center;
    border-radius: 50%; background: #fef2f2; border: 1px solid #fecaca;
  }
  .icon svg { width: 42px; height: 42px; }
  h1 { font-size: 22px; font-weight: 600; color: #0f172a; margin-bottom: 12px; }
  .desc { font-size: 14px; color: #64748b; line-height: 1.9; margin-bottom: 26px; }
  .meta {
    background: #f8fafc; border: 1px solid #e2e8f0; border-radius: 10px;
    padding: 14px 18px; font-size: 13px; color: #94a3b8; text-align: left;
    display: grid; gap: 8px; margin-bottom: 26px;
  }
  .meta .row { display: flex; gap: 8px; }
  .meta .k { color: #64748b; flex-shrink: 0; min-width: 72px; }
  .meta .v { color: #334155; font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; word-break: break-all; }
  .footer { font-size: 12px; color: #94a3b8; }
  .footer b { color: #64748b; font-weight: 500; }
</style>
</head>
<body>
  <div class="card">
    <div class="icon">
      <svg viewBox="0 0 24 24" fill="none">
        <path d="M12 3 2 20h20L12 3z" fill="#ef4444"/>
        <path d="M13 9.5h-2V15h2V9.5zm0 7.5h-2v2h2v-2z" fill="#ffffff"/>
      </svg>
    </div>
    <h1>访问已被拦截</h1>
    <p class="desc">检测到您的请求存在恶意行为或异常特征，已由安全防火墙拦截。如有疑问请联系网站管理员。</p>
    <div class="meta">
      <div class="row"><span class="k">来源 IP</span><span class="v">{ip}</span></div>
      <div class="row"><span class="k">请求地址</span><span class="v">{uri}</span></div>
      <div class="row"><span class="k">拦截原因</span><span class="v">{group}</span></div>
      <div class="row"><span class="k">事件编号</span><span class="v">{req_id}</span></div>
    </div>
    <div class="footer">Web Application Firewall 安全防护 · <b>请求已被拦截</b></div>
  </div>
</body>
</html>]],
    -- 自定义拦截页面：按命中规则分组（group）显示不同 HTML。
    -- pages = { { group = "crawler", name = "爬虫拦截", html = "<...>" }, ... }
    -- 未配置分组命中的请求回退使用上方 html（兜底默认页）。
    pages = {},
}

-- 命中分组中文名（拦截页 {group} 占位符展示用）
local group_names = {
    sqli        = "SQL 注入攻击",
    xss         = "跨站脚本攻击",
    rce         = "远程代码执行",
    lfi         = "文件包含攻击",
    ssrf        = "服务端请求伪造",
    protocol    = "协议异常",
    leak        = "信息泄露风险",
    scanner     = "扫描探测行为",
    custom      = "自定义规则拦截",
    crawler     = "爬虫 / 自动化工具",
    cc          = "访问频率过高",
    trigger     = "触发规则拦截",
    upload      = "非法文件上传",
    fingerprint = "设备指纹异常",
    response    = "响应内容异常",
    cve         = "CVE 漏洞攻击",
    hpp         = "参数污染攻击",
    api         = "API 安全风险",
    obfuscation = "编码混淆绕过",
    dlp         = "敏感数据泄露",
    deser       = "反序列化攻击",
    webshell    = "Webshell 攻击",
}

-- 按命中分组选择拦截页面：pages 中有该分组的自定义 HTML 则使用，
-- 否则回退兜底默认页（cfg.block.html）。
function _M.block_page(cfg, group)
    local pages = cfg and cfg.block and cfg.block.pages
    if type(pages) == "table" then
        for _, p in ipairs(pages) do
            if p and p.group == group and p.html and p.html ~= "" then
                return p.html
            end
        end
    end
    return (cfg and cfg.block and cfg.block.html) or "Forbidden"
end

-- 拦截页占位符渲染：{ip} {uri} {group} {req_id}
-- 输出拦截页面前的最后一步，所有拦截路径统一调用。
-- 注意：替换值可能含 %（如 URL 编码的 %20），必须用函数式替换——
-- 字符串式 repl 会把 %2 等解析为回溯引用导致 "invalid capture index" 报错，
-- 进而被外层 pcall 捕获走 fail-open（命中 BLOCK 却放行 200）。
function _M.render_block_html(html, ctx, group)
    if not html or html == "" then
        return html
    end
    local ip = (ctx and ctx.client_ip) or ""
    local uri = (ctx and ctx.request and ctx.request.uri) or ""
    local req_id = (ctx and ctx.req_id) or ""
    local g = (group_names and group_names[group]) or group or ""
    return html:gsub("{ip}", function() return ip end)
        :gsub("{uri}", function() return uri end)
        :gsub("{group}", function() return g end)
        :gsub("{req_id}", function() return req_id end)
end

-- ============================================================================
-- 日志
-- ============================================================================
_M.log = {
    enabled   = true,
    backend   = "file",    -- "file" 本地文件 | "redis" 推送 Redis 队列
    dir       = "/var/log/waf",   -- file 后端日志目录
    format    = "json",    -- "json" | "plain"
    level     = "info",    -- debug/info/warn/error
    -- redis 后端字段
    redis_key = "waf:event:list",
}

-- ============================================================================
-- 白名单（内置，管理后台名单下发前的兜底）
-- ============================================================================
_M.whitelist = {
    ips       = { "127.0.0.1", "::1" },   -- 放行 IP（精确匹配或 CIDR）
    urls      = { "/favicon.ico" },        -- 放行 URL（正则）
    user_agents = { },                     -- 放行 UA（正则）
}

-- 黑名单（内置兜底）
_M.blacklist = {
    ips = { },
    urls = { },
}

-- 可信反向代理列表（精确 IP 或 CIDR，IPv4）。
-- 直连地址命中此列表时才信任 X-Forwarded-For 最左值；
-- 列表为空 = 无条件信任 XFF（兼容旧行为；公网直连部署建议把
-- 反代/CDN 回源 IP 加入此列表，防止攻击者伪造 XFF 绕过 IP 防护）。
_M.trusted_proxies = { }

-- 自定义来源 IP 头（可选，优先级高于 XFF）：
-- 部分 CDN（如腾讯云 EdgeOne 的 eo-connecting-ip）把真实客户端 IP
-- 放在私有头中且回源 IP 不公开，无法用 trusted_proxies 校验。
-- 留空则不启用；开启后仅接受合法 IP 值，非法值自动回退 XFF/remote_addr。
_M.client_ip_header = ""

-- 高频攻击自动封禁：同 IP 短窗口内多次攻击命中后自动临时封禁（雷池同款能力）
_M.auto_ban = {
    enabled        = true,
    threshold      = 10,     -- 窗口内攻击次数阈值
    window         = 60,     -- 统计窗口（秒）
    duration       = 600,    -- 封禁时长（秒）
    ban_key_prefix = "waf:ab:ban:",
    counter_prefix = "waf:ab:cnt:",
}

-- 文件上传黑名单
_M.upload = {
    enabled  = true,   -- 上传检测开关（关闭后仅放行，不检测文件后缀/类型）
    deny_ext = { "php", "php3", "php5", "phtml", "jsp", "jspx", "asp",
                 "aspx", "asa", "cer", "cgi", "pl", "sh", "py", "exe" },
    deny_mime = { "application/x-php", "application/x-httpd-php",
                  "application/x-msdownload" },
    -- 请求体落临时文件（超过 client_body_buffer_size）时，流式读取文件前
    -- N 字节继续做后缀/类型检测（防超大上传绕过；超出部分不再读入内存）
    spooled_scan_bytes = 524288,
}

-- 全量流量记录（后台配置中心可开关；开启后每个请求上报一条，含命中标记）
_M.traffic_log = {
    enabled       = false,
    retention_days = 7,           -- 后台按此天数自动清理过期记录
    redis_key     = "waf:traffic:list",
}

-- 本地覆盖配置：部署时由安装脚本生成 config_local.lua（含 Redis 连接信息），
-- 深合并覆盖上述默认值，避免直接改动本文件。
-- 注意：模块名用下划线（config_local），点号会被 require 解析为路径分隔。
-- 数组判断：连续整数 key（含空表）。数组字段（名单列表等）需整体替换，
-- 避免逐 key 递归合并导致旧元素残留/错位（热更新必须用新数组整体覆盖）。
local function is_array(v)
    local n = 0
    for k in pairs(v) do
        if type(k) ~= "number" or k < 1 or k % 1 ~= 0 then
            return false
        end
        if k > n then n = k end
    end
    for i = 1, n do
        if v[i] == nil then return false end
    end
    return true
end

local function merge_cfg(t, override)
    for k, v in pairs(override) do
        if type(v) == "table" and type(t[k]) == "table" and not is_array(v) then
            merge_cfg(t[k], v)
        else
            t[k] = v
        end
    end
end

local ok_local, local_cfg = pcall(require, "config_local")
if ok_local and type(local_cfg) == "table" then
    merge_cfg(_M, local_cfg)
end

-- 默认 cookie_secret 仅作回退：接入脚本生成 config_local.lua 时会写入随机密钥，
-- 仍为默认值时告警（默认密钥可被伪造 waf_pass cookie 绕过人机验证/CC）
if _M.challenge.cookie_secret == "openresty-waf-change-me" and ngx then
    ngx.log(ngx.WARN, "WAF: challenge.cookie_secret 仍为默认值，请重新运行接入脚本（-f 强制）生成 config_local.lua")
end

return _M
