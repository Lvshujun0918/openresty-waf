-- config.lua
-- WAF 全局配置模块。
-- 所有可调参数集中于此，init.lua 启动时加载并广播到共享内存。

local _M = {}

-- ============================================================================
-- 基本参数
-- ============================================================================

-- 运行模式:
--   "active"  拦截模式（命中即阻断）
--   "detect"  监控模式（仅记录攻击日志，不阻断）
--   "off"     放行模式（旁路，不执行检测）
_M.mode = "active"

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
    event_key     = "waf:event:list",       -- 攻击事件队列（LPUSH）
    stat_key      = "waf:stat:counter",     -- 统计计数
}

-- ============================================================================
-- CC 防刷
-- ============================================================================
_M.cc = {
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
    -- 高级验证码（geetest / gitee）配置
    captcha = {
        id         = "",       -- captcha_id
        key        = "",       -- captcha_key
        verify_api = "https://gcaptcha4.geetest.com/validate",
        sdk        = "https://static.geetest.com/v4/gt4.js",
    },
}

-- ============================================================================
-- 拦截响应
-- ============================================================================
_M.block = {
    status   = 403,
    html     = [[<!DOCTYPE html>
<html lang="zh-CN"><head><meta charset="utf-8">
<title>访问被拒绝</title>
<style>body{font-family:sans-serif;text-align:center;padding:80px 20px;color:#444}
h1{font-size:36px;color:#c0392b}.code{font-size:72px;color:#eee}</style>
</head><body><div class="code">403</div>
<h1>您的请求已被防火墙拦截</h1>
<p>该请求可能包含恶意内容，如有疑问请联系网站管理员。</p>
</body></html>]],
}

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
-- 仅当直连地址（remote_addr）命中此列表时才信任 X-Forwarded-For 最左值，
-- 防止公网直接暴露时攻击者伪造 XFF 绕过 IP 名单/CC/人机验证。
-- 列表为空时保持兼容行为（无条件信任 XFF），适合确认部署在可信反代之后。
_M.trusted_proxies = { }

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
local function merge_cfg(t, override)
    for k, v in pairs(override) do
        if type(v) == "table" and type(t[k]) == "table" then
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

return _M
