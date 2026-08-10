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

-- ============================================================================
-- 检测模块开关
-- ============================================================================
_M.modules = {
    ip_check      = true,   -- IP 黑白名单
    ua_check      = true,   -- User-Agent 检测
    url_check     = true,   -- URL 检测
    args_check    = true,   -- GET 参数检测
    cookie_check  = true,   -- Cookie 检测
    header_check  = true,   -- 请求头检测
    post_check    = true,   -- POST body 检测（含 multipart）
    upload_check  = true,   -- 文件上传检测
    cc_check      = true,   -- CC 防刷
    challenge     = true,   -- 人机验证
    protocol_check= true,   -- 协议异常
    leak_check    = true,   -- 敏感文件/目录泄露
    semisense     = false,  -- 语义增强探测（词法级 SQL/XSS，实验性）
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
    host            = "127.0.0.1",
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
    version_key   = "waf:rule:version",     -- 全局版本号
    ruleset_key   = "waf:rule:ruleset",     -- 完整规则集（JSON）
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

-- 文件上传黑名单后缀
_M.upload = {
    deny_ext = { "php", "php3", "php5", "phtml", "jsp", "jspx", "asp",
                 "aspx", "asa", "cer", "cgi", "pl", "sh", "py", "exe" },
    deny_mime = { "application/x-php", "application/x-httpd-php",
                  "application/x-msdownload" },
}

return _M
