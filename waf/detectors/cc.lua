-- detectors/cc.lua
-- CC 防刷：基于共享内存计数，同 IP 同 Host 同路径超频后临时封禁该 IP。
-- 频率阈值 / 封禁时长来自命中的触发规则 config（缺省回退全局 config.cc），
-- 哪些请求参与限流由「触发规则」页的 cc 触发规则（host/UA/请求头/IP 等条件）决定；
-- 触发封禁时记录一条 CC 触发事件（waf:cc:list，后台「触发记录」页展示）。

local _M = {}

local config  = require "config"
local storage = require "storage"
local cjson   = require "cjson.safe"

-- 解析 "count/seconds" 形式阈值，缺省 100/60
local function parse_rate(rate)
    local count, seconds = rate:match("^(%d+)/(%d+)$")
    if not count or not seconds then
        return 100, 60
    end
    return tonumber(count), tonumber(seconds)
end

-- 本地时区偏移（与 log.lua 保持一致）
local function tz_offset()
    local now = os.time()
    local utc = os.time(os.date("!*t", now))
    local diff = os.difftime(now, utc)
    local sign = diff < 0 and "-" or "+"
    local a = math.abs(diff)
    return string.format("%s%02d:%02d", sign, math.floor(a / 3600), math.floor((a % 3600) / 60))
end

-- 该 IP 是否在封禁期
local function is_banned(cfg, ip)
    local key = (cfg.cc.ban_key_prefix or "waf:cc:ban:") .. ip
    return storage.get_shared(config.dict.counter, key) ~= nil
end

-- 记录一次 CC 触发事件（封禁/已在封禁期时上报，含详细参数供后台「触发记录」详情）
-- rule_name: 命中的触发规则名称
function _M.record(waf_ctx, cfg, rule_name)
    local client_ip = waf_ctx and waf_ctx.client_ip or ngx.var.remote_addr or ""
    local ok, geo = pcall(function()
        return require("ip_region").lookup(client_ip)
    end)
    local evidence = (waf_ctx and waf_ctx.evidence) or {}
    local rec = {
        time       = os.date("%Y-%m-%dT%H:%M:%S") .. tz_offset(),
        req_id     = waf_ctx and waf_ctx.req_id or "",
        client_ip  = client_ip,
        engine_version = config.version or "",
        country    = ok and geo and geo.country or "",
        province   = ok and geo and geo.province or "",
        city       = ok and geo and geo.city or "",
        method     = waf_ctx and waf_ctx.request and waf_ctx.request.method or "",
        host       = waf_ctx and waf_ctx.request and waf_ctx.request.host or "",
        uri        = waf_ctx and waf_ctx.request and waf_ctx.request.uri or "",
        rule_name  = rule_name or "",
        ja4        = (waf_ctx and waf_ctx.ja4 and waf_ctx.ja4 ~= "" and waf_ctx.ja4) or (waf_ctx and waf_ctx.tls_fp) or "",
        ja4h       = (waf_ctx and waf_ctx.ja4h) or "",
        headers    = cjson.encode(evidence.headers or {}),
        body       = evidence.body or "",
        status     = ngx.status and ngx.status ~= 0 and ngx.status or 503, -- 记录封禁拦截状态
    }
    local ok2, err = ngx.timer.at(0, function(premature)
        if premature then return end
        local storage2 = require "storage"
        storage2.redis_lpush("waf:cc:list", cjson.encode(rec))
    end)
    if not ok2 then
        ngx.log(ngx.ERR, "[waf] 调度 CC 触发事件上报失败: ", tostring(err))
    end
end

-- 执行 CC 检查：
-- rate / ban_duration 可传触发规则级配置（nil 时回退全局 cfg.cc）；
-- dims 可选维度数组："ua"（按 UA 哈希独立计数）/ "cookie"（无 Cookie 与有 Cookie 分开计数），
-- 封禁仍为 IP 级。
-- 返回 "banned"（触发封禁或已在封禁期）/ nil（正常）
function _M.check(waf_ctx, cfg, rate, ban_duration, dims)
    if not (cfg and cfg.cc) then
        return nil
    end

    local ip = waf_ctx.client_ip
    if not ip or ip == "" then
        return nil
    end

    if is_banned(cfg, ip) then
        return "banned"
    end

    local host = (waf_ctx.request and waf_ctx.request.host) or ""
    local path = (waf_ctx.request and waf_ctx.request.path) or "/"

    -- 规则级阈值优先，缺省回退全局
    rate = rate or cfg.cc.rate or "100/60"
    ban_duration = ban_duration or cfg.cc.ban_duration or 300

    local count, seconds = parse_rate(rate)
    -- 计数维度：IP + Host + 路径（不含 query string）+ 可选维度。
    -- host:path 做 md5 哈希：攻击者可用超长/多变 path 制造大量唯一键，
    -- 直接拼接原始字符串会撑爆 waf_counter 共享内存导致 CC 失效
    local counter_key = (cfg.cc.counter_prefix or "waf:cc:cnt:") .. ip .. ":" ..
        ngx.md5(host .. ":" .. path)
    for _, d in ipairs(dims or {}) do
        if d == "ua" then
            -- UA 哈希（防超长 key）：同 IP 换 UA 绕过时各 UA 独立计数
            local ua = ngx.var.http_user_agent or ""
            counter_key = counter_key .. ":ua:" .. ngx.md5(ua)
        elseif d == "cookie" then
            -- 无 Cookie 请求（多为脚本/bot）与有 Cookie 请求分开计数
            local has = (ngx.var.http_cookie or "") ~= ""
            counter_key = counter_key .. ":ck:" .. (has and "1" or "0")
        end
    end

    local n = storage.incr_shared(config.dict.counter, counter_key, 1, 0, seconds)
    if n and n >= count then
        -- 触发封禁（IP 级）
        local ban_key = (cfg.cc.ban_key_prefix or "waf:cc:ban:") .. ip
        local ok, serr = storage.set_shared(config.dict.counter, ban_key, ngx.time(), ban_duration)
        if not ok then
            -- 共享字典写满降级：封禁状态写不进去时仍拦截本次请求，
            -- 并告警（下一请求会再次尝试写入；计数键仍能正常读，不影响限流本身）
            ngx.log(ngx.ERR, "[waf] CC 封禁写入共享内存失败（字典可能已满）: ", tostring(serr))
        end
        return "banned"
    end

    return nil
end

-- 解除该 IP 封禁（人机验证通过后放行）
function _M.unban(waf_ctx, cfg)
    local ip = waf_ctx.client_ip
    if not ip or ip == "" then return end
    local key = (cfg.cc.ban_key_prefix or "waf:cc:ban:") .. ip
    storage.set_shared(config.dict.counter, key, nil)
end

return _M
