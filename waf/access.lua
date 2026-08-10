-- access.lua
-- access_by_lua 检测编排入口。
--
-- nginx.conf:
--   access_by_lua_file /opt/waf/access.lua;

local engine    = require "rule_engine.engine"
local storage   = require "storage"
local operators = require "rule_engine.operators"

-- 初始化请求上下文（写入 ngx.ctx，供 log 等后续阶段使用）
local function new_ctx(cfg)
    local ctx = {
        mode            = cfg.mode or "active",
        score           = 0,
        score_threshold = cfg.score_threshold or 5,
        matched         = {},
        client_ip       = storage.get_client_ip(),
        start_time      = ngx.now(),
        request         = {
            method = ngx.req.get_method() or "",
            host   = ngx.var.host or "",
            uri    = ngx.var.request_uri or "",   -- 含 query string
            path   = ngx.var.uri or "",           -- 不含 query string
        },
    }
    ngx.ctx.waf_ctx = ctx
    return ctx
end

-- 发送拦截响应
local function block(cfg)
    local status = tonumber(cfg.block and cfg.block.status) or 403
    ngx.status = status
    ngx.header.content_type = "text/html; charset=utf-8"
    ngx.say(cfg.block and cfg.block.html or "Forbidden")
    ngx.exit(status)
end

-- IP 黑白名单快速检查（白名单优先）
-- 返回 "whitelisted" / "blocked" / nil
local function ip_check(ctx, cfg)
    local wl = cfg.whitelist and cfg.whitelist.ips or {}
    for _, ip in ipairs(wl) do
        if operators.eval("CIDR", ctx.client_ip, ip) then
            return "whitelisted"
        end
    end
    local bl = cfg.blacklist and cfg.blacklist.ips or {}
    for _, ip in ipairs(bl) do
        if operators.eval("CIDR", ctx.client_ip, ip) then
            return "blocked"
        end
    end
    return nil
end

-- ============================================================================
-- 主流程
-- ============================================================================

local cfg = engine.get_active_config()

-- 放行模式：不执行检测
if cfg.mode == "off" then
    return
end

local ctx = new_ctx(cfg)

-- 1. IP 黑白名单
local ip_result = ip_check(ctx, cfg)
if ip_result == "whitelisted" then
    return
elseif ip_result == "blocked" then
    if ctx.mode == "active" then
        block(cfg)
    end
    -- detect 模式：仅记录（命中信息后续由 log 阶段落盘）
    return
end

-- 2. 规则引擎（URL / Args / Cookie / Header / Body 等规则）
local ruleset = engine.get_ruleset()
if ruleset then
    local result = engine.run(ruleset, "access", ctx)
    if result == "blocked" or result == "accepted" then
        return
    end
end

-- 3. CC 防刷
if cfg.modules and cfg.modules.cc_check then
    local cc = require "detectors.cc"
    if cc.check(ctx, cfg) == "banned" then
        if ctx.mode == "active" then
            ngx.exit(503)
        end
        -- detect 模式：仅记录
        return
    end
end

-- 4. 扩展检测器（人机验证、语义增强、上传检测等）后续接入：
--    require("detectors.challenge").check(ctx, cfg)
