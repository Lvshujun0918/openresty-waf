-- access.lua
-- access_by_lua 检测编排入口。
--
-- nginx.conf:
--   access_by_lua_file /opt/waf/access.lua;

local engine    = require "rule_engine.engine"
local storage   = require "storage"
local operators = require "rule_engine.operators"

-- 每请求唯一 ID：worker pid + 毫秒时间戳 + 连接序号 + 请求内自增
local req_seq = 0
local function gen_req_id()
    req_seq = (req_seq + 1) % 0xFFFF
    return string.format(
        "%d-%d-%d-%d",
        ngx.worker.pid(),
        math.floor(ngx.now() * 1000),
        tonumber(ngx.var.connection or 0) % 0x100000000,
        req_seq
    )
end

-- 证据采集上限
local EVIDENCE_MAX_HEADERS = 16
local EVIDENCE_MAX_BODY    = 8192  -- 请求体最大保留 8KB

-- 命中攻击时捕获请求头与请求体（access 阶段执行，供 log 阶段事件详情使用）
local function capture_evidence(ctx)
    local evidence = {}
    -- 请求头：按名称排序，取前 N 个
    local all = ngx.req.get_headers()
    local hdrs = {}
    if all then
        for k, v in pairs(all) do
            hdrs[#hdrs + 1] = { name = tostring(k), value = tostring(v) }
        end
    end
    table.sort(hdrs, function(a, b) return a.name < b.name end)
    if #hdrs > EVIDENCE_MAX_HEADERS then
        -- 截断到前 N 个
        local cut = {}
        for i = 1, EVIDENCE_MAX_HEADERS do cut[i] = hdrs[i] end
        hdrs = cut
    end
    evidence.headers = hdrs
    -- 请求体（表单 / JSON / 原始）：仅非 GET/HEAD 读取，避免无谓开销
    local method = ngx.req.get_method() or "GET"
    if method ~= "GET" and method ~= "HEAD" then
        ngx.req.read_body()
        local body = ngx.req.get_body_data()
        if body and #body > 0 then
            evidence.body = string.sub(body, 1, EVIDENCE_MAX_BODY)
        end
    end
    ctx.evidence = evidence
end

-- 初始化请求上下文（写入 ngx.ctx，供 log 等后续阶段使用）
local function new_ctx(cfg)
    local ctx = {
        req_id          = gen_req_id(),
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

-- 0. 挑战相关路径（验证页 / 回调），不参与规则检测
if cfg.challenge and cfg.challenge.enabled then
    local uri = ngx.var.uri or ""
    if uri == cfg.challenge.page_path then
        require("detectors.challenge").serve_page(ctx, cfg)
        return
    elseif uri == cfg.challenge.verify_path then
        require("detectors.challenge").serve_verify(ctx, cfg)
        return
    end
end

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
    -- 豁免路径：命中前缀时跳过规则检测（用于规避 JSON API 误报）
    local exempt = false
    local ep = cfg.detection and cfg.detection.exclude_paths
    if ep and #ep > 0 then
        local uri = ngx.var.uri or ""
        for _, p in ipairs(ep) do
            if p ~= "" and (uri == p or uri:sub(1, #p) == p) then
                exempt = true
                break
            end
        end
    end
    if not exempt then
        -- 先捕获请求头/请求体：engine.run 内部 BLOCK 动作会直接 ngx.exit(403)，
        -- 因此必须在检测前捕获证据，否则永远执行不到。
        pcall(capture_evidence, ctx)
        local result = engine.run(ruleset, "access", ctx)
        if result == "blocked" or result == "accepted" then
            return
        end
    end
end

-- 3. 人机验证手动触发路径：命中且未通过验证时直接进入验证页（不受 CC 限制）
if cfg.challenge and cfg.challenge.enabled
   and cfg.challenge.trigger_paths and #cfg.challenge.trigger_paths > 0 then
    local ch = require "detectors.challenge"
    if ch.is_triggered(ngx.var.uri or "", cfg.challenge.trigger_paths,
                      ngx.var.host or "", cfg.challenge.trigger_hosts) then
        if not ch.check(ctx, cfg) then
            return  -- 已通过验证，放行
        end
        if ctx.mode == "active" then
            local target = cfg.challenge.page_path .. "?redirect=" .. ngx.escape_uri(ngx.var.request_uri or "/")
            ngx.redirect(target, ngx.HTTP_TEMPORARY_REDIRECT)
            return
        end
        -- detect 模式：仅记录，放行
        return
    end
end

-- 4. CC 防刷
if cfg.modules and cfg.modules.cc_check then
    local cc = require "detectors.cc"
    if cc.check(ctx, cfg) == "banned" then
        if ctx.mode == "active" then
            -- 人机验证：已通过验证（check 返回 nil）则解除封禁放行；否则进入验证页
            if cfg.challenge and cfg.challenge.enabled then
                local ch = require "detectors.challenge"
                if not ch.check(ctx, cfg) then
                    cc.unban(ctx, cfg)
                    return  -- 验证通过，放行
                end
                local target = cfg.challenge.page_path .. "?redirect=" .. ngx.escape_uri(ngx.var.request_uri or "/")
                ngx.redirect(target, ngx.HTTP_TEMPORARY_REDIRECT)
                return
            end
            ngx.exit(503)
        end
        -- detect 模式：仅记录
        return
    end
end

-- 4. 扩展检测器（人机验证、语义增强、上传检测等）后续接入：
--    require("detectors.challenge").check(ctx, cfg)
