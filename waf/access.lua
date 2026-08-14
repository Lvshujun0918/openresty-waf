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
if cfg.challenge then
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

-- 1.5 URL / UA 名单（whitelist 跳过规则检测；blacklist 直接拦截）
local util = require "rule_engine.util"
local uri_for_list = ngx.var.uri or ""
if util.match_regex_list(uri_for_list, cfg.whitelist and cfg.whitelist.urls) then
    ctx.exempt_from_rules = true
elseif util.match_regex_list(ngx.var.http_user_agent or "",
                             cfg.whitelist and cfg.whitelist.user_agents) then
    ctx.exempt_from_rules = true
elseif util.match_regex_list(uri_for_list, cfg.blacklist and cfg.blacklist.urls) then
    if ctx.mode == "active" then
        block(cfg)
    end
    -- detect 模式：仅记录
    return
end

-- 2. 规则引擎（URL / Args / Cookie / Header / Body 等规则，按 Host 过滤站点规则）
local ruleset = engine.get_rules_for_host((ngx.var.host or ""):gsub(":%d+$", ""))
if ruleset then
    -- 豁免：URL/UA 白名单命中 或 exclude_paths 前缀 或 命中 exempt 触发规则
    -- （host/UA/请求头/IP 条件）时跳过规则检测
    local exempt = ctx.exempt_from_rules or false
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
        local trigger = require "rule_engine.trigger"
        exempt = trigger.match_any("exempt", ctx)
    end
    -- 静态资源剪枝：命中后缀/前缀白名单时跳过规则检测（名单/CC/人机验证仍生效）
    local skip_static = false
    if not exempt then
        skip_static = require("rule_engine.util").is_static_path(
            ngx.var.uri, cfg.detection and cfg.detection.skip_static)
    end
    if not exempt and not skip_static then
        -- 先捕获请求头/请求体：engine.run 内部 BLOCK 动作会直接 ngx.exit(403)，
        -- 因此必须在检测前捕获证据，否则永远执行不到。
        pcall(capture_evidence, ctx)
        -- fail-open：规则引擎任何运行错误都不影响业务，记录错误后放行。
        -- ngx.exit 以 Lua 错误形式抛出：配合 _exited 标记区分「正常拦截」与「异常」。
        local ok, result = pcall(engine.run, ruleset, "access", ctx)
        if ok then
            if result == "blocked" or result == "accepted" then
                return
            end
        elseif ctx._exited then
            return  -- 拦截响应已发送
        else
            ngx.log(ngx.ERR, "[waf] 规则引擎执行异常，fail-open 放行: " .. tostring(result))
        end
        -- 上传检测（multipart 文件名后缀 / Content-Type 黑名单），fail-open。
        -- 命中写入 ctx.matched 由 log 阶段统一落盘；active 模式直接拦截。
        local up_cfg = cfg.upload
        if up_cfg and up_cfg.enabled ~= false then
            local up = require "detectors.upload"
            local ok2, hit = pcall(up.check, ctx, up_cfg)
            if ok2 and hit then
                ctx.matched[#ctx.matched + 1] = {
                    id = "UPLOAD", group = "upload", msg = hit, severity = 3,
                }
                if ctx.mode == "active" then
                    block(cfg)
                end
            elseif not ok2 then
                ngx.log(ngx.ERR, "[waf] 上传检测异常，fail-open 放行: " .. tostring(hit))
            end
        end
    end
end

-- 3. 人机验证触发：命中 challenge 触发规则（host/UA/请求头/IP 等条件）且未通过验证时进入验证页。
--    验证模式取规则 config（缺省用全局）；规则级触发不受全局 enabled 开关限制。
if cfg.challenge then
    local ch = require "detectors.challenge"
    local trigger = require "rule_engine.trigger"
    local rule = trigger.match_first("challenge", ctx)
    if rule then
        -- 规则级验证模式（缺省用全局）：浅拷贝构造局部配置，避免修改缓存配置表
        local rule_cfg = rule.config or {}
        local eff_cfg = cfg
        if rule_cfg.mode and rule_cfg.mode ~= cfg.challenge.mode then
            eff_cfg = {}
            for k, v in pairs(cfg) do eff_cfg[k] = v end
            local ch_copy = {}
            for k, v in pairs(cfg.challenge) do ch_copy[k] = v end
            ch_copy.mode = rule_cfg.mode
            eff_cfg.challenge = ch_copy
        end
        -- 未通过验证（无有效 cookie）才进入挑战
        if not ch.check(ctx, eff_cfg, true) then
            return  -- 已通过验证，放行
        end
        -- 记录触发规则名 + 捕获请求证据（供「触发记录」详情）
        ctx.trigger_rule = rule.name
        pcall(capture_evidence, ctx)
        if ctx.mode == "active" then
            local target = cfg.challenge.page_path .. "?redirect=" .. ngx.escape_uri(ngx.var.request_uri or "/")
                .. "&rule=" .. ngx.escape_uri(rule.name or "")
            ngx.redirect(target, ngx.HTTP_TEMPORARY_REDIRECT)
            return
        end
        -- detect 模式：记录一次 issue 事件（含规则名与请求证据）后放行
        ch.record(ctx, "issue")
        return
    end
end

-- 4. CC 防刷：命中 cc 触发规则（host/UA/请求头/IP 等条件）的请求参与限流，
--    频率阈值 / 封禁时长取规则 config（缺省回退全局）
if cfg.cc then
    local cc = require "detectors.cc"
    local trigger = require "rule_engine.trigger"
    local rule = trigger.match_first("cc", ctx)
    if rule then
        local rule_cfg = rule.config or {}
        if cc.check(ctx, cfg, rule_cfg.rate, rule_cfg.ban_duration) == "banned" then
            -- 上报 CC 触发事件（含详细参数）
            pcall(capture_evidence, ctx)
            cc.record(ctx, cfg, rule.name)
            if ctx.mode == "active" then
                -- 人机验证：已通过验证（check 返回 nil）则解除封禁放行；否则进入验证页
                if cfg.challenge and cfg.challenge.enabled then
                    local ch = require "detectors.challenge"
                    if not ch.check(ctx, cfg) then
                        cc.unban(ctx, cfg)
                        return  -- 验证通过，放行
                    end
                    local target = cfg.challenge.page_path .. "?redirect=" .. ngx.escape_uri(ngx.var.request_uri or "/")
                        .. "&rule=" .. ngx.escape_uri(rule.name or "")
                    ngx.redirect(target, ngx.HTTP_TEMPORARY_REDIRECT)
                    return
                end
                ngx.exit(503)
            end
            -- detect 模式：仅记录
            return
        end
    end
end

-- 4. 扩展检测器（人机验证、语义增强、上传检测等）后续接入：
--    require("detectors.challenge").check(ctx, cfg)
