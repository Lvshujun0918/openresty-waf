-- access.lua
-- access_by_lua 检测编排入口。
--
-- nginx.conf:
--   access_by_lua_file /opt/waf/access.lua;

local engine    = require "rule_engine.engine"
local storage   = require "storage"
local operators = require "rule_engine.operators"
local auto_ban  = require "detectors.auto_ban"
local config    = require "config"

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

-- 命中攻击时捕获请求头与请求体（access 阶段执行，供 log 阶段事件详情使用）。
-- 惰性调用：仅规则/触发命中时执行一次（_evidence_captured 幂等标记），
-- 正常流量不做 header 收集与 body 读取。
local function capture_evidence(ctx)
    if ctx._evidence_captured then return end
    ctx._evidence_captured = true
    -- 敏感信息脱敏配置（config.detection.evidence_mask，后台可配置）
    local mask = nil
    local cfg = engine.get_active_config()
    if cfg and cfg.detection then
        mask = cfg.detection.evidence_mask
    end
    local util = require "rule_engine.util"
    local evidence = {}
    -- 请求头：按名称排序，取前 N 个（值打码）
    local all = ngx.req.get_headers()
    local hdrs = {}
    if all then
        for k, v in pairs(all) do
            hdrs[#hdrs + 1] = { name = tostring(k), value = util.mask_sensitive(tostring(v), mask) }
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
            evidence.body = util.mask_sensitive(string.sub(body, 1, EVIDENCE_MAX_BODY), mask)
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

-- 发送拦截响应（wctx 传入时标记 _exited，供外层 fail-open 总闸区分正常拦截与异常）
local function block(cfg, wctx)
    if wctx then wctx._exited = true end
    local status = tonumber(cfg.block and cfg.block.status) or 403
    ngx.status = status
    ngx.header.content_type = "text/html; charset=utf-8"
    ngx.say(cfg.block and cfg.block.html or "Forbidden")
    ngx.exit(status)
end

-- 名单条目解析：
--   "地址" | "地址|unix时间戳" | "地址|UA|unix时间戳"（IP+UA 维度封禁，UA 子串匹配）
-- 临时封禁到期自动跳过。
local function list_entry(entry)
    local addr, ua, ts = tostring(entry):match("^([^|]+)|([^|]*)|(%d+)$")
    if addr then
        if ua and ua ~= "" then
            return addr, tonumber(ts), ua
        end
        return addr, tonumber(ts)
    end
    local addr2, ts2 = tostring(entry):match("^([^|]+)|(%d+)$")
    if addr2 then
        return addr2, tonumber(ts2)
    end
    return tostring(entry), nil
end

-- 名单条目是否命中：UA 维度存在时做子串匹配（UA 精确匹配不可靠）
local function entry_matches(addr, ua, ts, client_ip)
    if not (not ts or ngx.time() < ts) then
        return false
    end
    if not operators.eval("CIDR", client_ip, addr) then
        return false
    end
    if ua then
        local actual = ngx.var.http_user_agent or ""
        if actual == "" or not actual:find(ua, 1, true) then
            return false
        end
    end
    return true
end

-- IP 黑白名单快速检查（白名单优先）
-- 返回 "whitelisted" / "blocked" / nil
local function ip_check(ctx, cfg)
    local wl = cfg.whitelist and cfg.whitelist.ips or {}
    for _, entry in ipairs(wl) do
        local addr, ts, ua = list_entry(entry)
        if entry_matches(addr, ua, ts, ctx.client_ip) then
            return "whitelisted"
        end
    end
    -- 高频攻击自动封禁（白名单不受影响）
    if auto_ban.is_banned(cfg, ctx.client_ip) then
        return "blocked"
    end
    local bl = cfg.blacklist and cfg.blacklist.ips or {}
    for _, entry in ipairs(bl) do
        local addr, ts, ua = list_entry(entry)
        if entry_matches(addr, ua, ts, ctx.client_ip) then
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

-- watchdog：检测耗时超阈值（默认 10ms，config.detection.watchdog_ms 可调）时
-- 强制放行——灾难性回溯/极端慢规则的最后防线，保证单请求延迟有硬上限。
local function watchdog_exceeded()
    local limit = 10
    if cfg.detection and tonumber(cfg.detection.watchdog_ms) then
        limit = tonumber(cfg.detection.watchdog_ms)
    end
    return (ngx.now() - ctx.start_time) * 1000 > limit
end

-- 第 3 段：人机验证触发规则。返回 true 表示本请求已处置完毕（放行/跳转/记录）
local function challenge_section()
    if not cfg.challenge then return false end
    local ch = require "detectors.challenge"
    local trigger = require "rule_engine.trigger"
    local rule = trigger.match_first("challenge", ctx)
    if not rule then return false end
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
        return true  -- 已通过验证，放行
    end
    -- 记录触发规则名 + 捕获请求证据（供「触发记录」详情）
    ctx.trigger_rule = rule.name
    pcall(capture_evidence, ctx)
    if ctx.mode == "active" then
        local target = cfg.challenge.page_path .. "?redirect=" .. ngx.escape_uri(ngx.var.request_uri or "/")
            .. "&rule=" .. ngx.escape_uri(rule.name or "")
        ngx.redirect(target, ngx.HTTP_TEMPORARY_REDIRECT)
        return true
    end
    -- detect 模式：记录一次 issue 事件（含规则名与请求证据）后放行
    ch.record(ctx, "issue")
    return true
end

-- 第 4 段：CC 防刷。返回 true 表示本请求已处置完毕
local function cc_section()
    if not cfg.cc then return false end
    local cc = require "detectors.cc"
    local trigger = require "rule_engine.trigger"
    local rule = trigger.match_first("cc", ctx)
    if not rule then return false end
    local rule_cfg = rule.config or {}
    local dims = rule_cfg.dims
    if type(dims) ~= "table" then dims = nil end
    if cc.check(ctx, cfg, rule_cfg.rate, rule_cfg.ban_duration, dims) == "banned" then
        -- 上报 CC 触发事件（含详细参数）
        pcall(capture_evidence, ctx)
        cc.record(ctx, cfg, rule.name)
        if ctx.mode == "active" then
            -- 人机验证：已通过验证（check 返回 nil）则解除封禁放行；否则进入验证页
            if cfg.challenge and cfg.challenge.enabled then
                local ch = require "detectors.challenge"
                if not ch.check(ctx, cfg) then
                    cc.unban(ctx, cfg)
                    return true  -- 验证通过，放行
                end
                local target = cfg.challenge.page_path .. "?redirect=" .. ngx.escape_uri(ngx.var.request_uri or "/")
                    .. "&rule=" .. ngx.escape_uri(rule.name or "")
                ngx.redirect(target, ngx.HTTP_TEMPORARY_REDIRECT)
                return true
            end
            ctx._exited = true
            ngx.exit(503)
        end
        -- detect 模式：仅记录
        return true
    end
    return false
end

-- 检测主流程（外层由 pcall 总闸保护：任何未捕获异常均 fail-open 放行）
local function protection_flow()
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

    -- 1. IP 黑白名单（检查异常按无命中处理）
    local ok, ip_result = pcall(ip_check, ctx, cfg)
    if not ok then
        ngx.log(ngx.ERR, "[waf] IP 名单检查异常，fail-open 放行: ", tostring(ip_result))
        ip_result = nil
    end
    if ip_result == "whitelisted" then
        return
    elseif ip_result == "blocked" then
        if ctx.mode == "active" then
            block(cfg, ctx)
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
            block(cfg, ctx)
        end
        -- detect 模式：仅记录
        return
    end

    -- 1.6 恶意指纹拦截（HTTP 客户端指纹命中恶意指纹库；库为空时零开销）
    local fingerprint = require "fingerprint"
    local fp_hit = fingerprint.match_malicious(ctx, fingerprint.get(ctx))
    if fp_hit then
        ctx.fp_malicious = fp_hit
        ctx.matched[#ctx.matched + 1] = {
            id = "FP-BLOCK", group = "fingerprint", severity = 3,
            msg = "恶意指纹拦截: " .. tostring(fp_hit),
        }
        if ctx.mode == "active" then
            block(cfg, ctx)
        end
        -- detect 模式：仅记录（log 阶段落盘）
        return
    end

    -- 1.7 爬虫识别（仅统计与标记，不阻断；拦截交由触发规则的 ua 条件或指纹库）
    if config.bot and config.bot.enabled ~= false then
        local okb7, botres = pcall(function()
            return require("detectors.bot").classify(ctx)
        end)
        if okb7 and botres then
            ctx.bot_result = botres
        elseif not okb7 then
            ngx.log(ngx.ERR, "[waf] 爬虫识别异常: ", tostring(botres))
        end
    end

    -- 1.8 触发规则拦截（kind=block：host/UA/请求头/IP 等条件命中即拦截，
    --     可用于爬虫/采集器分级处置；detect 模式仅记录事件）
    local okb, ruleb = pcall(function()
        return require("rule_engine.trigger").match_first("block", ctx)
    end)
    if not okb then
        ngx.log(ngx.ERR, "[waf] block 触发规则检查异常，fail-open 放行: ", tostring(ruleb))
    elseif ruleb then
        ctx.matched[#ctx.matched + 1] = {
            id = "TRIGGER-BLOCK", group = "trigger", severity = 3,
            msg = "触发规则拦截: " .. tostring(ruleb.name),
        }
        if ctx.mode == "active" then
            block(cfg, ctx)
        end
        -- detect 模式：仅记录（log 阶段落盘）
        return
    end

    -- 2. 规则引擎（URL / Args / Cookie / Header / Body 等规则；按 phase 预过滤复用）
    local phase_rules = engine.get_phase_rules("access")
    if phase_rules and #phase_rules > 0 then
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
            -- 注入惰性证据捕获：engine.run 内部 BLOCK 动作会直接 ngx.exit(403)，
            -- 因此捕获只能在规则命中时由引擎回调触发（record_hit），否则永远执行不到。
            ctx.capture_evidence = capture_evidence
            -- fail-open：规则引擎任何运行错误都不影响业务，记录错误后放行。
            -- ngx.exit 以 Lua 错误形式抛出：配合 _exited 标记区分「正常拦截」与「异常」。
            local ok2, result = pcall(engine.run, { rules = phase_rules }, "access", ctx)
            if ok2 then
                if result == "blocked" or result == "accepted" then
                    return
                end
            elseif ctx._exited then
                return  -- 拦截响应已发送
            else
                ngx.log(ngx.ERR, "[waf] 规则引擎执行异常，fail-open 放行: " .. tostring(result))
            end
            -- watchdog：规则引擎/上传检测超时则跳过后续检测强制放行
            if watchdog_exceeded() then
                ngx.log(ngx.ERR, "[waf] 检测耗时超过 watchdog 阈值，强制放行")
                return
            end
            -- 上传检测（multipart 文件名后缀 / Content-Type 黑名单），fail-open。
            -- 命中写入 ctx.matched 由 log 阶段统一落盘；active 模式直接拦截。
            local up_cfg = cfg.upload
            if up_cfg and up_cfg.enabled ~= false then
                local up = require "detectors.upload"
                local ok3, hit = pcall(up.check, ctx, up_cfg)
                if ok3 and hit then
                    ctx.matched[#ctx.matched + 1] = {
                        id = "UPLOAD", group = "upload", msg = hit, severity = 3,
                    }
                    if ctx.mode == "active" then
                        block(cfg, ctx)
                    end
                elseif not ok3 then
                    ngx.log(ngx.ERR, "[waf] 上传检测异常，fail-open 放行: " .. tostring(hit))
                end
            end
        end
    end

    -- 3. 人机验证触发（fail-open：检查异常视为未命中）
    local ok4, stop = pcall(challenge_section)
    if not ok4 then
        ngx.log(ngx.ERR, "[waf] 人机验证触发检查异常，fail-open 放行: ", tostring(stop))
    elseif stop then
        return
    end

    -- 4. CC 防刷（fail-open：检查异常视为未命中）
    local ok5, stop5 = pcall(cc_section)
    if not ok5 then
        ngx.log(ngx.ERR, "[waf] CC 检查异常，fail-open 放行: ", tostring(stop5))
    elseif stop5 then
        return
    end
end

-- fail-open 总闸：access 阶段任何未捕获异常都不影响业务，记录错误后放行。
-- ngx.exit 以 Lua 错误形式抛出：配合 ctx._exited 标记区分「正常拦截」与「异常」。
local ok, err = pcall(protection_flow)
if not ok then
    if ctx._exited then
        return  -- 拦截响应已发送
    end
    ngx.log(ngx.ERR, "[waf] access 阶段检测异常，fail-open 放行: ", tostring(err))
end
