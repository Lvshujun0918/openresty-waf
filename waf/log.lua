-- log.lua
-- log_by_lua 日志入口：将本请求命中的攻击事件写入日志。
--
-- nginx.conf:
--   log_by_lua_file /opt/waf/log.lua;
--
-- 后端支持：
--   "file"   本地文件（按天分文件，io 追加写）
--   "redis"  推送到 Redis 列表（由后台消费落库）

local storage = require "storage"
local config  = require "config"
local cjson   = require "cjson.safe"

-- 查询 IP 归属（数据可用时；log 阶段微秒级，失败返回 nil 优雅降级）
local function lookup_geo(ip)
    if not ip or ip == "" then return nil end
    local ok, geo = pcall(function()
        return require("ip_region").lookup(ip)
    end)
    if ok and geo then return geo end
    return nil
end

-- 本地时区偏移（如 +08:00），保证入库时间为本地时间而非 UTC
local function tz_offset()
    local now = os.time()
    local utc = os.time(os.date("!*t", now))
    local diff = os.difftime(now, utc)
    local sign = diff < 0 and "-" or "+"
    local a = math.abs(diff)
    return string.format("%s%02d:%02d", sign, math.floor(a / 3600), math.floor((a % 3600) / 60))
end

-- 本地时间戳（RFC3339 带时区偏移）
local function ts_now()
    return os.date("%Y-%m-%dT%H:%M:%S") .. tz_offset()
end

-- 组装单条攻击事件：一个请求最多一条（即使命中多条规则）。
-- 主命中取 severity 最高者（同级别取先命中），rule_ids 列出全部命中；
-- rules / headers / body 为 JSON 文本，供事件详情展示。
local function build_event(ctx)
    local geo = lookup_geo(ctx.client_ip)
    local matches = ctx.matched or {}
    local primary = matches[1]
    local rule_ids = {}
    local rules = {}
    for _, m in ipairs(matches) do
        rule_ids[#rule_ids + 1] = m.id
        rules[#rules + 1] = {
            id       = m.id,
            group    = m.group,
            msg      = m.msg,
            severity = m.severity,
        }
        if primary == nil or (m.severity or 0) > (primary.severity or 0) then
            primary = m
        end
    end
    local evidence = ctx.evidence or {}
    return {
        time      = ts_now(),   -- 本地时间（带时区偏移）
        req_id    = ctx.req_id or "",
        ts        = ngx.now(),
        client_ip = ctx.client_ip,
        engine_version = config.version or "",
        method    = ctx.request and ctx.request.method,
        host      = ctx.request and ctx.request.host,
        uri       = ctx.request and ctx.request.uri,
        rule_id   = primary and primary.id,
        rule_ids  = table.concat(rule_ids, ","),
        rules     = cjson.encode(rules),
        headers   = cjson.encode(evidence.headers or {}),
        body      = evidence.body or "",
        group     = primary and primary.group,
        msg       = primary and primary.msg,
        severity  = primary and primary.severity,
        status    = ngx.status,
        blocked   = ctx._exited == true,   -- 是否 WAF 真正拦截（拦截响应由引擎发出），404 等后端状态码不算
        ja4       = (ctx.ja4 and ctx.ja4 ~= "" and ctx.ja4) or ctx.tls_fp or "",
        ja4h      = ctx.ja4h or "",
        country   = geo and geo.country or "",
        province  = geo and geo.province or "",
        city      = geo and geo.city or "",
    }
end

-- file 后端：按天追加写。
-- 模块级句柄缓存（log 阶段单 worker 串行，句柄可跨请求复用），
-- 避免攻击风暴下每个事件 open/close 文件的开销；按天/目录变化自动切换。
local log_handle, log_day, log_dir

local function write_file(cfg, line)
    local dir = cfg.log.dir or "/var/log/waf"
    local day = os.date("%Y%m%d")
    if log_day ~= day or log_dir ~= dir then
        if log_handle then
            pcall(io.close, log_handle)
            log_handle = nil
        end
        local path = dir .. "/waf_" .. day .. ".log"
        local f, err = io.open(path, "a")
        if not f then
            ngx.log(ngx.WARN, "[waf] 打开日志文件失败: ", tostring(err))
            return
        end
        log_handle, log_day, log_dir = f, day, dir
    end
    -- 写失败（如句柄被外部关闭）时关闭句柄重开一次
    local ok, werr = pcall(log_handle.write, log_handle, line, "\n")
    if not ok then
        pcall(io.close, log_handle)
        log_handle = nil
        local path = dir .. "/waf_" .. day .. ".log"
        local f, err = io.open(path, "a")
        if not f then
            ngx.log(ngx.WARN, "[waf] 重新打开日志文件失败: ", tostring(err))
            return
        end
        log_handle, log_day, log_dir = f, day, dir
        pcall(log_handle.write, log_handle, line, "\n")
    end
    pcall(log_handle.flush, log_handle)
end

-- redis 后端：经 ngx.timer 异步推送（log 阶段禁用 TCP cosocket，
-- 定时器回调中可用），不阻塞请求收尾。items 为 { key, payload } 数组，
-- 一次 timer 内完成多条推送（同一请求的 traffic + 事件可合并）。
local function push_to_redis(premature, items)
    if premature then return end
    local storage = require "storage"
    for _, it in ipairs(items) do
        storage.redis_lpush(it.key, it.payload)
    end
end

-- ============================================================================

local ctx = ngx.ctx.waf_ctx
local cfg = require("rule_engine.engine").get_active_config()

-- ===== 实时统计计数（秒级共享内存窗口，init_worker 定时器聚合上报） =====
if config.stats and config.stats.enabled ~= false then
    local sec = os.time()
    storage.incr_shared(config.dict.counter, "st:" .. sec, 1, 0, 2)
    if ctx and ctx.matched and #ctx.matched > 0 then
        storage.incr_shared(config.dict.counter, "stb:" .. sec, 1, 0, 2)
    end
end

-- crawler_only：本请求仅命中 crawler 组规则（如空 UA/爬虫指纹）。爬虫不算攻击：
-- 不生成攻击事件，但作为爬虫记录上报（即使 bot 画像未命中，如空 UA 场景）。
local crawler_only = false
if ctx and ctx.matched and #ctx.matched > 0 then
    crawler_only = true
    for _, m in ipairs(ctx.matched) do
        if m.group ~= "crawler" then
            crawler_only = false
            break
        end
    end
end

-- 本请求待上报的 Redis 负载（traffic + 攻击事件合并为一次 timer 推送，
-- 攻击风暴下减少 timer 数量与 Redis 连接往返）
local pending = {}

-- 合并推送（在可能提前 return 的路径前调用，确保 traffic/爬虫记录不丢失）
local function flush_pending()
    if #pending > 0 then
        local ok, err = ngx.timer.at(0, push_to_redis, pending)
        if not ok then
            ngx.log(ngx.ERR, "[waf] 调度事件上报失败: ", tostring(err))
        end
        pending = {}
    end
end

-- ===== 全量流量记录（可选）：开启后每个请求上报一条（含是否命中攻击） =====
local traffic = cfg.traffic_log
if traffic and traffic.enabled then
    local rule_ids = {}
    if ctx and ctx.matched then
        for _, m in ipairs(ctx.matched) do
            rule_ids[#rule_ids + 1] = m.id
        end
    end
    local geo = lookup_geo(ctx and ctx.client_ip or nil)
    local rec = {
        time          = ts_now(),  -- 本地时间（带时区偏移）
        req_id        = ctx and ctx.req_id or "",
        client_ip     = ctx and ctx.client_ip or "",
        method        = ctx and ctx.request and ctx.request.method or "",
        host          = ctx and ctx.request and ctx.request.host or "",
        uri           = ctx and ctx.request and ctx.request.uri or "",
        status        = ngx.status,
        user_agent    = ngx.var.http_user_agent or "",
        attack        = ctx and ctx.matched and #ctx.matched > 0 and not crawler_only,
        rule_ids      = table.concat(rule_ids, ","),
        response_time = ctx and ((ngx.now() - ctx.start_time) * 1000) or 0,
        country       = geo and geo.country or "",
        province      = geo and geo.province or "",
        city          = geo and geo.city or "",
    }
    pending[#pending + 1] = { key = traffic.redis_key or "waf:traffic:list",
                              payload = cjson.encode(rec) }
end

-- ===== 爬虫识别记录（可选：识别为爬虫的请求上报一条，供后台爬虫统计页） =====
if ctx and (ctx.bot_result or crawler_only) then
    local bot = ctx.bot_result or {}
    local geo = lookup_geo(ctx.client_ip)
    local okb, malicious_ip = pcall(function()
        return require("detectors.bot").is_malicious_ip(ctx)
    end)
    if not okb then malicious_ip = false end
    local rec = {
        time         = ts_now(),
        req_id       = ctx.req_id or "",
        client_ip    = ctx.client_ip or "",
        country      = geo and geo.country or "",
        province     = geo and geo.province or "",
        city         = geo and geo.city or "",
        method       = ctx.request and ctx.request.method or "",
        host         = ctx.request and ctx.request.host or "",
        uri          = ctx.request and ctx.request.uri or "",
        ua           = ngx.var.http_user_agent or "",
        fingerprint  = ctx.fingerprint or "",
        ja4          = (ctx.ja4 and ctx.ja4 ~= "" and ctx.ja4) or ctx.tls_fp or "",
        ja4h         = ctx.ja4h or "",
        profile      = bot.profile or "",
        engine       = bot.engine and true or false,
        fake         = bot.fake and true or false,
        malicious_ip = malicious_ip and true or false,
        malicious_fp = ctx.fp_malicious or "",
        fp_source    = ctx.fp_source or "",
        headers      = cjson.encode((ctx.evidence and ctx.evidence.headers) or {}),
        body         = (ctx.evidence and ctx.evidence.body) or "",
        status       = ngx.status,
    }
    pending[#pending + 1] = { key = config.bot.report_key or "waf:bot:list",
                              payload = cjson.encode(rec) }
end

-- ===== 攻击事件 =====
if not ctx or not ctx.matched or #ctx.matched == 0 then
    flush_pending()  -- 普通请求：确保 traffic / 爬虫记录已推送
    return
end

-- 爬虫命中不算攻击：仅 crawler 组命中不生成攻击事件
-- （爬虫记录已在上文 bot_result/crawler_only 分支上报）
if crawler_only then
    flush_pending()
    return
end

if not (cfg.log and cfg.log.enabled) then
    flush_pending()
    return
end

local event = build_event(ctx)
local backend = cfg.log.backend or "file"

if backend == "redis" then
    pending[#pending + 1] = { key = cfg.log.redis_key or "waf:event:list",
                              payload = cjson.encode(event) }
else
    write_file(cfg, cjson.encode(event))
end

-- 合并推送：traffic + 攻击事件一次 timer 完成，避免逐条连接往返
flush_pending()

-- ===== 高频攻击自动封禁计数（仅拦截模式；达到阈值自动临时封禁该 IP） =====
if cfg.mode == "active" and ctx and ctx.client_ip then
    local ok2, banned = pcall(function()
        return require("detectors.auto_ban").record_hit(cfg, ctx.client_ip)
    end)
    if ok2 and banned then
        ngx.log(ngx.WARN, "[waf] 高频攻击自动封禁: ", ctx.client_ip)
    elseif not ok2 then
        ngx.log(ngx.ERR, "[waf] 自动封禁计数异常: ", tostring(banned))
    end
end
