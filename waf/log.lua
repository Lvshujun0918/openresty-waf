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

-- 组装事件列表（数据在 access 阶段已缓存到 ctx，log 阶段不依赖请求对象）
local function build_events(ctx)
    local events = {}
    local geo = lookup_geo(ctx.client_ip)
    for _, m in ipairs(ctx.matched or {}) do
        events[#events + 1] = {
            time      = os.date("!%Y-%m-%dT%H:%M:%SZ"),  -- RFC3339 UTC
            ts        = ngx.now(),
            client_ip = ctx.client_ip,
            method    = ctx.request and ctx.request.method,
            host      = ctx.request and ctx.request.host,
            uri       = ctx.request and ctx.request.uri,
            rule_id   = m.id,
            group     = m.group,
            msg       = m.msg,
            severity  = m.severity,
            status    = ngx.status,
            country   = geo and geo.country or "",
            province  = geo and geo.province or "",
            city      = geo and geo.city or "",
        }
    end
    return events
end

-- file 后端：按天追加写
local function write_file(cfg, line)
    local dir = cfg.log.dir or "/var/log/waf"
    local path = dir .. "/waf_" .. os.date("%Y%m%d") .. ".log"
    local f, err = io.open(path, "a")
    if not f then
        ngx.log(ngx.WARN, "[waf] 打开日志文件失败: ", tostring(err))
        return
    end
    f:write(line, "\n")
    f:close()
end

-- redis 后端：经 ngx.timer 异步推送（log 阶段禁用 TCP cosocket，
-- 定时器回调中可用），不阻塞请求收尾。
local function push_to_redis(premature, key, payloads)
    if premature then return end
    local storage = require "storage"
    for _, raw in ipairs(payloads) do
        storage.redis_lpush(key, raw)
    end
end

-- ============================================================================

local ctx = ngx.ctx.waf_ctx
local cfg = require("rule_engine.engine").get_active_config()

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
        time          = os.date("!%Y-%m-%dT%H:%M:%SZ"),  -- RFC3339 UTC
        client_ip     = ctx and ctx.client_ip or "",
        method        = ctx and ctx.request and ctx.request.method or "",
        host          = ctx and ctx.request and ctx.request.host or "",
        uri           = ctx and ctx.request and ctx.request.uri or "",
        status        = ngx.status,
        user_agent    = ngx.var.http_user_agent or "",
        attack        = ctx and ctx.matched and #ctx.matched > 0,
        rule_ids      = table.concat(rule_ids, ","),
        response_time = ctx and ((ngx.now() - ctx.start_time) * 1000) or 0,
        country       = geo and geo.country or "",
        province      = geo and geo.province or "",
        city          = geo and geo.city or "",
    }
    local key = traffic.redis_key or "waf:traffic:list"
    local ok, err = ngx.timer.at(0, push_to_redis, key, { cjson.encode(rec) })
    if not ok then
        ngx.log(ngx.ERR, "[waf] 调度流量记录上报失败: ", tostring(err))
    end
end

-- ===== 攻击事件 =====
if not ctx or not ctx.matched or #ctx.matched == 0 then
    return
end

if not (cfg.log and cfg.log.enabled) then
    return
end

local events = build_events(ctx)
local backend = cfg.log.backend or "file"

if backend == "redis" then
    local key = cfg.log.redis_key or "waf:event:list"
    local payloads = {}
    for _, ev in ipairs(events) do
        payloads[#payloads + 1] = cjson.encode(ev)
    end
    local ok, err = ngx.timer.at(0, push_to_redis, key, payloads)
    if not ok then
        ngx.log(ngx.ERR, "[waf] 调度事件上报失败: ", tostring(err))
    end
else
    for _, ev in ipairs(events) do
        write_file(cfg, cjson.encode(ev))
    end
end
