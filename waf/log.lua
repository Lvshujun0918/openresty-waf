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

-- 组装事件列表（数据在 access 阶段已缓存到 ctx，log 阶段不依赖请求对象）
local function build_events(ctx)
    local events = {}
    for _, m in ipairs(ctx.matched or {}) do
        events[#events + 1] = {
            time      = os.date("%Y-%m-%dT%H:%M:%S"),
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

-- ============================================================================

local ctx = ngx.ctx.waf_ctx
if not ctx or not ctx.matched or #ctx.matched == 0 then
    return
end

local cfg = require("rule_engine.engine").get_active_config()
if not (cfg.log and cfg.log.enabled) then
    return
end

local events = build_events(ctx)
local backend = cfg.log.backend or "file"

if backend == "redis" then
    local key = cfg.log.redis_key or "waf:event:list"
    for _, ev in ipairs(events) do
        storage.redis_lpush(key, cjson.encode(ev))
    end
else
    for _, ev in ipairs(events) do
        write_file(cfg, cjson.encode(ev))
    end
end
