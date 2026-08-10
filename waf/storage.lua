-- storage.lua
-- 共享内存 + Redis 读写封装（纯 Lua，cosocket，不阻塞 worker）。

local _M = {}

local config = require "config"
local cjson  = require "cjson.safe"

local redis = require "resty.redis"

-- ============================================================================
-- 共享内存（lua_shared_dict）
-- ============================================================================

local function get_dict(name)
    return ngx.shared[name]
end

-- 读共享内存
function _M.get_shared(dict_name, key)
    local d = get_dict(dict_name)
    if not d then return nil, "shared dict not found: " .. tostring(dict_name) end
    return d:get(key)
end

-- 写共享内存（exptime=0 表示不过期）
function _M.set_shared(dict_name, key, value, exptime)
    local d = get_dict(dict_name)
    if not d then return nil, "shared dict not found: " .. tostring(dict_name) end
    return d:set(key, value, exptime or 0)
end

-- 原子递增（用于频控/统计计数；key 不存在时以 init 初始化再加 step）
function _M.incr_shared(dict_name, key, step, init, exptime)
    local d = get_dict(dict_name)
    if not d then return nil, "shared dict not found: " .. tostring(dict_name) end
    return d:incr(key, step or 1, init or 0, exptime or 0)
end

-- ============================================================================
-- JSON 序列化（OpenResty 自带 cjson）
-- ============================================================================

function _M.encode(t)
    if type(t) == "string" then return t end
    return cjson.encode(t)
end

function _M.decode(s)
    if not s or s == "" then return nil end
    return cjson.decode(s)
end

-- ============================================================================
-- Redis（cosocket，仅请求阶段 / worker 定时器内可用，init 阶段不可用）
-- ============================================================================

local function connect_redis()
    local red = redis:new()
    red:set_timeouts(config.redis.timeout, config.redis.timeout, config.redis.timeout)

    local ok, err = red:connect(config.redis.host, config.redis.port)
    if not ok then
        return nil, "redis connect failed: " .. tostring(err)
    end

    if config.redis.password then
        local ok2, err2 = red:auth(config.redis.password)
        if not ok2 then
            red:close()
            return nil, "redis auth failed: " .. tostring(err2)
        end
    end

    if config.redis.db and config.redis.db > 0 then
        local ok3, err3 = red:select(config.redis.db)
        if not ok3 then
            red:close()
            return nil, "redis select failed: " .. tostring(err3)
        end
    end

    return red
end

local function release(red)
    red:set_keepalive(config.redis.keepalive_timeout, config.redis.pool_size)
end

-- GET
function _M.redis_get(key)
    local red, err = connect_redis()
    if not red then return nil, err end
    local val, err2 = red:get(key)
    release(red)
    if err2 then return nil, err2 end
    return val
end

-- SET / SETEX
function _M.redis_set(key, value, exptime)
    local red, err = connect_redis()
    if not red then return nil, err end
    local ok2, err2
    if exptime and exptime > 0 then
        ok2, err2 = red:setex(key, exptime, value)
    else
        ok2, err2 = red:set(key, value)
    end
    release(red)
    if not ok2 then return nil, err2 end
    return ok2
end

-- LPUSH（攻击事件缓冲）
function _M.redis_lpush(key, value)
    local red, err = connect_redis()
    if not red then return nil, err end
    local ok2, err2 = red:lpush(key, value)
    release(red)
    if not ok2 then return nil, err2 end
    return ok2
end

-- INCR + 首次设置过期（用于跨 worker 共享的计数）
function _M.redis_incr(key, exptime)
    local red, err = connect_redis()
    if not red then return nil, err end
    local n, err2 = red:incr(key)
    if n == 1 and exptime and exptime > 0 then
        red:expire(key, exptime)
    end
    release(red)
    if err2 then return nil, err2 end
    return n
end

-- ============================================================================
-- 客户端真实 IP（优先 X-Forwarded-For 最左值；仅在可信反代后部署时启用）
-- ============================================================================

function _M.get_client_ip()
    local ip = ngx.var.remote_addr or ""
    local xff = ngx.var.http_x_forwarded_for
    if xff and xff ~= "" then
        local first = xff:match("^%s*([^,%s]+)")
        if first and first ~= "unknown" then
            ip = first
        end
    end
    return ip
end

return _M
