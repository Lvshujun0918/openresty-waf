-- detectors/cc.lua
-- CC 防刷：基于共享内存计数，同 IP 同 URI 超频后临时封禁该 IP。
-- 计数使用 lua_shared_dict 原子 incr，跨 worker 一致。

local _M = {}

local config  = require "config"
local storage = require "storage"

-- 解析 "count/seconds" 形式阈值，缺省 100/60
local function parse_rate(rate)
    local count, seconds = rate:match("^(%d+)/(%d+)$")
    if not count or not seconds then
        return 100, 60
    end
    return tonumber(count), tonumber(seconds)
end

-- 该 IP 是否在封禁期
local function is_banned(cfg, ip)
    local key = (cfg.cc.ban_key_prefix or "waf:cc:ban:") .. ip
    return storage.get_shared(config.dict.counter, key) ~= nil
end

-- 执行 CC 检查：
-- 返回 "banned"（触发封禁或已在封禁期）/ nil（正常）
function _M.check(waf_ctx, cfg)
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

    local count, seconds = parse_rate(cfg.cc.rate or "100/60")
    -- 使用不含 query string 的路径作为计数维度
    local path = (waf_ctx.request and waf_ctx.request.path) or "/"
    local counter_key = (cfg.cc.counter_prefix or "waf:cc:cnt:") .. ip .. ":" .. path

    local n = storage.incr_shared(config.dict.counter, counter_key, 1, 0, seconds)
    if n and n >= count then
        -- 触发封禁
        local ban_key = (cfg.cc.ban_key_prefix or "waf:cc:ban:") .. ip
        storage.set_shared(config.dict.counter, ban_key, ngx.time(),
                           cfg.cc.ban_duration or 300)
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
