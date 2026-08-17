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

-- 写共享内存（exptime=0 表示不过期）。
-- value 为 nil 时执行删除语义（真实 lua-nginx-module 下 dict:set 传 nil 会抛错，
-- 删除需走 dict:delete；如 CC 解封路径）
function _M.set_shared(dict_name, key, value, exptime)
    local d = get_dict(dict_name)
    if not d then return nil, "shared dict not found: " .. tostring(dict_name) end
    if value == nil then
        return d:delete(key)
    end
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

-- 生效的 Redis 连接配置：优先共享内存 active_config（含后台下发），
-- 回退到 config.lua（含 config_local 部署覆盖）
local function effective_redis()
    local d = ngx.shared[config.dict.rules]
    if d then
        local raw = d:get("active_config")
        local cfg = raw and cjson.decode(raw)
        if cfg and cfg.redis then
            return cfg.redis
        end
    end
    return config.redis
end

local function connect_redis()
    local rc = effective_redis()
    local red = redis:new()
    red:set_timeouts(rc.timeout, rc.timeout, rc.timeout)

    local ok, err = red:connect(rc.host, rc.port)
    if not ok then
        return nil, "redis connect failed: " .. tostring(err)
    end

    if rc.password then
        local ok2, err2 = red:auth(rc.password)
        if not ok2 then
            red:close()
            return nil, "redis auth failed: " .. tostring(err2)
        end
    end

    if rc.db and rc.db > 0 then
        local ok3, err3 = red:select(rc.db)
        if not ok3 then
            red:close()
            return nil, "redis select failed: " .. tostring(err3)
        end
    end

    return red, rc
end

-- 归还连接到池：参数必须与建立连接时使用的生效配置一致
-- （连接可能来自后台下发的 active_config，静态 config.redis 的
-- keepalive_timeout/pool_size 可能与实际不符）
local function release(red, rc)
    rc = rc or config.redis
    red:set_keepalive(rc.keepalive_timeout or 60, rc.pool_size or 100)
end

-- GET
function _M.redis_get(key)
    local red, rc = connect_redis()
    if not red then return nil, rc end
    local val, err2 = red:get(key)
    release(red, rc)
    if err2 then return nil, err2 end
    -- lua-resty-redis 对不存在的键返回 ngx.null（userdata），统一归一为 nil。
    -- 否则调用方把 ngx.null 误判为"有值"，会继续读取并因 JSON 解析失败误报"规则集非法"。
    if val == ngx.null then
        return nil
    end
    return val
end

-- SET / SETEX
function _M.redis_set(key, value, exptime)
    local red, rc = connect_redis()
    if not red then return nil, rc end
    local ok2, err2
    if exptime and exptime > 0 then
        ok2, err2 = red:setex(key, exptime, value)
    else
        ok2, err2 = red:set(key, value)
    end
    release(red, rc)
    if not ok2 then return nil, err2 end
    return ok2
end

-- LPUSH（攻击事件缓冲）
function _M.redis_lpush(key, value)
    local red, rc = connect_redis()
    if not red then return nil, rc end
    local ok2, err2 = red:lpush(key, value)
    release(red, rc)
    if not ok2 then return nil, err2 end
    return ok2
end

-- DEL（CC 解封等）
function _M.redis_del(key)
    local red, rc = connect_redis()
    if not red then return nil, rc end
    local ok2, err2 = red:del(key)
    release(red, rc)
    if not ok2 then return nil, err2 end
    return ok2
end

-- RPUSH + 可选 LTRIM（实时统计列表：追加后裁剪到 maxlen 防无限增长）
function _M.redis_rpush_trim(key, value, maxlen)
    local red, rc = connect_redis()
    if not red then return nil, rc end
    local ok2, err2 = red:rpush(key, value)
    if ok2 and maxlen and maxlen > 0 then
        red:ltrim(key, -maxlen, -1)
    end
    release(red, rc)
    if not ok2 then return nil, err2 end
    return ok2
end

-- INCR + 首次设置过期（用于跨 worker 共享的计数）
function _M.redis_incr(key, exptime)
    local red, rc = connect_redis()
    if not red then return nil, rc end
    local n, err2 = red:incr(key)
    if n == 1 and exptime and exptime > 0 then
        red:expire(key, exptime)
    end
    release(red, rc)
    if err2 then return nil, err2 end
    return n
end

-- ============================================================================
-- 客户端真实 IP（优先 X-Forwarded-For 最左值）
-- 仅当直连地址命中 config.trusted_proxies 时才信任 XFF；
-- 列表为空视为未配置可信代理（安全默认），不信任任何 XFF。
-- ============================================================================

--- IP 合法性校验（IPv4 四段 0-255 / IPv6 含冒号合法字符），
--- 防止 XFF / 自定义头中的脏值（如 ";|true"）进入 IP 维度防护。
local function valid_ip(v)
    if not v then return false end
    local a, b, c, d = v:match("^(%d+)%.(%d+)%.(%d+)%.(%d+)$")
    if a then
        return a:len() <= 3 and b:len() <= 3 and c:len() <= 3 and d:len() <= 3
            and tonumber(a) <= 255 and tonumber(b) <= 255
            and tonumber(c) <= 255 and tonumber(d) <= 255
    end
    if v:find(":") then
        return v:match("^[0-9a-fA-F:%.%%]+$") ~= nil
    end
    return false
end

--- 直连地址是否在可信代理列表中。
--- 列表为空 → 无条件信任 X-Forwarded-For（兼容旧行为；面向 CDN/反代
--- 回源 IP 不公开的部署，如腾讯云 EdgeOne；公网直连部署建议把
--- 反代/CDN 回源 IP 填入以防伪造 XFF 绕过 IP 名单 / CC / 封禁）。
local function is_trusted_proxy(ip)
    local list = config.trusted_proxies
    if not list or #list == 0 then
        return true
    end
    local operators = require "rule_engine.operators"
    for _, entry in ipairs(list) do
        if operators.eval("CIDR", ip, entry) then
            return true
        end
    end
    return false
end

function _M.get_client_ip()
    local ip = ngx.var.remote_addr or ""
    -- 自定义来源 IP 头优先（CDN 场景，如腾讯云 EdgeOne 的 eo-connecting-ip）：
    -- 仅接受合法 IP 值，非法时回退后续解析，防伪造脏值。
    local hcfg = config.client_ip_header
    if hcfg and hcfg ~= "" then
        local hdr = ngx.req.get_headers()[string.lower(hcfg)]
        if hdr and hdr ~= "" then
            local cand = hdr:match("^%s*([^,%s]+)")
            if cand and cand ~= "unknown" and valid_ip(cand) then
                return cand
            end
        end
    end
    local xff = ngx.var.http_x_forwarded_for
    if xff and xff ~= "" and is_trusted_proxy(ip) then
        local first = xff:match("^%s*([^,%s]+)")
        if first and first ~= "unknown" and valid_ip(first) then
            ip = first
        end
    end
    return ip
end

return _M
