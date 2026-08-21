-- hit_cache.lua
-- 命中缓存：同一请求指纹（版本+模式+方法+host+IP+URI+全部请求头）的规则引擎判定
-- 短时缓存（shared dict TTL），重复请求跳过规则扫描。
--
-- 设计边界（安全优先）：
--   * 仅缓存「规则引擎」一段的判定结果；IP 名单/自动封禁/恶意指纹/触发规则/
--     上传检测/人机验证/CC 等有状态或独立判定层每请求照常执行，不受缓存影响。
--   * 缓存键包含 ruleset_version：规则发布/回滚后旧键自然失配（TTL 内也不会误复用）。
--   * 缓存键包含 mode 与全部请求头指纹：UA/Cookie/自定义头任一差异 → 不同键。
--   * 仅无请求体方法（GET/HEAD/OPTIONS）参与缓存，规避 body 差异导致的误复用。
--   * 拦截判定同样缓存（含主命中条目重建），重复攻击请求直接复用拦截响应。

local config  = require "config"
local storage = require "storage"

local _M = {}

-- 参与缓存的方法（无请求体）
local CACHEABLE_METHODS = {
    GET     = true,
    HEAD    = true,
    OPTIONS = true,
}

-- URI 键长度护栏：超长 URI 不缓存（防 shared dict 键膨胀）
local MAX_URI_LEN = 2048

function _M.enabled(cfg)
    local hc = cfg and cfg.hit_cache
    return hc ~= nil and hc.enabled == true
end

-- 请求是否可缓存
function _M.cacheable(ctx)
    if not CACHEABLE_METHODS[ctx.request.method] then return false end
    local uri = ctx.request.uri or ""
    if #uri > MAX_URI_LEN then return false end
    return true
end

-- 缓存键：ruleset_version | mode | method | host | ip | uri(含 args) | 请求头指纹
function _M.cache_key(cfg, ctx)
    local version = storage.get_shared(config.dict.rules, "ruleset_version") or ""
    local parts = {
        version,
        ctx.mode or "",
        ctx.request.method or "",
        ctx.request.host or "",
        ctx.client_ip or "",
        ctx.request.uri or "",
    }
    -- 全部请求头按名称排序拼接：UA/Cookie/Referer/自定义头差异都会改变指纹
    local hdrs = {}
    local all = ngx.req.get_headers()
    if all then
        for k, v in pairs(all) do
            if type(v) == "table" then
                hdrs[#hdrs + 1] = tostring(k) .. "=" .. table.concat(v, ",")
            else
                hdrs[#hdrs + 1] = tostring(k) .. "=" .. tostring(v)
            end
        end
        table.sort(hdrs)
    end
    parts[#parts + 1] = table.concat(hdrs, "&")
    return "hc:" .. ngx.md5(table.concat(parts, "|"))
end

local function dict_get()
    return ngx.shared[config.dict.counter]
end

local function bump(dict, key)
    -- 统计计数允许并发丢增（仅观测用），避免 incr 兼容性问题
    local n = tonumber(dict:get(key) or 0) + 1
    dict:set(key, n)
end

-- 查询缓存。返回 nil（未命中/不可缓存）或 { blocked = bool, matched = {...}|nil }
function _M.lookup(cfg, ctx)
    if not _M.enabled(cfg) or not _M.cacheable(ctx) then return nil end
    local dict = dict_get()
    if not dict then return nil end
    local v = dict:get(_M.cache_key(cfg, ctx))
    if v == nil then
        bump(dict, "hc:stat:misses")
        return nil
    end
    bump(dict, "hc:stat:hits")
    if v == "A" then
        return { blocked = false }
    end
    -- "B" 前缀：cjson 编码 {m = 主命中条目}
    local payload = v:sub(2)
    local ok, decoded = pcall(require("cjson").decode, payload)
    if not ok or type(decoded) ~= "table" then
        return nil  -- 坏值按未命中处理
    end
    return { blocked = true, matched = decoded.m }
end

-- 写入缓存。blocked=false 存 "A"；blocked=true 存 "B"+JSON（主命中条目）。
-- primary_matched 为命中时取 ctx.matched 中 severity 最高条目（由调用方挑选传入）。
function _M.store(cfg, ctx, blocked, primary_matched)
    if not _M.enabled(cfg) or not _M.cacheable(ctx) then return end
    local ttl = 10
    if cfg.hit_cache and tonumber(cfg.hit_cache.ttl) then
        ttl = tonumber(cfg.hit_cache.ttl)
    end
    if ttl <= 0 then return end
    local dict = dict_get()
    if not dict then return end
    local value = "A"
    if blocked then
        local ok, encoded = pcall(require("cjson").encode, { m = primary_matched })
        if not ok then return end
        value = "B" .. encoded
    end
    dict:set(_M.cache_key(cfg, ctx), value, ttl)
end

-- 从 ctx.matched 挑选主命中条目（severity 最高；并列取先出现者）
function _M.primary_matched(ctx)
    local best = nil
    for _, m in ipairs(ctx.matched or {}) do
        if best == nil or (tonumber(m.severity) or 0) > (tonumber(best.severity) or 0) then
            best = m
        end
    end
    return best
end

return _M
