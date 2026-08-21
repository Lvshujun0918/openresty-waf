-- canary.lua
-- 规则灰度选择：后台下发独立灰度规则集后，按 IP 名单优先、百分比分桶其次
-- 决定当前请求是否使用灰度规则集。

local config = require "config"
local storage = require "storage"

local _M = {}

local cfg_cache = { version = false, value = nil }

function _M.current_version()
    return storage.get_shared(config.dict.rules, "canary_version")
end

function _M.is_active()
    local version = _M.current_version()
    return version ~= nil and version ~= ""
end

function _M.clear()
    cfg_cache.version = false
    cfg_cache.value = nil
end

local function load_cfg(version)
    if cfg_cache.version == version and cfg_cache.value ~= nil then
        if cfg_cache.value == false then return nil end
        return cfg_cache.value
    end
    local raw = storage.get_shared(config.dict.rules, "canary_cfg")
    local cfg = storage.decode(raw)
    if type(cfg) ~= "table" then
        cfg_cache.version = version
        cfg_cache.value = false
        return nil
    end
    cfg.percent = tonumber(cfg.percent) or 0
    if cfg.percent < 0 then cfg.percent = 0 end
    if cfg.percent > 100 then cfg.percent = 100 end
    if type(cfg.ips) ~= "table" then cfg.ips = {} end
    cfg_cache.version = version
    cfg_cache.value = cfg
    return cfg
end

-- 返回 selected, version。version 用于命中缓存 tag，确保灰度规则集独立缓存。
function _M.select(ctx)
    local version = _M.current_version()
    if not version or version == "" then
        return false, nil
    end
    local cfg = load_cfg(version)
    if not cfg then
        return false, version
    end

    local ip = ctx and ctx.client_ip or ""
    for _, listed in ipairs(cfg.ips or {}) do
        if tostring(listed) == ip then
            return true, version
        end
    end

    local percent = tonumber(cfg.percent) or 0
    if percent <= 0 then return false, version end
    if percent >= 100 then return true, version end

    local n = tonumber((ngx.md5(ip .. "|" .. tostring(version))):sub(1, 8), 16)
    if not n then
        return false, version
    end
    return (n % 100) < percent, version
end

return _M
