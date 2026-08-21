-- detectors/auto_ban.lua
-- 高频攻击自动封禁：同一 IP 在短窗口内多次触发攻击事件时，自动写入
-- 临时封禁键（shared dict），access 阶段检查命中即拦截。
-- 与触发规则无关：仅统计"攻击命中"，正常流量不参与计数；
-- 白名单 IP 不会走到攻击命中计数（名单检查更早放行）。
--
-- 配置（config.auto_ban，后台配置页可调）：
--   enabled / threshold（窗口内攻击次数阈值）/ window（秒）/
--   duration（封禁秒数）/ 键前缀。

local _M = {}

local config  = require "config"
local storage = require "storage"
local errlog  = require "errlog"

-- 该 IP 是否处于自动封禁期
function _M.is_banned(cfg, ip)
    if not (cfg and cfg.auto_ban and cfg.auto_ban.enabled) then
        return false
    end
    if not ip or ip == "" then
        return false
    end
    local key = (cfg.auto_ban.ban_key_prefix or "waf:ab:ban:") .. ip
    return storage.get_shared(config.dict.counter, key) ~= nil
end

-- 封禁时长：按该 IP 历史封禁次数升级（阶梯 1 次→IP；2 次→IP；3 次起→IP+UA）
-- 防"换 UA 绕过 IP 封禁"：升级后的条目用名单格式 ip|ua|ts（引擎名单子串匹配 UA）。
-- 封禁次数记录在共享内存（TTL = duration，随封禁一起过期）。
local function ban_level(cfg, ab, ip, duration)
    local level_key = (ab.counter_prefix or "waf:ab:cnt:") .. "lv:" .. ip
    local level = storage.get_shared(config.dict.counter, level_key) or 0
    level = level + 1
    storage.set_shared(config.dict.counter, level_key, level, duration)

    local entry = ip
    if level >= 3 then
        -- 升级为 IP+UA 封禁（名单条目 ip|ua|ts，UA 子串匹配；UA 为空时保持 IP 级）
        local ua = ngx.var.http_user_agent or ""
        if ua ~= "" and not ua:find("|", 1, true) then
            entry = ip .. "|" .. ua
        end
    end
    return entry .. "|" .. tostring(ngx.time() + duration)
end

-- 记录一次攻击命中：达到阈值即写入封禁键（时长 duration 秒）。
-- 返回 true 表示本次触发了封禁（供日志告警）。
function _M.record_hit(cfg, ip)
    if not (cfg and cfg.auto_ban and cfg.auto_ban.enabled) then
        return false
    end
    if not ip or ip == "" then
        return false
    end
    local ab = cfg.auto_ban
    local threshold = tonumber(ab.threshold) or 10
    local window = tonumber(ab.window) or 60
    local duration = tonumber(ab.duration) or 600
    local ckey = (ab.counter_prefix or "waf:ab:cnt:") .. ip
    local n = storage.incr_shared(config.dict.counter, ckey, 1, 0, window)
    if n and n >= threshold then
        local bkey = (ab.ban_key_prefix or "waf:ab:ban:") .. ip
        local ok, err = storage.set_shared(config.dict.counter, bkey, ban_level(cfg, ab, ip, duration), duration)
        if not ok then
            -- 字典写满降级：封禁键写不进去时仅告警，不影响业务
            errlog.err("auto_ban", "自动封禁写入共享内存失败（字典可能已满）: " .. tostring(err), { client_ip = ip })
        end
        return true
    end
    return false
end

return _M
