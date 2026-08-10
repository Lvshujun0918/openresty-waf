-- detectors/cc.lua
-- CC 防刷：基于共享内存计数，同 IP 同 Host 同路径超频后临时封禁该 IP。
-- 支持后台下发的精细化规则（host + path 匹配不同阈值），
-- 未命中规则时回退全局默认（config.cc / 后台配置中心）。

local _M = {}

local config  = require "config"
local storage = require "storage"

local CC_RULES_SHARED_KEY = "active_cc_rules"

-- 解析 "count/seconds" 形式阈值，缺省 100/60
local function parse_rate(rate)
    local count, seconds = rate:match("^(%d+)/(%d+)$")
    if not count or not seconds then
        return 100, 60
    end
    return tonumber(count), tonumber(seconds)
end

-- host 通配匹配：空 / `*` = 全部；`*.example.com` 匹配该域与子域；否则精确匹配
local function host_match(rule_host, host)
    if not rule_host or rule_host == "" or rule_host == "*" then
        return true
    end
    local prefix = rule_host:match("^%*%.(.+)$")
    if prefix then
        return host == prefix or string.find(host, "." .. prefix, 1, true) ~= nil
    end
    return host == rule_host
end

-- path 前缀匹配：空 = 全部；否则前缀命中
local function path_match(rule_path, path)
    if not rule_path or rule_path == "" then
        return true
    end
    return string.find(path, rule_path, 1, true) == 1
end

-- 从共享内存读取 CC 规则集（后台发布 + 热更新）
local function get_cc_rules()
    local body = storage.get_shared(config.dict.rules, CC_RULES_SHARED_KEY)
    if not body or body == "" then return nil end
    local rs = storage.decode(body)
    if type(rs) ~= "table" then return nil end
    return rs.rules
end

-- 匹配最具体的规则：specificity = host非空(2) + path非空(1)，取最大
local function match_rule(host, path, rules)
    local best, best_spec = nil, -1
    for _, r in ipairs(rules or {}) do
        if r.enabled ~= false then
            local h = r.host or ""
            local p = r.path or ""
            if host_match(h, host) and path_match(p, path) then
                local spec = (h ~= "" and 2 or 0) + (p ~= "" and 1 or 0)
                if spec > best_spec then
                    best, best_spec = r, spec
                end
            end
        end
    end
    return best
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

    local host = (waf_ctx.request and waf_ctx.request.host) or ""
    local path = (waf_ctx.request and waf_ctx.request.path) or "/"

    -- 精细化规则优先，未命中回退全局默认
    local rate = cfg.cc.rate or "100/60"
    local ban_duration = cfg.cc.ban_duration or 300
    local rule = match_rule(host, path, get_cc_rules())
    if rule then
        rate = rule.rate or rate
        ban_duration = rule.ban_duration or ban_duration
    end

    local count, seconds = parse_rate(rate)
    -- 计数维度：IP + Host + 路径（不含 query string）
    local counter_key = (cfg.cc.counter_prefix or "waf:cc:cnt:") .. ip .. ":" .. host .. ":" .. path

    local n = storage.incr_shared(config.dict.counter, counter_key, 1, 0, seconds)
    if n and n >= count then
        -- 触发封禁（IP 级）
        local ban_key = (cfg.cc.ban_key_prefix or "waf:cc:ban:") .. ip
        storage.set_shared(config.dict.counter, ban_key, ngx.time(), ban_duration)
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
