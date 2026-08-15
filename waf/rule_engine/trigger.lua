-- rule_engine/trigger.lua
-- 触发规则评估：按条件（host/UA/请求头/IP/路径/方法/参数 + AND/OR 组合）筛选请求，
-- 命中后执行对应动作（challenge=人机验证 / exempt=豁免检测 / cc=CC 限流）。
--
-- 规则由后台下发（waf:trigger:rules），经 init.lua 热更新到 shared dict，
-- 结构：{ version, rules: [{ id, name, kind, match_logic(and|or), conditions: [{field,operator,value,header,negate}] }] }

local _M = {}

local operators = require "rule_engine.operators"

-- 模块级缓存：触发规则集按共享内存版本号（trigger_rules_version）缓存解码结果，
-- 并惰性构建「按 kind 分组」的启用规则列表（by_kind）。
-- 避免每个请求对触发规则 JSON 重复 cjson.decode（access 阶段最多查询 4 次），
-- 也避免 match_first/match_any 每次调用全量遍历过滤建新表。
local trigger_cache = { version = false, value = nil, by_kind = {} }

-- 条件字段取值（带请求级缓存：一次读取多次复用，避免每规则重复 ngx.var 访问）
local function get_value(field, ctx, cond)
    local vc = ctx and ctx._trigger_vars or nil
    if field == "host" then
        if vc and vc.host ~= nil then return vc.host end
        -- 规范化 host：去掉端口（HTTP/2 下 ngx.var.host 可能带 :port）
        local v = (ngx.var.host or ""):gsub(":%d+$", "")
        if vc then vc.host = v end
        return v
    elseif field == "path" then
        if vc and vc.path ~= nil then return vc.path end
        local v = ngx.var.uri or ""
        if vc then vc.path = v end
        return v
    elseif field == "ua" then
        if vc and vc.ua ~= nil then return vc.ua end
        local v = ngx.var.http_user_agent or ""
        if vc then vc.ua = v end
        return v
    elseif field == "ip" then
        return ctx and ctx.client_ip or ""
    elseif field == "method" then
        if vc and vc.method ~= nil then return vc.method end
        local v = ngx.req.get_method() or ""
        if vc then vc.method = v end
        return v
    elseif field == "args" then
        if vc and vc.args ~= nil then return vc.args end
        local v = ngx.var.args or ""
        if vc then vc.args = v end
        return v
    elseif field == "header" then
        local name = tostring(cond.header or "")
        if name == "" then return "" end
        local var = "http_" .. name:lower():gsub("-", "_")
        if vc and vc.headers and vc.headers[var] ~= nil then return vc.headers[var] end
        local v = ngx.var[var] or ""
        if vc then
            vc.headers = vc.headers or {}
            vc.headers[var] = v
        end
        return v
    end
    return ""
end

-- 单条件评估（negate 取反）
local function eval_condition(cond, ctx)
    local field = tostring(cond.field or "")
    local op = tostring(cond.operator or "equals")
    local value = tostring(cond.value or "")
    local actual = get_value(field, ctx, cond)

    local matched = false
    if op == "equals" then
        matched = actual == value
    elseif op == "prefix" then
        matched = actual:sub(1, #value) == value
    elseif op == "contains" then
        matched = actual:find(value, 1, true) ~= nil
    elseif op == "regex" then
        -- PCRE 语义（与规则引擎 / 后台规则测试一致）：编译错误视为不匹配
        local ok, res = pcall(ngx.re.find, actual, value, "jo")
        matched = ok and res ~= nil
    elseif op == "cidr" then
        matched = operators.eval("CIDR", actual, value)
    elseif op == "in" then
        for item in value:gmatch("[^,]+") do
            if actual == item then matched = true break end
        end
    end
    if cond.negate then
        return not matched
    end
    return matched
end

-- 评估单条规则：条件按 match_logic（and/or）组合；无条件视为命中
function _M.match(rule, ctx)
    local conds = rule.conditions or {}
    if #conds == 0 then return true end
    local logic = rule.match_logic or "and"
    if logic == "or" then
        for _, c in ipairs(conds) do
            if eval_condition(c, ctx) then return true end
        end
        return false
    end
    for _, c in ipairs(conds) do
        if not eval_condition(c, ctx) then return false end
    end
    return true
end

-- 获取当前生效的触发规则（按 kind 过滤，结果按版本 + kind 缓存复用）
function _M.get_rules(kind)
    local storage = require "storage"
    local config = require "config"
    local version = storage.get_shared(config.dict.rules, "trigger_rules_version")
    if version ~= trigger_cache.version or trigger_cache.value == nil then
        local body = storage.get_shared(config.dict.rules, "active_trigger_rules")
        trigger_cache.version = version
        trigger_cache.value = storage.decode(body)
        trigger_cache.by_kind = {}
    end
    local rs = trigger_cache.value
    if type(rs) ~= "table" or type(rs.rules) ~= "table" then return nil end
    kind = kind or ""
    local cached = trigger_cache.by_kind[kind]
    if cached then return cached end
    local rules = {}
    for _, r in ipairs(rs.rules) do
        if r.enabled ~= false and (kind == "" or r.kind == kind) then
            rules[#rules + 1] = r
        end
    end
    trigger_cache.by_kind[kind] = rules
    return rules
end

-- 是否存在任一命中该 kind 的规则
function _M.match_any(kind, ctx)
    local rules = _M.get_rules(kind)
    for _, r in ipairs(rules or {}) do
        if _M.match(r, ctx) then return true end
    end
    return false
end

-- 返回第一个命中的规则（含 config 动作参数），供 access.lua 使用规则级配置
function _M.match_first(kind, ctx)
    local rules = _M.get_rules(kind)
    for _, r in ipairs(rules or {}) do
        if _M.match(r, ctx) then return r end
    end
    return nil
end

-- 是否已配置该类触发规则
function _M.has_rules(kind)
    return #(_M.get_rules(kind) or {}) > 0
end

return _M
