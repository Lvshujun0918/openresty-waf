-- rule_engine/engine.lua
-- 规则执行器：从共享内存读取当前生效规则集，按规则 DSL 匹配并执行动作。
--
-- 支持特性：
--   - phase 过滤（access / header_filter / body_filter / log）
--   - 变量提取 + 变换链 + 运算符匹配
--   - action.skip_after 规则跳转（链式规则后续可扩展 chain 支持）
--   - SCORE 异常分累计与阈值阻断
--   - 命中结果缓存到 ctx.matched（由 log 阶段统一写日志）

local _M = {}

local operators  = require "rule_engine.operators"
local variables  = require "rule_engine.variables"
local transforms = require "rule_engine.transforms"
local actions    = require "rule_engine.actions"

-- 单条规则是否命中
-- 说明：OpenResty 新版已移除 ngx.re.compile，正则走 ngx.re.find("joi")，
-- 依赖 PCRE JIT 与 compile-once 缓存；此处优化点为请求级变量提取缓存
-- （variables.collect 带 ctx），避免多规则重复解析 URI_ARGS/HEADERS/BODY。
local function match_rule(rule, waf_ctx)
    for _, var in ipairs(rule.vars or {}) do
        local values = variables.collect(var, waf_ctx)
        for _, value in ipairs(values) do
            local transformed = transforms.apply(value, rule.transforms)
            if operators.eval(rule.operator, transformed, rule.pattern) then
                return true
            end
        end
    end
    return false
end

-- 执行一个规则集（当前阶段）
-- 返回 "blocked" / "accepted" / "matched" / nil
-- 动作仲裁：收集全部命中 → 高 salience 优先；同级按 拦截 > 放行 > 记录。
-- 使「用户放行规则（高 salience）」可以覆盖「内置/CRS 拦截规则」。
function _M.run(ruleset, phase, waf_ctx)
    waf_ctx = waf_ctx or {}
    waf_ctx.score = waf_ctx.score or 0
    waf_ctx.matched = waf_ctx.matched or {}
    waf_ctx.var_cache = waf_ctx.var_cache or {}

    local rules = ruleset.rules or {}
    local i, n = 1, #rules
    -- 命中动作收集（仲裁用）
    local hits = {}

    while i <= n do
        local rule = rules[i]

        if rule.enabled and (not rule.phase or rule.phase == phase) then
            if match_rule(rule, waf_ctx) then
                -- 记录命中（日志由 log 阶段统一落盘）
                waf_ctx.matched[#waf_ctx.matched + 1] = {
                    id       = rule.id,
                    group    = rule.group,
                    msg      = rule.actions and rule.actions.msg,
                    severity = rule.severity,
                }

                local action = rule.actions or {}
                local disrupt = action.disrupt

                -- SCORE：累计异常分，不参与动作仲裁（最后阈值判定）
                if disrupt == "SCORE" then
                    waf_ctx.score = (waf_ctx.score or 0) + (tonumber(action.value) or 1)
                elseif disrupt and disrupt ~= "LOG_ONLY" then
                    -- 其余动作（BLOCK/DROP/ALLOW/ACCEPT/REDIRECT）收集后仲裁
                    hits[#hits + 1] = {
                        actions  = action,
                        salience = tonumber(rule.salience) or 10,
                    }
                end

                -- 跳转处理
                if action.skip_after then
                    i = i + tonumber(action.skip_after)
                else
                    i = i + 1
                end
            else
                i = i + 1
            end
        else
            i = i + 1
        end
    end

    -- 动作仲裁：最高 salience 的命中集内，按 拦截(3) > 放行(2) > 记录(1) 取最终动作
    if #hits > 0 then
        local top = hits[1].salience
        for k = 2, #hits do
            if hits[k].salience > top then top = hits[k].salience end
        end
        local rank = { BLOCK = 3, DROP = 3, ALLOW = 2, ACCEPT = 2, REDIRECT = 2 }
        local best, best_rank
        for _, h in ipairs(hits) do
            if h.salience == top then
                local r = rank[h.actions.disrupt] or 1
                if not best_rank or r > best_rank then
                    best, best_rank = h, r
                end
            end
        end
        if best then
            local result = actions.execute(waf_ctx, best.actions, nil)
            if result == "accepted" then
                return "accepted"
            end
            if result == "blocked" then
                return "blocked"
            end
        end
    end

    -- 异常分阈值阻断
    local threshold = waf_ctx.score_threshold or 5
    if waf_ctx.score >= threshold and waf_ctx.mode ~= "detect" then
        local cfg = _M.get_active_config()
        ngx.status = 403
        ngx.header.content_type = "text/html; charset=utf-8"
        ngx.say(cfg.block and cfg.block.html or "Forbidden")
        ngx.exit(403)
    end

    if #waf_ctx.matched > 0 then
        return "matched"
    end
    return nil
end

-- 模块级缓存：规则集 / 生效配置按共享内存版本号缓存解码结果。
-- 版本号由 init.lua 热更新时与数据一并写入（ruleset_version / config_version），
-- 版本未变化直接返回缓存表，避免每个请求重复 cjson.decode 整份 JSON。
-- 注意：返回的表为共享缓存，调用方禁止修改（需改动请先浅拷贝）。
local ruleset_cache = { version = false, value = nil }
local config_cache  = { version = false, value = nil }

-- 读取当前生效规则集（共享内存，按版本号缓存）
function _M.get_ruleset()
    local config = require "config"
    local storage = require "storage"
    local version = storage.get_shared(config.dict.rules, "ruleset_version")
    if version == ruleset_cache.version and ruleset_cache.value ~= nil then
        return ruleset_cache.value
    end
    local body = storage.get_shared(config.dict.rules, "active_ruleset")
    local ruleset = storage.decode(body)
    ruleset_cache.version = version
    ruleset_cache.value = ruleset
    return ruleset
end

-- 读取当前生效配置（共享内存，按版本号缓存；无下发配置时回退默认 config）
function _M.get_active_config()
    local config = require "config"
    local storage = require "storage"
    local version = storage.get_shared(config.dict.rules, "config_version")
    if version == config_cache.version and config_cache.value ~= nil then
        return config_cache.value
    end
    local body = storage.get_shared(config.dict.rules, "active_config")
    local cfg = storage.decode(body)
    if type(cfg) ~= "table" then
        cfg = config
    end
    config_cache.version = version
    config_cache.value = cfg
    return cfg
end

return _M
