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
local function match_rule(rule)
    for _, var in ipairs(rule.vars or {}) do
        local values = variables.collect(var)
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
function _M.run(ruleset, phase, waf_ctx)
    waf_ctx = waf_ctx or {}
    waf_ctx.score = waf_ctx.score or 0
    waf_ctx.matched = waf_ctx.matched or {}

    local rules = ruleset.rules or {}
    local i, n = 1, #rules

    while i <= n do
        local rule = rules[i]

        if rule.enabled and (not rule.phase or rule.phase == phase) then
            if match_rule(rule) then
                -- 记录命中（日志由 log 阶段统一落盘）
                waf_ctx.matched[#waf_ctx.matched + 1] = {
                    id       = rule.id,
                    group    = rule.group,
                    msg      = rule.actions and rule.actions.msg,
                    severity = rule.severity,
                }

                local action = rule.actions or {}
                local result = actions.execute(waf_ctx, action, rule)

                if result == "accepted" then
                    return "accepted"
                end
                if result == "blocked" then
                    return "blocked"
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

    -- 异常分阈值阻断
    local threshold = waf_ctx.score_threshold or 5
    if waf_ctx.score >= threshold and waf_ctx.mode ~= "detect" then
        local config = require "config"
        local storage = require "storage"
        local body = storage.get_shared(config.dict.rules, "active_config")
        local cfg = storage.decode(body) or config
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

-- 读取当前生效规则集（共享内存）
function _M.get_ruleset()
    local config = require "config"
    local storage = require "storage"
    local body = storage.get_shared(config.dict.rules, "active_ruleset")
    return storage.decode(body)
end

-- 读取当前生效配置
function _M.get_active_config()
    local config = require "config"
    local storage = require "storage"
    local body = storage.get_shared(config.dict.rules, "active_config")
    local cfg = storage.decode(body)
    if type(cfg) == "table" then
        return cfg
    end
    return config
end

return _M
