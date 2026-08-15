-- rule_engine/engine.lua
-- 规则执行器：从共享内存读取当前生效规则集，按规则 DSL 匹配并执行动作。
--
-- 支持特性：
--   - phase 过滤（access / header_filter / body_filter / log）
--   - 变量提取 + 变换链 + 运算符匹配
--   - action.skip_after 规则跳转
--   - action.chain 链式规则（父规则命中后紧随规则须连续命中，链尾才执行动作）
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

-- 记录单条规则命中（日志由 log 阶段统一落盘）
-- 首次命中时触发请求证据惰性捕获（access.lua 注入的 capture_evidence 回调），
-- 保证 BLOCK 动作 ngx.exit 前证据已就绪，且正常流量零证据采集开销
local function record_hit(waf_ctx, rule)
    waf_ctx.matched[#waf_ctx.matched + 1] = {
        id       = rule.id,
        group    = rule.group,
        msg      = rule.actions and rule.actions.msg,
        severity = rule.severity,
    }
    if not waf_ctx._evidence_captured and waf_ctx.capture_evidence then
        waf_ctx._evidence_captured = true
        pcall(waf_ctx.capture_evidence, waf_ctx)
    end
end

-- 应用单条规则动作：SCORE 累计异常分 / 其余收集后仲裁；
-- 返回 skip_after 跳转增量（0 表示不跳转）
local function apply_action(waf_ctx, rule, hits)
    local action = rule.actions or {}
    local disrupt = action.disrupt
    if disrupt == "SCORE" then
        waf_ctx.score = (waf_ctx.score or 0) + (tonumber(action.value) or 1)
    elseif disrupt and disrupt ~= "LOG_ONLY" then
        -- 其余动作（BLOCK/DROP/ALLOW/ACCEPT/REDIRECT）收集后仲裁
        hits[#hits + 1] = {
            actions  = action,
            salience = tonumber(rule.salience) or 10,
        }
    end
    local skip = tonumber(action.skip_after)
    if skip and skip > 0 then
        return skip
    end
    return 0
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
    -- chain 链式状态（ModSecurity 语义）：
    --   - 链成员（含链尾）均带 actions.chain=true，链尾同时携带实际动作
    --     （disrupt 非空，可为 BLOCK/LOG_ONLY/SCORE 等）；成员必须紧随排列。
    --   - 链首命中开启链；后续成员连续命中则继续，链尾命中执行动作并记录整条链；
    --   - 任一成员未命中/被禁用 → 链中断，后续成员整体跳过，
    --     直到出现不带 chain 的普通规则后重置。
    local chain = nil        -- 进行中的链 { ids = {...} }
    local chain_broken = false

    while i <= n do
        local rule = rules[i]
        local eligible = rule.enabled and (not rule.phase or rule.phase == phase)
        local action = rule.actions or {}
        local is_member = action.chain == true
        local disrupt = action.disrupt
        local has_disrupt = disrupt ~= nil
        local skip = 0

        if is_member then
            if chain_broken then
                -- 链已断：跳过后续成员
            elseif chain then
                if eligible and match_rule(rule, waf_ctx) then
                    if has_disrupt then
                        -- 链尾：记录整条链（此前成员 + 链尾自身）并执行尾规则动作
                        for _, id in ipairs(chain.ids) do
                            record_hit(waf_ctx, { id = id, group = rule.group, severity = rule.severity })
                        end
                        chain = nil
                        record_hit(waf_ctx, rule)
                        skip = apply_action(waf_ctx, rule, hits)
                    else
                        chain.ids[#chain.ids + 1] = rule.id
                    end
                else
                    chain, chain_broken = nil, true  -- 链中断
                end
            else
                -- 链首：正常评估
                if eligible and match_rule(rule, waf_ctx) then
                    chain = { ids = { rule.id } }
                    if has_disrupt then
                        -- 单成员链（链尾即链首）：直接记录并执行
                        chain = nil
                        record_hit(waf_ctx, rule)
                        skip = apply_action(waf_ctx, rule, hits)
                    end
                else
                    chain_broken = true  -- 链首未命中：后续成员跳过
                end
            end
        else
            if eligible and match_rule(rule, waf_ctx) then
                record_hit(waf_ctx, rule)
                skip = apply_action(waf_ctx, rule, hits)
            end
            -- 普通规则重置链状态（链块到此结束）
            chain, chain_broken = nil, false
        end

        i = i + (skip > 0 and skip or 1)
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
            local result = actions.execute(waf_ctx, best.actions, nil, phase)
            if result == "accepted" then
                return "accepted"
            end
            if result == "blocked" then
                return "blocked"
            end
        end
    end

    -- 异常分阈值阻断（响应阶段不 ngx.exit，改为改状态码/替换响应体）
    local threshold = waf_ctx.score_threshold or 5
    if waf_ctx.score >= threshold and waf_ctx.mode ~= "detect" then
        local cfg = _M.get_active_config()
        if phase == "access" then
            ngx.status = 403
            ngx.header.content_type = "text/html; charset=utf-8"
            ngx.say(cfg.block and cfg.block.html or "Forbidden")
            waf_ctx._exited = true
            ngx.exit(403)
        elseif phase == "header_filter" then
            ngx.status = 403
            ngx.header.content_type = "text/html; charset=utf-8"
            ngx.header.content_length = nil
            waf_ctx.response_block = cfg.block and cfg.block.html or "Forbidden"
        else
            waf_ctx.response_block = cfg.block and cfg.block.html or "Forbidden"
        end
        return "blocked"
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
