-- waf/t/engine_test.lua
-- rule_engine/engine 规则执行器单测

local t = require "assert"
local engine = require "rule_engine.engine"

-- 构造规则
local function rule(over)
    local r = {
        id = "1", group = "custom", phase = "access", severity = 2,
        enabled = true,
        vars = { { type = "URI" } },
        operator = "REGEX", pattern = "union%s+select",
        transforms = { "to_lowercase" },
        actions = { disrupt = "BLOCK", status = 403, msg = "blocked" },
    }
    if over then
        for k, v in pairs(over) do r[k] = v end
    end
    return r
end

t.test("无命中返回 nil", function()
    ngx_reset()
    ngx.var.uri = "/hello"
    local rs = { rules = { rule() } }
    local res = engine.run(rs, "access", { mode = "active" })
    t.isnil(res)
end)

t.test("命中 + BLOCK + active → blocked 且 exit 403", function()
    ngx_reset()
    ngx.var.uri = "/union select"
    local rs = { rules = { rule() } }
    local ctx = { mode = "active" }
    t.exits(function()
        engine.run(rs, "access", ctx)
    end, 403, "BLOCK")
    t.eq(#ctx.matched, 1)
    t.eq(ctx.matched[1].id, "1")
end)

t.test("命中 + BLOCK + detect 模式仅记录", function()
    ngx_reset()
    ngx.var.uri = "/union select"
    local rs = { rules = { rule() } }
    local ctx = { mode = "detect" }
    local res = engine.run(rs, "access", ctx)
    t.eq(res, "matched")
    t.eq(#ctx.matched, 1)
end)

t.test("仲裁：同优先级下 BLOCK 优先于 ACCEPT", function()
    ngx_reset()
    ngx.var.uri = "/union select"
    local rs = {
        rules = {
            rule({ id = "1", actions = { disrupt = "ACCEPT" } }),
            rule({ id = "2", actions = { disrupt = "BLOCK" } }),
        },
    }
    local ctx = { mode = "active" }
    t.exits(function() engine.run(rs, "access", ctx) end, 403, "BLOCK")
    -- 两条命中均被记录（供审计）
    t.eq(#ctx.matched, 2)
end)

t.test("仲裁：用户 ALLOW 高 salience 覆盖种子 BLOCK", function()
    ngx_reset()
    ngx.var.uri = "/union select"
    local rs = {
        rules = {
            rule({ id = "1", actions = { disrupt = "BLOCK" }, salience = 10 }),
            rule({ id = "2", actions = { disrupt = "ALLOW" }, salience = 100 }),
        },
    }
    local ctx = { mode = "active" }
    local res = engine.run(rs, "access", ctx)
    t.eq(res, "accepted")
    t.eq(#ctx.matched, 2)
end)

t.test("命中 + ALLOW → accepted 放行", function()
    ngx_reset()
    ngx.var.uri = "/union select"
    local rs = { rules = { rule({ actions = { disrupt = "ALLOW" } }) } }
    local ctx = { mode = "active" }
    local res = engine.run(rs, "access", ctx)
    t.eq(res, "accepted")
end)

t.test("phase 过滤：非当前阶段规则跳过", function()
    ngx_reset()
    ngx.var.uri = "/union select"
    local rs = {
        rules = {
            rule({ id = "1", phase = "header_filter" }),
            rule({ id = "2", phase = "access", actions = { disrupt = "BLOCK" } }),
        },
    }
    local ctx = { mode = "active" }
    t.exits(function() engine.run(rs, "access", ctx) end, 403)
    t.eq(ctx.matched[1].id, "2")
end)

t.test("disabled 规则跳过", function()
    ngx_reset()
    ngx.var.uri = "/union select"
    local rs = { rules = { rule({ id = "1", enabled = false }) } }
    local ctx = { mode = "active" }
    local res = engine.run(rs, "access", ctx)
    t.isnil(res)
    t.eq(#ctx.matched, 0)
end)

t.test("SCORE 累计低于阈值 → matched 不阻断", function()
    ngx_reset()
    ngx.var.uri = "/union select"
    local rs = {
        rules = {
            rule({ id = "1", actions = { disrupt = "SCORE", value = 2 } }),
        },
    }
    local ctx = { mode = "active", score_threshold = 5 }
    local res = engine.run(rs, "access", ctx)
    t.eq(ctx.score, 2)
    t.eq(res, "matched")
end)

t.test("SCORE 达到阈值 → exit 403", function()
    ngx_reset()
    ngx.var.uri = "/union select"
    local rs = {
        rules = {
            rule({ id = "1", actions = { disrupt = "SCORE", value = 6 } }),
        },
    }
    local ctx = { mode = "active", score_threshold = 5 }
    t.exits(function() engine.run(rs, "access", ctx) end, 403)
    t.ok(ctx._exited, "ngx.exit 前应标记 _exited")
end)

t.test("SCORE 达到阈值但 detect 模式不阻断", function()
    ngx_reset()
    ngx.var.uri = "/union select"
    local rs = {
        rules = {
            rule({ id = "1", actions = { disrupt = "SCORE", value = 6 } }),
        },
    }
    local ctx = { mode = "detect", score_threshold = 5 }
    local ok, err = pcall(engine.run, rs, "access", ctx)
    t.ok(ok, "no exit in detect: " .. tostring(err))
    t.eq(ctx.score, 6)
end)

t.test("skip_after 跳转：跳过中间规则", function()
    ngx_reset()
    ngx.var.uri = "/union select"
    local rs = {
        rules = {
            rule({ id = "1", actions = { disrupt = "SCORE", value = 1, skip_after = 2 } }),
            rule({ id = "2", actions = { disrupt = "BLOCK" } }),
            rule({ id = "3", actions = { disrupt = "BLOCK" } }),
        },
    }
    local ctx = { mode = "active" }
    -- 规则1 命中后跳过 2 条 → 跳过规则2，执行规则3 → BLOCK
    t.exits(function() engine.run(rs, "access", ctx) end, 403)
    t.eq(#ctx.matched, 2)
    t.eq(ctx.matched[2].id, "3")
end)

t.test("空规则集 → nil", function()
    ngx_reset()
    local res = engine.run({ rules = {} }, "access", { mode = "active" })
    t.isnil(res)
end)

t.test("无 vars 的规则不匹配", function()
    ngx_reset()
    ngx.var.uri = "/union select"
    local rs = { rules = { rule({ vars = {} }) } }
    local res = engine.run(rs, "access", { mode = "active" })
    t.isnil(res)
end)

t.test("多 vars 任一命中即匹配", function()
    ngx_reset()
    ngx.var.uri = "/safe"
    ngx.req._args = { id = "union select" }
    local rs = {
        rules = {
            rule({ vars = { { type = "URI" }, { type = "URI_ARGS" } },
                   actions = { disrupt = "BLOCK" } }),
        },
    }
    local ctx = { mode = "active" }
    t.exits(function() engine.run(rs, "access", ctx) end, 403)
end)

-- 响应阶段动作：header_filter/body_filter 禁用 ngx.exit

t.test("header_filter 阶段 BLOCK 不 exit：改状态码并标记 response_block", function()
    ngx_reset()
    ngx.var.uri = "/union select"
    local rs = { rules = { rule({ phase = "header_filter" }) } }
    local ctx = { mode = "active" }
    local res = engine.run(rs, "header_filter", ctx)
    t.eq(res, "blocked")
    t.eq(ngx.status, 403)
    t.isnil(ngx.exit_code, "header_filter 不应调用 ngx.exit")
    t.ok(ctx.response_block ~= nil and ctx.response_block ~= "", "应标记替换响应体")
end)

t.test("body_filter 阶段 BLOCK 仅标记 response_block", function()
    ngx_reset()
    ngx.var.uri = "/union select"
    local rs = { rules = { rule({ phase = "body_filter" }) } }
    local ctx = { mode = "active" }
    local res = engine.run(rs, "body_filter", ctx)
    t.eq(res, "blocked")
    t.isnil(ngx.exit_code, "body_filter 不应调用 ngx.exit")
    t.eq(ngx.status, 0, "响应头已发送不应改状态码")
    t.ok(ctx.response_block ~= nil, "应标记替换响应体")
end)

-- chain 链式规则（ModSecurity 语义）：成员（含链尾）均带 chain=true，
-- 链尾同时携带实际动作；链首命中后成员须连续命中，任一中断则整链丢弃。

local function chain_rules()
    return {
        rules = {
            rule({ id = "c1", vars = { { type = "URI_ARGS", specific = "a" } },
                   pattern = "union", actions = { chain = true } }),
            rule({ id = "c2", vars = { { type = "URI_ARGS", specific = "b" } },
                   pattern = "sleep", actions = { chain = true, disrupt = "BLOCK", status = 403 } }),
        },
    }
end

t.test("chain: 父子连续命中才执行链尾动作", function()
    ngx_reset()
    ngx.req._args = { a = "union select", b = "sleep(5)" }
    local ctx = { mode = "active" }
    t.exits(function() engine.run(chain_rules(), "access", ctx) end, 403)
    t.eq(#ctx.matched, 2, "整条链记录")
    t.eq(ctx.matched[1].id, "c1")
    t.eq(ctx.matched[2].id, "c2")
end)

t.test("chain: 链尾未命中则不动作不记录", function()
    ngx_reset()
    ngx.req._args = { a = "union select" }
    local ctx = { mode = "active" }
    local res = engine.run(chain_rules(), "access", ctx)
    t.isnil(res)
    t.eq(#ctx.matched, 0, "链中断丢弃")
end)

t.test("chain: 链首未命中时后续成员整体跳过", function()
    ngx_reset()
    ngx.req._args = { b = "sleep(5)" }
    local ctx = { mode = "active" }
    local res = engine.run(chain_rules(), "access", ctx)
    t.isnil(res, "链首未命中，成员不得独立触发")
    t.eq(#ctx.matched, 0)
end)

t.test("chain: 普通规则重置链状态，后续成员重新作为链首", function()
    ngx_reset()
    ngx.req._args = { b = "sleep(5)" }
    local rs = {
        rules = {
            rule({ id = "c1", vars = { { type = "URI_ARGS", specific = "a" } },
                   pattern = "union", actions = { chain = true } }),
            rule({ id = "gap", enabled = false }),
            rule({ id = "c2", vars = { { type = "URI_ARGS", specific = "b" } },
                   pattern = "sleep", actions = { chain = true, disrupt = "BLOCK", status = 403 } }),
        },
    }
    local ctx = { mode = "active" }
    -- c1 未命中（a 缺失）；gap 普通规则重置；c2 作为新链首命中并带动作 → 403
    t.exits(function() engine.run(rs, "access", ctx) end, 403)
end)

-- fail-open 机制：BLOCK/DROP 在 ngx.exit 前标记 _exited，外层据此区分拦截与异常
t.test("BLOCK 动作 exit 前标记 _exited", function()
    ngx_reset()
    ngx.var.uri = "/union select"
    local rs = { rules = { rule() } }
    local ctx = { mode = "active" }
    t.exits(function() engine.run(rs, "access", ctx) end, 403)
    t.ok(ctx._exited, "ngx.exit 前应标记 _exited")
end)

t.test("DROP 动作 exit 前标记 _exited", function()
    ngx_reset()
    ngx.var.uri = "/union select"
    local rs = { rules = { rule({ actions = { disrupt = "DROP" } }) } }
    local ctx = { mode = "active" }
    t.exits(function() engine.run(rs, "access", ctx) end, 444)
    t.ok(ctx._exited, "ngx.exit 前应标记 _exited")
end)

-- 版本化缓存：版本未变返回同一引用，变化后重新解码
t.test("get_ruleset: 版本未变返回缓存，版本变化重新解码", function()
    ngx_reset()
    local storage = require "storage"
    storage.set_shared("waf_rule", "ruleset_version", "v1")
    storage.set_shared("waf_rule", "active_ruleset", storage.encode({ rules = {} }))
    local a = engine.get_ruleset()
    local b = engine.get_ruleset()
    t.ok(a == b, "同版本应返回同一引用")
    t.eq(#a.rules, 0)
    -- 版本变化 → 重新解码
    storage.set_shared("waf_rule", "ruleset_version", "v2")
    storage.set_shared("waf_rule", "active_ruleset", storage.encode({ rules = { rule() } }))
    local c = engine.get_ruleset()
    t.ok(c ~= a, "版本变化应重新解码")
    t.eq(#c.rules, 1)
end)

t.test("get_active_config: 版本未变返回缓存，无下发配置回退默认", function()
    ngx_reset()
    local storage = require "storage"
    local config = require "config"
    -- 未下发配置：返回默认 config 模块表
    local a = engine.get_active_config()
    t.ok(a == config, "无 active_config 应回退 config 模块")
    -- 下发配置后版本变化 → 解码新配置
    storage.set_shared("waf_rule", "config_version", "c1")
    storage.set_shared("waf_rule", "active_config", storage.encode({ mode = "detect" }))
    local b = engine.get_active_config()
    t.eq(b.mode, "detect")
    t.ok(b == engine.get_active_config(), "同版本应返回同一引用")
    -- 版本不变但重写数据（模拟异常情况）不触发重新解码
    storage.set_shared("waf_rule", "active_config", storage.encode({ mode = "off" }))
    t.eq(engine.get_active_config().mode, "detect")
end)

-- 站点规则按 Host 过滤与缓存
t.test("get_rules_for_host: 全局+站点规则过滤与缓存", function()
    ngx_reset()
    local storage = require "storage"
    storage.set_shared("waf_rule", "ruleset_version", "v1")
    storage.set_shared("waf_rule", "active_ruleset", storage.encode({
        version = "v1",
        rules = {
            rule({ id = "g1" }),
            rule({ id = "s1", site = "cszj.wang" }),
        },
    }))
    local rs = engine.get_rules_for_host("cszj.wang")
    t.eq(#rs.rules, 2, "站点 host 命中全局 + 站点规则")
    local rs2 = engine.get_rules_for_host("other.com")
    t.eq(#rs2.rules, 1, "其他 host 仅全局规则")
    t.eq(rs2.rules[1].id, "g1")
    t.ok(engine.get_rules_for_host("cszj.wang") == rs, "同 host 命中缓存")
    -- 版本变化后重新过滤
    storage.set_shared("waf_rule", "ruleset_version", "v2")
    local rs3 = engine.get_rules_for_host("cszj.wang")
    t.ok(rs3 ~= rs, "版本变化应重新过滤")
    t.eq(#rs3.rules, 2)
end)

t.test("get_rules_for_host: 无规则集返回 nil", function()
    ngx_reset()
    t.isnil(engine.get_rules_for_host("x.com"))
end)
