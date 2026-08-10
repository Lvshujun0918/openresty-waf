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

t.test("命中 + ACCEPT → accepted 且跳过后续规则", function()
    ngx_reset()
    ngx.var.uri = "/union select"
    local rs = {
        rules = {
            rule({ id = "1", actions = { disrupt = "ACCEPT" } }),
            rule({ id = "2", actions = { disrupt = "BLOCK" } }),
        },
    }
    local ctx = { mode = "active" }
    local res = engine.run(rs, "access", ctx)
    t.eq(res, "accepted")
    -- 规则 2 不应被执行
    t.eq(#ctx.matched, 1)
    t.eq(ctx.matched[1].id, "1")
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
