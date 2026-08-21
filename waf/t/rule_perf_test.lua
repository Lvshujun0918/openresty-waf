-- waf/t/rule_perf_test.lua
-- 规则耗时画像：聚合数学 + 引擎接线（timed_match 生效）

local t = require "assert"
local rule_perf = require "rule_perf"
local engine = require "rule_engine.engine"

local function rule(over)
    local r = {
        id = "9001", group = "custom", phase = "access", severity = 2,
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

t.test("now_us 返回递增数值", function()
    local a = rule_perf.now_us()
    local b = rule_perf.now_us()
    t.eq(type(a), "number")
    t.eq(type(b), "number")
    t.ok(b >= a)
end)

t.test("record 聚合 次数/累计/最大值", function()
    rule_perf.reset()
    rule_perf.record("A", 100)
    rule_perf.record("A", 300)
    rule_perf.record("A", 200)
    local s = rule_perf.pending().A
    t.eq(s.n, 3)
    t.eq(s.total_us, 600)
    t.eq(s.max_us, 300)
end)

t.test("record 非法输入忽略（nil/负数）", function()
    rule_perf.reset()
    rule_perf.record(nil, 100)
    rule_perf.record("B", -5)
    rule_perf.record("B", nil)
    t.eq(rule_perf.pending().B, nil)
end)

t.test("reset 清空快照", function()
    rule_perf.reset()
    rule_perf.record("C", 1)
    t.ok(rule_perf.pending().C ~= nil)
    rule_perf.reset()
    t.eq(rule_perf.pending().C, nil)
end)

t.test("engine.run 经 timed_match 写入画像（命中路径）", function()
    rule_perf.reset()
    ngx_reset()
    ngx.var.uri = "/union select"
    local rs = { rules = { rule() } }
    t.exits(function()
        engine.run(rs, "access", { mode = "active" })
    end, 403, "BLOCK")
    local s = rule_perf.pending()["9001"]
    t.ok(s ~= nil, "规则 9001 应有画像记录")
    t.eq(s.n, 1)
    t.ok(s.total_us >= 0)
end)

t.test("engine.run 经 timed_match 写入画像（未命中也计次）", function()
    rule_perf.reset()
    ngx_reset()
    ngx.var.uri = "/hello"
    local rs = { rules = { rule() } }
    engine.run(rs, "access", { mode = "active" })
    local s = rule_perf.pending()["9001"]
    t.ok(s ~= nil, "未命中规则同样计入评估次数")
    t.eq(s.n, 1)
end)
