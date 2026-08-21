-- waf/t/canary_test.lua
-- 规则灰度：状态、IP 名单优先、百分比分桶、灰度规则集缓存隔离

local t      = require "assert"
local canary = require "canary"
local engine = require "rule_engine.engine"
local cjson  = require "cjson"

local function fresh()
    ngx_reset()
    canary.clear()
end

local function set_cfg(version, cfg)
    ngx.shared.waf_rule:set("canary_version", version)
    ngx.shared.waf_rule:set("canary_cfg", cjson.encode(cfg))
end

local function ctx(ip)
    return { client_ip = ip or "1.2.3.4" }
end

t.test("未下发灰度版本时未启用", function()
    fresh()
    t.no(canary.is_active())
    local selected, version = canary.select(ctx())
    t.no(selected)
    t.eq(version, nil)
end)

t.test("IP 名单优先于百分比", function()
    fresh()
    set_cfg("1", { percent = 0, ips = { "1.2.3.4" } })
    local selected, version = canary.select(ctx("1.2.3.4"))
    t.ok(selected)
    t.eq(version, "1")
    local other = canary.select(ctx("5.6.7.8"))
    t.no(other)
end)

t.test("百分比边界", function()
    fresh()
    set_cfg("2", { percent = 0, ips = {} })
    local selected0 = canary.select(ctx("5.6.7.8"))
    t.no(selected0)
    set_cfg("3", { percent = 100, ips = {} })
    canary.clear()
    local selected100 = canary.select(ctx("5.6.7.8"))
    t.ok(selected100)
end)

t.test("非法配置按未命中灰度处理", function()
    fresh()
    ngx.shared.waf_rule:set("canary_version", "4")
    ngx.shared.waf_rule:set("canary_cfg", "not-json")
    local selected, version = canary.select(ctx())
    t.no(selected)
    t.eq(version, "4")
end)

t.test("clear 清理本地配置缓存", function()
    fresh()
    set_cfg("5", { percent = 0, ips = {} })
    local selected0 = canary.select(ctx())
    t.no(selected0)
    ngx.shared.waf_rule:set("canary_cfg", cjson.encode({ percent = 100, ips = {} }))
    local cached = canary.select(ctx())
    t.no(cached)
    canary.clear()
    local reloaded = canary.select(ctx())
    t.ok(reloaded)
end)

t.test("engine 稳定集与灰度集独立读取", function()
    fresh()
    ngx.shared.waf_rule:set("ruleset_version", "stable-1")
    ngx.shared.waf_rule:set("active_ruleset", cjson.encode({ version = "stable", rules = {
        { id = "STABLE", phase = "access" },
    } }))
    ngx.shared.waf_rule:set("canary_version", "canary-1")
    ngx.shared.waf_rule:set("canary_ruleset", cjson.encode({ version = "canary", rules = {
        { id = "CANARY", phase = "access" },
    } }))

    local stable = engine.get_phase_rules("access")
    local grey = engine.get_phase_rules("access", "canary")
    t.eq(#stable, 1)
    t.eq(#grey, 1)
    t.eq(stable[1].id, "STABLE")
    t.eq(grey[1].id, "CANARY")
end)

t.summary("canary_test")
