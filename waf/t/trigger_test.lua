-- waf/t/trigger_test.lua
-- rule_engine/trigger 触发规则引擎单测：条件字段/运算符/AND-OR 组合/kind 过滤

local t = require "assert"
local trigger = require "rule_engine.trigger"
local storage = require "storage"

-- 写入共享内存的触发规则集（ngx_reset 会清空 waf_rule，必须在 reset 后调用）
local function load_rules(rules)
    storage.set_shared("waf_rule", "active_trigger_rules",
                       storage.encode({ version = "v1", rules = rules }))
end

local function rule_with(conds, over)
    local r = {
        id = "t1", name = "test-rule", kind = "challenge",
        match_logic = "and", enabled = true,
        conditions = conds or {},
    }
    if over then
        for k, v in pairs(over) do r[k] = v end
    end
    return r
end

local function cond(field, operator, value)
    return { field = field, operator = operator, value = value }
end

t.test("无条件规则视为命中", function()
    ngx_reset()
    load_rules({ rule_with({}) })
    t.ok(trigger.match_any("challenge", {}))
end)

t.test("equals: host 条件去掉端口后精确匹配", function()
    ngx_reset()
    ngx.var.host = "cszj.wang:5208"
    load_rules({ rule_with({ cond("host", "equals", "cszj.wang") }) })
    t.ok(trigger.match_any("challenge", {}))
    ngx.var.host = "other.com"
    t.ok(not trigger.match_any("challenge", {}))
end)

t.test("prefix/contains: path 前缀与 UA 子串", function()
    ngx_reset()
    ngx.var.uri = "/admin/login"
    ngx.var.http_user_agent = "curl/8.0"
    load_rules({
        rule_with({ cond("path", "prefix", "/admin") }, { kind = "cc" }),
        rule_with({ cond("ua", "contains", "curl") }, { kind = "challenge" }),
    })
    t.ok(trigger.match_any("cc", {}), "path 前缀命中")
    t.ok(trigger.match_any("challenge", {}), "UA 子串命中")
end)

t.test("regex: PCRE 语义匹配（\\d 等转义）", function()
    ngx_reset()
    ngx.var.uri = "/admin123"
    load_rules({ rule_with({ cond("path", "regex", "^/admin\\d+") }) })
    t.ok(trigger.match_any("challenge", {}))
    -- 非法正则不抛错，视为不匹配
    load_rules({ rule_with({ cond("path", "regex", "[unclosed") }) })
    t.ok(not trigger.match_any("challenge", {}), "非法正则不命中")
end)

t.test("cidr: IP 网段命中", function()
    ngx_reset()
    load_rules({ rule_with({ cond("ip", "cidr", "10.0.0.0/8") }) })
    t.ok(trigger.match_any("challenge", { client_ip = "10.1.2.3" }))
    t.ok(not trigger.match_any("challenge", { client_ip = "8.8.8.8" }))
end)

t.test("in: 逗号分隔值列表任一相等", function()
    ngx_reset()
    ngx.req._method = "POST"
    load_rules({ rule_with({ cond("method", "in", "GET,POST") }) })
    t.ok(trigger.match_any("challenge", {}))
    ngx.req._method = "DELETE"
    t.ok(not trigger.match_any("challenge", {}))
end)

t.test("header 条件：任意请求头取值", function()
    ngx_reset()
    ngx.var.http_x_custom_hdr = "evil"
    load_rules({ rule_with({ { field = "header", header = "X-Custom-Hdr", operator = "equals", value = "evil" } }) })
    t.ok(trigger.match_any("challenge", {}))
end)

t.test("negate: 条件取反", function()
    ngx_reset()
    ngx.req._method = "POST"
    local c = cond("method", "equals", "GET")
    c.negate = true
    load_rules({ rule_with({ c }) })
    t.ok(trigger.match_any("challenge", {}), "非 GET 命中")
end)

t.test("match_logic: and 全命中 / or 任一命中", function()
    ngx_reset()
    ngx.var.uri = "/api/login"
    ngx.req._method = "GET"
    local path_c = cond("path", "prefix", "/api")
    local method_c = cond("method", "equals", "POST")
    -- and：POST 条件不满足 → 不命中
    load_rules({ rule_with({ path_c, method_c }, { match_logic = "and" }) })
    t.ok(not trigger.match_any("challenge", {}))
    -- or：任一命中
    load_rules({ rule_with({ path_c, method_c }, { match_logic = "or" }) })
    t.ok(trigger.match_any("challenge", {}))
end)

t.test("get_rules: 按 kind 过滤并跳过 disabled", function()
    ngx_reset()
    load_rules({
        rule_with({}, { id = "a", kind = "cc" }),
        rule_with({}, { id = "b", kind = "challenge", enabled = false }),
        rule_with({}, { id = "c", kind = "challenge" }),
    })
    local rules = trigger.get_rules("challenge")
    t.eq(#rules, 1)
    t.eq(rules[1].id, "c")
end)

t.test("match_first: 返回首个命中规则（含 config）", function()
    ngx_reset()
    load_rules({
        rule_with({ cond("path", "prefix", "/vip") }, { id = "r1", name = "VIP 验证", kind = "challenge", config = { mode = "basic" } }),
    })
    ngx.var.uri = "/vip/page"
    local r = trigger.match_first("challenge", {})
    t.notnil(r)
    t.eq(r.id, "r1")
    t.eq(r.name, "VIP 验证")
    t.eq(r.config.mode, "basic")
    ngx.var.uri = "/other"
    t.isnil(trigger.match_first("challenge", {}))
end)

t.test("未下发触发规则集时所有查询安全返回", function()
    ngx_reset()
    t.ok(not trigger.match_any("challenge", {}))
    t.isnil(trigger.match_first("cc", {}))
    t.eq(#(trigger.get_rules(nil) or {}), 0)
end)