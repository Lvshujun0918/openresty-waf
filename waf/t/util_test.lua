-- waf/t/util_test.lua
-- rule_engine/util JSON 结构化工具单测

local t = require "assert"
local util = require "rule_engine.util"

t.test("try_parse_json: 非 JSON 返回 nil", function()
    t.isnil(util.try_parse_json(nil))
    t.isnil(util.try_parse_json(""))
    t.isnil(util.try_parse_json("hello world"))
    t.isnil(util.try_parse_json("plain=1&x=2"))
end)

t.test("try_parse_json: 解析对象为字段值列表", function()
    local ok, vals = util.try_parse_json('{"email":"x@163.com","password":"secret"}')
    t.ok(ok)
    t.eq(#vals, 2)
    local set = {}
    for _, v in ipairs(vals) do set[v] = true end
    t.ok(set["x@163.com"])
    t.ok(set["secret"])
end)

t.test("try_parse_json: 嵌套对象与数组展平", function()
    local ok, vals = util.try_parse_json('{"user":{"name":"a"},"tags":["x","y"],"n":3}')
    t.ok(ok)
    local set = {}
    for _, v in ipairs(vals) do set[v] = true end
    t.ok(set["a"], "嵌套值")
    t.ok(set["x"] and set["y"], "数组元素")
    t.ok(set["3"], "数字值转字符串")
end)

t.test("try_parse_json: 非法 JSON 返回 nil 不抛错", function()
    local ok, vals = util.try_parse_json('{"email":"x@163.com",,}')
    t.isnil(ok)
    t.isnil(util.try_parse_json('{broken'))
end)

t.test("try_parse_json: include_keys 收集字段路径", function()
    local ok, vals = util.try_parse_json('{"a":"1","b":{"c":"2"}}', true)
    t.ok(ok)
    local set = {}
    for _, v in ipairs(vals) do set[v] = true end
    t.ok(set["a"] and set["b.c"], "字段路径")
    t.ok(set["1"] and set["2"])
end)
