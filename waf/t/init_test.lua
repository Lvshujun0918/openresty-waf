-- waf/t/init_test.lua
-- init 热更校验单测：版本合法性/单调性与规则集结构校验（回滚保护）

local t = require "assert"
local init = require "init"

t.test("version_newer: 数字版本严格递增", function()
    t.ok(init.version_newer("1", "2"))
    t.no(init.version_newer("2", "2"))
    t.no(init.version_newer("5", "3"))
end)

t.test("version_newer: 当前为空（规则集未就绪）时接受首个数字版本", function()
    t.ok(init.version_newer(nil, "1"))
    t.ok(init.version_newer("", "1"))
end)

t.test("version_newer: 非法/非数字版本拒绝", function()
    t.no(init.version_newer("1", "v2"))
    t.no(init.version_newer("1", ""))
    t.no(init.version_newer("1", "abc"))
    t.no(init.version_newer("1", nil))
end)

t.test("validate_ruleset: 合法规则集通过", function()
    t.ok(init.validate_ruleset({ rules = { { id = "10001" }, { id = "20001" } } }))
end)

t.test("validate_ruleset: 结构非法拒绝", function()
    t.no(init.validate_ruleset(nil))
    t.no(init.validate_ruleset({}))
    t.no(init.validate_ruleset({ rules = {} }))
    t.no(init.validate_ruleset({ rules = { { foo = 1 } } }))
    t.no(init.validate_ruleset({ rules = { { id = "" } } }))
    t.no(init.validate_ruleset({ rules = "not-array" }))
end)
