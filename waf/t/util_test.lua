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

t.test("is_static_path: 后缀匹配忽略大小写", function()
    local skip = { ext = { ".js", ".png" }, prefix = {} }
    t.ok(util.is_static_path("/assets/app.JS", skip))
    t.ok(util.is_static_path("/img/logo.png?x=1", skip) == false, "带 query 的 uri 不受剪枝")
    t.ok(util.is_static_path("/api/user", skip) == false)
end)

t.test("is_static_path: 前缀匹配", function()
    local skip = { ext = {}, prefix = { "/static/" } }
    t.ok(util.is_static_path("/static/css/site.css", skip))
    t.ok(util.is_static_path("/api/static-file", skip) == false, "前缀需从路径头匹配")
end)

t.test("is_static_path: 空配置与异常输入不命中", function()
    t.ok(util.is_static_path("/a.js", nil) == false)
    t.ok(util.is_static_path("/a.js", {}) == false)
    t.ok(util.is_static_path(nil, { ext = { ".js" } }) == false)
end)

t.test("match_regex_list: 任一正则命中", function()
    t.ok(util.match_regex_list("/api/v1/x", { "^/api", "/health" }))
    t.ok(util.match_regex_list("/health", { "^/api", "/health" }))
    t.ok(util.match_regex_list("/other", { "^/api", "/health" }) == false)
end)

t.test("match_regex_list: 空值/空列表/非法正则安全", function()
    t.ok(util.match_regex_list(nil, { "/x" }) == false)
    t.ok(util.match_regex_list("/x", nil) == false)
    t.ok(util.match_regex_list("/x", {}) == false)
    t.ok(util.match_regex_list("/x", { "" }) == false, "空 pattern 跳过")
    t.ok(util.match_regex_list("/x", { "[unclosed" }) == false, "非法正则不抛错")
end)

-- ========== XML 结构化解析 ==========

t.test("try_parse_xml: 非 XML 返回 nil", function()
    t.isnil(util.try_parse_xml("hello world"))
    t.isnil(util.try_parse_xml(""))
    t.isnil(util.try_parse_xml(nil))
end)

t.test("try_parse_xml: 标签/属性/文本展平", function()
    local vals = util.try_parse_xml('<root><item id="1">hello</item></root>')
    t.notnil(vals)
    local joined = table.concat(vals, "|")
    t.match(joined, "root")
    t.match(joined, "item")
    t.match(joined, "id")
    t.match(joined, "1")
    t.match(joined, "hello")
end)

t.test("try_parse_xml: CDATA 与注释处理", function()
    local vals = util.try_parse_xml('<a><!-- comment --><b><![CDATA[x<y>z]]></b></a>')
    t.notnil(vals)
    local joined = table.concat(vals, "|")
    t.match(joined, "x<y>z")
    t.no(joined:find("comment", 1, true), "注释内容不参与检测")
end)

t.test("try_parse_xml: DOCTYPE 整体保留（XXE 检测用）", function()
    local vals = util.try_parse_xml('<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo/>')
    t.notnil(vals)
    local joined = table.concat(vals, "|")
    t.match(joined, "ENTITY")
    t.match(joined, "SYSTEM")
    t.match(joined, "file:///etc/passwd")
end)

t.test("try_parse_xml: 单引号属性值", function()
    local vals = util.try_parse_xml("<a x='1'/>")
    t.notnil(vals)
    local joined = table.concat(vals, "|")
    t.match(joined, "x")
    t.match(joined, "1")
end)

t.test("try_parse_xml: 超长输入片段数量受限不抛错", function()
    local big = {}
    for i = 1, 5000 do big[#big + 1] = "<x" .. i .. "/>" end
    local ok, vals = pcall(util.try_parse_xml, table.concat(big))
    t.ok(ok, "不抛错")
    if ok then t.ok(vals == nil or #vals <= 1001, "片段数量受限") end
end)

t.test("mask_sensitive: JSON 键值打码", function()
    local mask = { enabled = true, fields = { "password", "token" }, regex = {} }
    local out = util.mask_sensitive([[{"username":"bob","password":"secret123"}]], mask)
    t.ok(out:find("password\":\"***", 1, true) ~= nil, "password 已打码")
    t.ok(out:find("secret123", 1, true) == nil, "原文已隐藏")
end)

t.test("mask_sensitive: form 键值打码", function()
    local mask = { enabled = true, fields = { "password" }, regex = {} }
    local out = util.mask_sensitive("user=bob&password=abc123&role=admin", mask)
    t.ok(out:find("password=***", 1, true) ~= nil)
    t.ok(out:find("abc123", 1, true) == nil)
end)

t.test("mask_sensitive: 正则打码手机号", function()
    local mask = { enabled = true, fields = {}, regex = { [[1[3-9]\d\d\d\d\d\d\d\d\d]] } }
    local out = util.mask_sensitive("联系 13812345678 咨询", mask)
    t.ok(out:find("13812345678", 1, true) == nil, "手机号已打码")
end)

t.test("mask_sensitive: disabled 原样返回", function()
    local mask = { enabled = false, fields = { "password" }, regex = {} }
    t.eq(util.mask_sensitive("password=abc", mask), "password=abc")
end)
