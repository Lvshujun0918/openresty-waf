-- waf/t/transforms_test.lua
-- rule_engine/transforms 变换链单测

local t = require "assert"
local transforms = require "rule_engine.transforms"

t.test("url_decode: %XX 与 +", function()
    t.eq(transforms.apply("a%20b", { "url_decode" }), "a b")
    t.eq(transforms.apply("a+b", { "url_decode" }), "a b")
    t.eq(transforms.apply("%27union%27", { "url_decode" }), "'union'")
end)

t.test("url_decode: 中文 UTF-8", function()
    t.eq(transforms.apply("%E6%B5%8B%E8%AF%95", { "url_decode" }), "测试")
end)

t.test("url_decode: nil 安全", function()
    t.eq(transforms.apply(nil, { "url_decode" }), "")
end)

t.test("to_lowercase: 大小写", function()
    t.eq(transforms.apply("UNION SELECT", { "to_lowercase" }), "union select")
    t.eq(transforms.apply(nil, { "to_lowercase" }), "")
end)

t.test("remove_comments: SQL 注释", function()
    local s = "1 /* comment */ union -- line\nselect # hash"
    local out = transforms.apply(s, { "remove_comments" })
    t.no(out:find("/%*", 1, true))
    t.no(out:find("%-%-", 1, true))
    t.no(out:find("#", 1, true))
    t.match(out, "union")
end)

t.test("remove_comments: 块注释跨行", function()
    local s = "a/**/b"
    t.eq(transforms.apply(s, { "remove_comments" }), "ab")
end)

t.test("compress_whitespace: 连续空白压缩", function()
    t.eq(transforms.apply("a\t  b\n\nc", { "compress_whitespace" }), "a b c")
    t.eq(transforms.apply(nil, { "compress_whitespace" }), "")
end)

t.test("normalize_path: 压缩重复斜杠", function()
    t.eq(transforms.apply("//etc//passwd", { "normalize_path" }), "/etc/passwd")
    t.eq(transforms.apply(nil, { "normalize_path" }), "")
end)

t.test("apply: 变换链串联", function()
    local s = "%27UNION%27"
    local out = transforms.apply(s, { "url_decode", "to_lowercase" })
    t.eq(out, "'union'")
end)

t.test("apply: 空变换返回原值", function()
    t.eq(transforms.apply("abc", nil), "abc")
    t.eq(transforms.apply("abc", {}), "abc")
end)

t.test("apply: 未知变换名跳过", function()
    t.eq(transforms.apply("abc", { "no_such_transform" }), "abc")
end)

t.test("is_valid: 变换名校验", function()
    t.ok(transforms.is_valid("url_decode"))
    t.ok(transforms.is_valid("normalize_path"))
    t.no(transforms.is_valid("nope"))
end)
