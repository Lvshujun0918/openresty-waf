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

t.test("url_decode_twice: 双重编码还原", function()
    t.eq(transforms.apply("%2520%2573elect", { "url_decode_twice" }), " select")
end)

t.test("url_decode_twice: 单重编码中文与普通文本不变", function()
    t.eq(transforms.apply("%E6%B5%8B%E8%AF%95", { "url_decode_twice" }), "测试")
    t.eq(transforms.apply("plain text", { "url_decode_twice" }), "plain text")
end)

t.test("url_decode_twice: 连续编码最多解码 3 次不循环", function()
    local s = string.rep("%25", 10) .. "20"
    local out = transforms.apply(s, { "url_decode_twice" })
    t.ok(type(out) == "string" and #out > 0, "应返回字符串且不抛错")
end)

t.test("is_valid: 变换名校验", function()
    t.ok(transforms.is_valid("url_decode"))
    t.ok(transforms.is_valid("url_decode_twice"))
    t.ok(transforms.is_valid("normalize_path"))
    t.no(transforms.is_valid("nope"))
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

-- ========== 编码解码（base64 / hex / html_entity） ==========

t.test("base64_decode: 解码疑似 base64 串", function()
    -- "union select" 的 base64：dW5pb24gc2VsZWN0
    t.eq(transforms.apply("dW5pb24gc2VsZWN0", { "base64_decode" }), "union select")
    -- "<script>" 的 base64：PHNjcmlwdD4=
    t.eq(transforms.apply("PHNjcmlwdD4=", { "base64_decode" }), "<script>")
end)

t.test("base64_decode: 非 base64 文本不解码（护栏）", function()
    t.eq(transforms.apply("hello world", { "base64_decode" }), "hello world")
    t.eq(transforms.apply("a=b&c=d", { "base64_decode" }), "a=b&c=d")
    t.eq(transforms.apply(nil, { "base64_decode" }), "")
end)

t.test("base64_decode: 长度非 4 倍数不解码", function()
    t.eq(transforms.apply("abcde", { "base64_decode" }), "abcde")
end)

t.test("hex_decode: 解码 hex 串", function()
    t.eq(transforms.apply("3c7363726970743e", { "hex_decode" }), "<script>")
    t.eq(transforms.apply("756e696f6e", { "hex_decode" }), "union")
end)

t.test("hex_decode: 非 hex 文本不解码", function()
    t.eq(transforms.apply("hello", { "hex_decode" }), "hello")
    t.eq(transforms.apply("abc", { "hex_decode" }), "abc")  -- 奇数长度
    t.eq(transforms.apply(nil, { "hex_decode" }), "")
end)

t.test("html_entity_decode: 命名与数字实体", function()
    t.eq(transforms.apply("&lt;script&gt;alert(1)&lt;/script&gt;", { "html_entity_decode" }),
         "<script>alert(1)</script>")
    t.eq(transforms.apply("&#60;img&#62;", { "html_entity_decode" }), "<img>")
    t.eq(transforms.apply("&#x3c;svg&#x3e;", { "html_entity_decode" }), "<svg>")
end)

t.test("html_entity_decode: 无实体/非法实体保持原样", function()
    t.eq(transforms.apply("plain text", { "html_entity_decode" }), "plain text")
    t.eq(transforms.apply("&unknown;", { "html_entity_decode" }), "&unknown;")
    t.eq(transforms.apply(nil, { "html_entity_decode" }), "")
end)

t.test("is_valid: 新解码变换可校验", function()
    t.ok(transforms.is_valid("base64_decode"))
    t.ok(transforms.is_valid("hex_decode"))
    t.ok(transforms.is_valid("html_entity_decode"))
end)
