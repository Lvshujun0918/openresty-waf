-- waf/t/variables_multipart_test.lua
-- rule_engine/variables 对 multipart/form-data 的文本字段提取：
-- 排除文件字段（二进制体），防止文本检测器误报

local t = require "assert"
local variables = require "rule_engine.variables"

local B = "----MultipartBoundaryXYZ"

-- 构造 multipart body：文本字段 + 文件字段（含二进制伪 XSS/CRLF 特征）
local function build_body()
    return "--" .. B .. "\r\n"
        .. 'Content-Disposition: form-data; name="title"\r\n\r\n'
        .. "我的文章标题\r\n"
        .. "--" .. B .. "\r\n"
        .. 'Content-Disposition: form-data; name="desc"\r\n\r\n'
        .. "正常描述\r\n"
        .. "--" .. B .. "\r\n"
        .. 'Content-Disposition: form-data; name="file"; filename="image.png"\r\n'
        .. "Content-Type: image/png\r\n\r\n"
        .. "\x89PNG\r\nfoo<?php ?>bar\x00\xff\r\n<script>evil</script>\r\n"
        .. "--" .. B .. "--\r\n"
end

local function ctx()
    return { var_cache = {} }
end

-- ============ POST_ARGS：multipart 排除文件字段 ============

t.test("POST_ARGS: 仅提取文本字段值，跳过文件二进制", function()
    ngx_reset()
    ngx.var.content_type = "multipart/form-data; boundary=" .. B
    ngx.req._body = build_body()
    local out = variables.collect({ type = "POST_ARGS" }, ctx())
    -- 文本字段：title + desc，均为明文可读
    t.eq(#out, 2)
    t.match(out[1], "我的文章标题")
    t.match(out[2], "正常描述")
    -- 断言不含文件二进制中的 XSS/PHP 特征
    for _, v in ipairs(out) do
        t.no(v:find("script", 1, true), "文件内容不应进入 POST_ARGS")
        t.no(v:find("php", 1, true), "文件内容不应进入 POST_ARGS")
    end
end)

t.test("POST_ARGS: parse keys 同时收集键名", function()
    ngx_reset()
    ngx.var.content_type = "multipart/form-data; boundary=" .. B
    ngx.req._body = build_body()
    local out = variables.collect({ type = "POST_ARGS", parse = { "keys" } }, ctx())
    -- 与 collect_args 惯例一致：值在前键在后 → 值,键,值,键
    t.eq(#out, 4)
    t.eq(out[2], "title")
    t.eq(out[4], "desc")
    -- 不得出现文件名或文件内容
    for _, v in ipairs(out) do
        t.no(tostring(v):find("image.png", 1, true), "键名不应含文件名")
    end
end)

t.test("POST_ARGS: specific 提取指定文本字段", function()
    ngx_reset()
    ngx.var.content_type = "multipart/form-data; boundary=" .. B
    ngx.req._body = build_body()
    local out = variables.collect({ type = "POST_ARGS", specific = "desc" }, ctx())
    t.eq(#out, 1)
    t.match(out[1], "正常描述")
end)

t.test("POST_ARGS: specific 指定文件字段名不产生输出", function()
    ngx_reset()
    ngx.var.content_type = "multipart/form-data; boundary=" .. B
    ngx.req._body = build_body()
    local out = variables.collect({ type = "POST_ARGS", specific = "file" }, ctx())
    t.eq(#out, 0, "文件字段不应被提取")
end)

-- ============ BODY：multipart 仅文本字段 ============

t.test("BODY: multipart 仅返回文本字段值", function()
    ngx_reset()
    ngx.var.content_type = "multipart/form-data; boundary=" .. B
    ngx.req._body = build_body()
    local out = variables.collect({ type = "BODY" }, ctx())
    t.eq(#out, 2)
    t.match(out[1], "我的文章标题")
    t.match(out[2], "正常描述")
    for _, v in ipairs(out) do
        t.no(tostring(v):find("script", 1, true), "BODY 不应含文件二进制")
    end
end)

t.test("BODY: 非 multipart 仍返回完整 body", function()
    ngx_reset()
    ngx.var.content_type = "application/x-www-form-urlencoded"
    ngx.req._body = "a=1&b=<script>alert(1)</script>"
    local out = variables.collect({ type = "BODY" }, ctx())
    t.eq(#out, 1)
    t.eq(out[1], "a=1&b=<script>alert(1)</script>")
end)

-- ============ POST_ARGS_DUP：multipart 文本字段重复 ============

t.test("POST_ARGS_DUP: 重复文本字段名与全部值", function()
    ngx_reset()
    ngx.var.content_type = "multipart/form-data; boundary=" .. B
    ngx.req._body = "--" .. B .. "\r\n"
        .. 'Content-Disposition: form-data; name="tag"\r\n\r\n'
        .. "v1\r\n"
        .. "--" .. B .. "\r\n"
        .. 'Content-Disposition: form-data; name="tag"\r\n\r\n'
        .. "v2\r\n"
        .. "--" .. B .. "\r\n"
        .. 'Content-Disposition: form-data; name="file"; filename="a.bin"\r\n\r\n'
        .. "\x00\x01\x02\r\n"
        .. "--" .. B .. "--\r\n"
    local out = variables.collect({ type = "POST_ARGS_DUP" }, ctx())
    t.eq(#out, 3, "键名 + 两个值")
    t.eq(out[1], "tag")
    t.eq(out[2], "v1")
    t.eq(out[3], "v2")
end)

t.test("POST_ARGS_DUP: 无重复字段不输出", function()
    ngx_reset()
    ngx.var.content_type = "multipart/form-data; boundary=" .. B
    ngx.req._body = build_body()
    local out = variables.collect({ type = "POST_ARGS_DUP" }, ctx())
    t.eq(#out, 0)
end)

-- ============ 缓存与回退 ============

t.test("collect: multipart 结果进 var_cache", function()
    ngx_reset()
    ngx.var.content_type = "multipart/form-data; boundary=" .. B
    ngx.req._body = build_body()
    local c = ctx()
    local out1 = variables.collect({ type = "POST_ARGS" }, c)
    local out2 = variables.collect({ type = "POST_ARGS" }, c)
    t.ok(out1 == out2, "同一请求内重复提取应命中缓存")
end)

t.test("collect: 缺 boundary 时 multipart 回退为空", function()
    ngx_reset()
    ngx.var.content_type = "multipart/form-data"
    ngx.req._body = build_body()
    local out = variables.collect({ type = "BODY" }, ctx())
    t.eq(#out, 0)
end)