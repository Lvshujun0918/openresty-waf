-- waf/t/builtin_test.lua
-- ruleset/builtin 内置规则回归：协议异常类（25001 起）。
-- 说明：mock 的 PCRE→Lua 转换不支持负向断言/\x 转义/{n,m} 量词（LuaJIT
-- string.find 不支持重复量词），25001（负向断言）、25002（.{8192,}）、
-- 25005（%00）、25006（\x 控制字符）不在本文件覆盖。

local t = require "assert"
local engine = require "rule_engine.engine"
local builtin = require "ruleset.builtin"

-- 用指定请求态运行完整内置规则集（active 模式）
local function run_with(method, uri, args, headers)
    ngx_reset()
    ngx.req._method = method
    ngx.var.uri = uri
    ngx.var.request_uri = uri
    ngx.req._args = args or {}
    ngx.req._headers = headers or {}
    return engine.run(builtin, "access", { mode = "active" })
end

t.test("内置规则：普通请求不误拦", function()
    local ctx = { mode = "active" }
    ngx_reset()
    ngx.req._method = "GET"
    ngx.var.uri = "/hello"
    ngx.var.request_uri = "/hello"
    local res = engine.run(builtin, "access", ctx)
    t.isnil(res)
end)

t.test("25003: 方法名含空格拦截 405", function()
    local ctx = { mode = "active" }
    ngx_reset()
    ngx.req._method = "GE T"
    ngx.var.uri = "/"
    ngx.var.request_uri = "/"
    t.exits(function() engine.run(builtin, "access", ctx) end, 405)
end)

t.test("25004: Content-Length 非数字拦截 400", function()
    local ctx = { mode = "active" }
    ngx_reset()
    ngx.req._method = "POST"
    ngx.var.uri = "/"
    ngx.var.request_uri = "/"
    ngx.req._headers = { ["content-length"] = "12abc" }
    t.exits(function() engine.run(builtin, "access", ctx) end, 400)
end)

t.test("25004: 合法 Content-Length 不误拦", function()
    local ctx = { mode = "active" }
    ngx_reset()
    ngx.req._method = "POST"
    ngx.var.uri = "/"
    ngx.var.request_uri = "/"
    ngx.req._headers = { ["content-length"] = "128" }
    local res = engine.run(builtin, "access", ctx)
    t.isnil(res)
end)