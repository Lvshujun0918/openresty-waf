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

-- 响应检测规则（默认 LOG_ONLY：仅记录不拦截）

-- 26001 模式含分组 alternation（mock 的 PCRE→Lua 转换不支持 alternation），
-- 校验规则结构即可；执行语义由生产环境 PCRE 保证（见 26002 执行用例）。
t.test("26001: 响应体泄露规则定义完整", function()
    local rule = nil
    for _, r in ipairs(builtin.rules) do
        if r.id == "26001" then rule = r end
    end
    t.notnil(rule)
    t.eq(rule.phase, "body_filter")
    t.eq(rule.actions.disrupt, "LOG_ONLY")
    t.eq(rule.vars[1].type, "RESPONSE_BODY")
end)

-- 940001 语义检测依赖 libinjection.so（mock 环境缺失，降级为不匹配），
-- 校验规则结构；命中语义由生产环境 .so 保证。
t.test("940001: libinjection 语义规则定义完整且降级不误拦", function()
    local rule = nil
    for _, r in ipairs(builtin.rules) do
        if r.id == "940001" then rule = r end
    end
    t.notnil(rule)
    t.eq(rule.operator, "LIBINJECTION_SQLI")
    t.eq(rule.actions.disrupt, "BLOCK")
    -- .so 缺失时普通请求不因语义规则误拦
    ngx_reset()
    ngx.req._args = { id = "普通文本" }
    local ctx = { mode = "active" }
    t.isnil(engine.run(builtin, "access", ctx))
end)

t.test("26002: 响应头 X-Powered-By 命中监控不拦截", function()
    ngx_reset()
    ngx.resp._headers = { ["x-powered-by"] = "PHP/7.4" }
    local ctx = { mode = "active" }
    local res = engine.run(builtin, "header_filter", ctx)
    t.eq(res, "matched")
    t.isnil(ngx.exit_code)
    local hit = false
    for _, m in ipairs(ctx.matched) do
        if m.id == "26002" then hit = true end
    end
    t.ok(hit, "应记录 26002 命中")
end)