-- waf/t/variables_test.lua
-- rule_engine/variables 变量提取单测

local t = require "assert"
local variables = require "rule_engine.variables"

t.test("URI: 取 ngx.var.uri", function()
    ngx_reset()
    ngx.var.uri = "/index.php"
    local out = variables.collect({ type = "URI" }, {})
    t.eq(#out, 1)
    t.eq(out[1], "/index.php")
end)

t.test("REQUEST_URI: 含查询串", function()
    ngx_reset()
    ngx.var.request_uri = "/index.php?id=1"
    local out = variables.collect({ type = "REQUEST_URI" }, {})
    t.eq(out[1], "/index.php?id=1")
end)

t.test("METHOD: 请求方法", function()
    ngx_reset()
    ngx.req._method = "POST"
    local out = variables.collect({ type = "METHOD" }, {})
    t.eq(out[1], "POST")
end)

t.test("URI_ARGS: 全部值与多值参数", function()
    ngx_reset()
    ngx.req._args = { id = "1", name = "admin", tag = { "a", "b" } }
    local out = variables.collect({ type = "URI_ARGS" }, {})
    -- 3 个 key：id, name, tag(2 个值)
    t.eq(#out, 4)
end)

t.test("URI_ARGS: 含键名（parse keys）", function()
    ngx_reset()
    ngx.req._args = { id = "1" }
    local out = variables.collect({ type = "URI_ARGS", parse = { "keys" } }, {})
    -- 值 "1" + 键 "id"
    t.eq(#out, 2)
end)

t.test("URI_ARGS: specific 提取单个参数", function()
    ngx_reset()
    ngx.req._args = { id = "1", evil = "<script>" }
    local out = variables.collect({ type = "URI_ARGS", specific = "evil" }, {})
    t.eq(#out, 1)
    t.eq(out[1], "<script>")
end)

t.test("URI_ARGS: specific 不存在", function()
    ngx_reset()
    ngx.req._args = { id = "1" }
    local out = variables.collect({ type = "URI_ARGS", specific = "nope" }, {})
    t.eq(#out, 0)
end)

t.test("POST_ARGS: body 参数", function()
    ngx_reset()
    ngx.req._post = { username = "admin' OR 1=1" }
    local out = variables.collect({ type = "POST_ARGS" }, {})
    t.eq(out[1], "admin' OR 1=1")
end)

t.test("HEADERS: 全部与 specific", function()
    ngx_reset()
    ngx.req._headers = { ["user-agent"] = "sqlmap/1.0", host = "x.com" }
    local out = variables.collect({ type = "HEADERS" }, {})
    t.eq(#out, 2)
    local ua = variables.collect({ type = "HEADERS", specific = "user-agent" }, {})
    t.eq(ua[1], "sqlmap/1.0")
end)

t.test("COOKIE: 解析指定 cookie", function()
    ngx_reset()
    ngx.var.http_cookie = "session=abc; waf_pass=123:deadbeef; theme=dark"
    local out = variables.collect({ type = "COOKIE", specific = "waf_pass" }, {})
    t.eq(#out, 1)
    t.eq(out[1], "123:deadbeef")
end)

t.test("COOKIE: 全部 cookie 值", function()
    ngx_reset()
    ngx.var.http_cookie = "a=1; b=2"
    local out = variables.collect({ type = "COOKIE" }, {})
    t.eq(#out, 2)
end)

t.test("BODY: body 数据", function()
    ngx_reset()
    ngx.req._body = "id=1 AND 1=1"
    local out = variables.collect({ type = "BODY" }, {})
    t.eq(out[1], "id=1 AND 1=1")
end)

t.test("CLIENT_IP: 取 remote_addr", function()
    ngx_reset()
    ngx.var.remote_addr = "9.9.9.9"
    local out = variables.collect({ type = "CLIENT_IP" }, {})
    t.eq(out[1], "9.9.9.9")
end)

t.test("collect: 请求级缓存（同 key 只解析一次）", function()
    ngx_reset()
    ngx.req._args = { id = "1" }
    local ctx = { var_cache = {} }
    local first = variables.collect({ type = "URI_ARGS" }, ctx)
    -- 改变数据后再次收集，应命中缓存返回旧结果
    ngx.req._args = { id = "2" }
    local second = variables.collect({ type = "URI_ARGS" }, ctx)
    t.eq(first[1], "1")
    t.eq(second[1], "1")
end)

t.test("collect: 无 ctx 不缓存", function()
    ngx_reset()
    ngx.req._args = { id = "1" }
    variables.collect({ type = "URI_ARGS" }, nil)
    ngx.req._args = { id = "2" }
    local out = variables.collect({ type = "URI_ARGS" }, nil)
    t.eq(out[1], "2")
end)
