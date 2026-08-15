-- waf/t/storage_test.lua
-- storage 纯函数单测：get_client_ip / 共享内存封装 / encode decode

local t = require "assert"
local storage = require "storage"

t.test("get_client_ip: 无 XFF 取 remote_addr", function()
    ngx_reset()
    ngx.var.remote_addr = "10.0.0.1"
    ngx.var.http_x_forwarded_for = nil
    t.eq(storage.get_client_ip(), "10.0.0.1")
end)

t.test("get_client_ip: XFF 最左优先", function()
    ngx_reset()
    ngx.var.remote_addr = "10.0.0.1"
    ngx.var.http_x_forwarded_for = "8.8.8.8, 1.1.1.1"
    t.eq(storage.get_client_ip(), "8.8.8.8")
end)

t.test("get_client_ip: XFF 为 unknown 回退", function()
    ngx_reset()
    ngx.var.remote_addr = "10.0.0.1"
    ngx.var.http_x_forwarded_for = "unknown, 1.1.1.1"
    t.eq(storage.get_client_ip(), "10.0.0.1")
end)

t.test("get_client_ip: XFF 空白回退", function()
    ngx_reset()
    ngx.var.remote_addr = "10.0.0.1"
    ngx.var.http_x_forwarded_for = ""
    t.eq(storage.get_client_ip(), "10.0.0.1")
end)

-- 可信代理：列表为空时不信任 XFF（安全默认，防止伪造 XFF 绕过 IP 维度防护）
t.test("get_client_ip: 可信代理列表为空时不信任 XFF", function()
    ngx_reset()
    local config = require "config"
    local orig = config.trusted_proxies
    config.trusted_proxies = {}
    ngx.var.remote_addr = "10.0.0.1"
    ngx.var.http_x_forwarded_for = "8.8.8.8"
    t.eq(storage.get_client_ip(), "10.0.0.1")
    config.trusted_proxies = orig
end)

t.test("get_client_ip: 直连不在可信代理内时忽略 XFF", function()
    ngx_reset()
    local config = require "config"
    local orig = config.trusted_proxies
    config.trusted_proxies = { "10.0.0.0/8" }
    ngx.var.remote_addr = "1.2.3.4"
    ngx.var.http_x_forwarded_for = "8.8.8.8"
    t.eq(storage.get_client_ip(), "1.2.3.4")
    config.trusted_proxies = orig
end)

t.test("get_client_ip: 直连命中可信 CIDR 时取 XFF 最左", function()
    ngx_reset()
    local config = require "config"
    local orig = config.trusted_proxies
    config.trusted_proxies = { "10.0.0.0/8" }
    ngx.var.remote_addr = "10.0.0.5"
    ngx.var.http_x_forwarded_for = "8.8.8.8, 1.1.1.1"
    t.eq(storage.get_client_ip(), "8.8.8.8")
    config.trusted_proxies = orig
end)

t.test("get_client_ip: 可信代理精确 IP 匹配", function()
    ngx_reset()
    local config = require "config"
    local orig = config.trusted_proxies
    config.trusted_proxies = { "127.0.0.1" }
    ngx.var.remote_addr = "127.0.0.1"
    ngx.var.http_x_forwarded_for = "9.9.9.9"
    t.eq(storage.get_client_ip(), "9.9.9.9")
    config.trusted_proxies = orig
end)

t.test("shared: set/get/incr", function()
    ngx_reset()
    local ok, err = storage.set_shared("waf_counter", "k1", "v1", 0)
    t.ok(ok, "set: " .. tostring(err))
    t.eq(storage.get_shared("waf_counter", "k1"), "v1")
    local n = storage.incr_shared("waf_counter", "n", 1, 0, 60)
    t.eq(n, 1)
    local n2 = storage.incr_shared("waf_counter", "n", 1, 0, 60)
    t.eq(n2, 2)
end)

t.test("shared: 不存在的 dict 返回错误", function()
    ngx_reset()
    local v, err = storage.get_shared("no_such_dict", "k")
    t.isnil(v)
    t.notnil(err)
end)

t.test("shared: set nil 清除", function()
    ngx_reset()
    storage.set_shared("waf_counter", "tmp", "x", 0)
    storage.set_shared("waf_counter", "tmp", nil, 0)
    t.isnil(storage.get_shared("waf_counter", "tmp"))
end)

t.test("encode/decode: 表往返", function()
    local t0 = { a = 1, b = { c = "x" } }
    local s = storage.encode(t0)
    local t2 = storage.decode(s)
    t.eq(t2.a, 1)
    t.eq(t2.b.c, "x")
end)

t.test("encode: 字符串原样", function()
    t.eq(storage.encode("raw"), "raw")
end)

t.test("decode: 空/非法返回 nil", function()
    t.isnil(storage.decode(nil))
    t.isnil(storage.decode(""))
    t.isnil(storage.decode("{bad"))
end)
