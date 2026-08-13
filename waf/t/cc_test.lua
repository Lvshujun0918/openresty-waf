-- waf/t/cc_test.lua
-- detectors/cc CC 防刷单测

local t = require "assert"
local cc = require "detectors.cc"

local function base_cfg()
    return {
        cc = {
            rate = "100/60",
            ban_duration = 300,
            ban_key_prefix = "waf:cc:ban:",
            counter_prefix = "waf:cc:cnt:",
        },
    }
end

t.test("未超频返回 nil", function()
    ngx_reset()
    local ctx = { client_ip = "1.2.3.4", request = { path = "/" } }
    local res = cc.check(ctx, base_cfg())
    t.isnil(res)
end)

t.test("达到阈值触发封禁", function()
    ngx_reset()
    local cfg = base_cfg()
    cfg.cc.rate = "3/60"
    local ctx = { client_ip = "1.2.3.4", request = { path = "/" } }
    local res
    res = cc.check(ctx, cfg); t.isnil(res, "1st")
    res = cc.check(ctx, cfg); t.isnil(res, "2nd")
    res = cc.check(ctx, cfg); t.eq(res, "banned", "3rd")
end)

t.test("已封禁直接返回 banned", function()
    ngx_reset()
    local cfg = base_cfg()
    ngx.shared.waf_counter:set("waf:cc:ban:1.2.3.4", 12345, 300)
    local ctx = { client_ip = "1.2.3.4", request = { path = "/" } }
    t.eq(cc.check(ctx, cfg), "banned")
end)

t.test("不同路径独立计数，封禁为 IP 级", function()
    ngx_reset()
    local cfg = base_cfg()
    cfg.cc.rate = "5/60"
    local ctxA = { client_ip = "1.2.3.4", request = { path = "/a" } }
    local ctxB = { client_ip = "1.2.3.4", request = { path = "/b" } }
    -- 各自独立计数，未达阈值前均不封禁
    cc.check(ctxA, cfg)
    cc.check(ctxA, cfg)
    cc.check(ctxB, cfg)
    t.isnil(cc.check(ctxA, cfg), "path /a not banned yet")
    t.isnil(cc.check(ctxB, cfg), "path /b not banned yet")
    -- /a 达到阈值 → IP 级封禁，/b 同样被 ban
    cc.check(ctxA, cfg)
    t.eq(cc.check(ctxA, cfg), "banned", "path /a banned")
    t.eq(cc.check(ctxB, cfg), "banned", "IP-level ban applies to /b")
end)

t.test("无 cc 配置返回 nil", function()
    ngx_reset()
    local ctx = { client_ip = "1.2.3.4", request = { path = "/" } }
    t.isnil(cc.check(ctx, {}))
    t.isnil(cc.check(ctx, nil))
end)

t.test("无 client_ip 返回 nil", function()
    ngx_reset()
    local ctx = { request = { path = "/" } }
    t.isnil(cc.check(ctx, base_cfg()))
end)

t.test("unban 解除封禁", function()
    ngx_reset()
    local cfg = base_cfg()
    ngx.shared.waf_counter:set("waf:cc:ban:1.2.3.4", 12345, 300)
    local ctx = { client_ip = "1.2.3.4" }
    t.eq(cc.check(ctx, cfg), "banned")
    cc.unban(ctx, cfg)
    t.isnil(ngx.shared.waf_counter:get("waf:cc:ban:1.2.3.4"))
    t.isnil(cc.check(ctx, cfg))
end)

t.test("封禁过期后自动解除", function()
    ngx_reset()
    local cfg = base_cfg()
    ngx.shared.waf_counter:set("waf:cc:ban:1.2.3.4", 12345, 300)
    -- 强制标记为已过期（模拟 TTL 到期）
    ngx.shared.waf_counter:_expire_at("waf:cc:ban:1.2.3.4", os.time() - 1)
    local ctx = { client_ip = "1.2.3.4", request = { path = "/" } }
    t.isnil(cc.check(ctx, cfg))
end)

-- ============ 全局阈值（触发规则由 rule_engine.trigger 单独测试） ============

t.test("同 IP 不同 host 独立计数（封禁仍为 IP 级）", function()
    ngx_reset()
    local cfg = base_cfg()
    cfg.cc.rate = "2/60"
    local ctxA = { client_ip = "1.2.3.4", request = { host = "a.example.com", path = "/" } }
    local ctxB = { client_ip = "1.2.3.4", request = { host = "b.example.com", path = "/" } }
    cc.check(ctxA, cfg) -- A 计数 1
    t.isnil(cc.check(ctxB, cfg), "B 计数 1，不受 A 的计数影响")
    t.eq(cc.check(ctxB, cfg), "banned", "B 自身到 2 才触发封禁")
end)

t.test("全局阈值生效", function()
    ngx_reset()
    local cfg = base_cfg()
    cfg.cc.rate = "3/60"
    local ctx = { client_ip = "1.2.3.4", request = { host = "x.com", path = "/" } }
    cc.check(ctx, cfg)
    cc.check(ctx, cfg)
    t.eq(cc.check(ctx, cfg), "banned", "default rate 3")
end)
