-- waf/t/cc_test.lua
-- detectors/cc CC 防刷单测

local t = require "assert"
local cc = require "detectors.cc"
local storage = require "storage"

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

-- 注入后台下发的 CC 规则集到共享内存
local function set_cc_rules(rules)
    storage.set_shared("waf_rule", "active_cc_rules",
                       storage.encode({ version = "test", rules = rules }))
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

-- ============ 精细化规则（host + path） ============

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

t.test("规则命中：host+path 使用规则阈值", function()
    ngx_reset()
    local cfg = base_cfg()
    set_cc_rules({
        { host = "api.example.com", path = "/v1", rate = "2/60", ban_duration = 60, enabled = true },
    })
    local ctx = { client_ip = "1.2.3.4", request = { host = "api.example.com", path = "/v1/list" } }
    cc.check(ctx, cfg)
    t.eq(cc.check(ctx, cfg), "banned", "rule rate 2 -> banned")
end)

t.test("规则未命中时回退全局默认", function()
    ngx_reset()
    local cfg = base_cfg()
    cfg.cc.rate = "5/60"
    set_cc_rules({
        { host = "api.example.com", path = "/v1", rate = "2/60", ban_duration = 60, enabled = true },
    })
    -- 非 api.example.com → 回退全局 5/60，2 次不封禁
    local ctx = { client_ip = "1.2.3.4", request = { host = "www.example.com", path = "/v1" } }
    cc.check(ctx, cfg)
    t.isnil(cc.check(ctx, cfg), "not banned under default rate 5")
end)

t.test("规则优先级：host+path 优于仅 host 优于全局", function()
    ngx_reset()
    local cfg = base_cfg()
    set_cc_rules({
        { host = "", path = "", rate = "100/60", ban_duration = 300, enabled = true },        -- 全局
        { host = "api.example.com", path = "", rate = "10/60", ban_duration = 300, enabled = true }, -- 仅 host
        { host = "api.example.com", path = "/v1", rate = "2/60", ban_duration = 60, enabled = true }, -- 最具体
    })
    -- /v1 命中最具体规则 → 2 次封禁
    local ctx = { client_ip = "1.2.3.4", request = { host = "api.example.com", path = "/v1/list" } }
    cc.check(ctx, cfg)
    t.eq(cc.check(ctx, cfg), "banned", "most specific rule")
    ngx_reset()
    -- 非 /v1 命中仅 host 规则 → 10/60，2 次不封禁
    set_cc_rules({
        { host = "", path = "", rate = "100/60", ban_duration = 300, enabled = true },
        { host = "api.example.com", path = "", rate = "10/60", ban_duration = 300, enabled = true },
        { host = "api.example.com", path = "/v1", rate = "2/60", ban_duration = 60, enabled = true },
    })
    local ctx2 = { client_ip = "1.2.3.4", request = { host = "api.example.com", path = "/other" } }
    cc.check(ctx2, cfg)
    t.isnil(cc.check(ctx2, cfg), "host-only rule rate 10")
end)

t.test("host 通配符 *.example.com 匹配子域", function()
    ngx_reset()
    local cfg = base_cfg()
    set_cc_rules({
        { host = "*.example.com", path = "", rate = "2/60", ban_duration = 60, enabled = true },
    })
    local ctx = { client_ip = "1.2.3.4", request = { host = "sub.example.com", path = "/" } }
    cc.check(ctx, cfg)
    t.eq(cc.check(ctx, cfg), "banned", "subdomain matched")
end)

t.test("path 前缀匹配：/admin 命中 /admin/login", function()
    ngx_reset()
    local cfg = base_cfg()
    set_cc_rules({
        { host = "", path = "/admin", rate = "2/60", ban_duration = 60, enabled = true },
    })
    local ctx = { client_ip = "1.2.3.4", request = { host = "x.com", path = "/admin/login" } }
    cc.check(ctx, cfg)
    t.eq(cc.check(ctx, cfg), "banned", "path prefix matched")
end)

t.test("无规则集时回退全局默认", function()
    ngx_reset()
    local cfg = base_cfg()
    cfg.cc.rate = "3/60"
    local ctx = { client_ip = "1.2.3.4", request = { host = "x.com", path = "/" } }
    cc.check(ctx, cfg)
    cc.check(ctx, cfg)
    t.eq(cc.check(ctx, cfg), "banned", "default rate 3")
end)
