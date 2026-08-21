-- waf/t/hit_cache_test.lua
-- 命中缓存：可缓存判定 / 缓存键指纹 / 存取回路 / 主命中挑选

local t         = require "assert"
local hit_cache = require "hit_cache"

local cfg = { hit_cache = { enabled = true, ttl = 10 } }

local function mk_ctx(over)
    local ctx = {
        mode      = "active",
        client_ip = "1.2.3.4",
        request   = { method = "GET", host = "a.com", uri = "/x?y=1", path = "/x" },
        matched   = {},
    }
    if over then
        for k, v in pairs(over) do
            if k == "request" then
                for kk, vv in pairs(v) do ctx.request[kk] = vv end
            else
                ctx[k] = v
            end
        end
    end
    return ctx
end

local function fresh()
    ngx_reset()
    ngx.req._headers = { host = "a.com", ["user-agent"] = "ua1" }
end

t.test("enabled 开关", function()
    t.ok(hit_cache.enabled(cfg))
    t.no(hit_cache.enabled({}))
    t.no(hit_cache.enabled({ hit_cache = { enabled = false } }))
end)

t.test("cacheable 仅无请求体方法且 URI 有限长", function()
    fresh()
    t.ok(hit_cache.cacheable(mk_ctx()))
    t.ok(hit_cache.cacheable(mk_ctx({ request = { method = "HEAD" } })))
    t.no(hit_cache.cacheable(mk_ctx({ request = { method = "POST" } })))
    local long = mk_ctx({ request = { uri = "/" .. string.rep("a", 3000) } })
    t.no(hit_cache.cacheable(long))
end)

t.test("cache_key 稳定且对指纹差异敏感", function()
    fresh()
    local a = hit_cache.cache_key(cfg, mk_ctx())
    t.eq(a, hit_cache.cache_key(cfg, mk_ctx()))
    -- IP 差异
    t.no(a == hit_cache.cache_key(cfg, mk_ctx({ client_ip = "5.6.7.8" })))
    -- URI 差异
    t.no(a == hit_cache.cache_key(cfg, mk_ctx({ request = { uri = "/y?z=2" } })))
    -- 方法差异
    t.no(a == hit_cache.cache_key(cfg, mk_ctx({ request = { method = "HEAD" } })))
    -- 模式差异
    t.no(a == hit_cache.cache_key(cfg, mk_ctx({ mode = "detect" })))
    -- 请求头差异
    ngx.req._headers = { host = "a.com", ["user-agent"] = "ua2" }
    t.no(a == hit_cache.cache_key(cfg, mk_ctx()))
    -- 规则版本差异（键含 ruleset_version）
    fresh()
    local b0 = hit_cache.cache_key(cfg, mk_ctx())
    ngx.shared.waf_rule:set("ruleset_version", "42")
    local b1 = hit_cache.cache_key(cfg, mk_ctx())
    t.no(b0 == b1)
    -- 灰度 tag 差异（同稳定版本下灰度规则集缓存隔离）
    local c0 = hit_cache.cache_key(cfg, mk_ctx(), "c1")
    local c1 = hit_cache.cache_key(cfg, mk_ctx(), "c2")
    t.no(c0 == c1)
end)

t.test("store/lookup 回路：放行判定", function()
    fresh()
    local ctx = mk_ctx()
    t.eq(hit_cache.lookup(cfg, ctx), nil)
    hit_cache.store(cfg, ctx, false)
    local cached = hit_cache.lookup(cfg, ctx)
    t.ok(cached ~= nil)
    t.no(cached.blocked)
end)

t.test("store/lookup 回路：拦截判定含主命中条目", function()
    fresh()
    local ctx = mk_ctx()
    local m = { id = "20001", group = "sqli", severity = 3, msg = "SQLi" }
    hit_cache.store(cfg, ctx, true, m)
    local cached = hit_cache.lookup(cfg, ctx)
    t.ok(cached ~= nil and cached.blocked)
    t.eq(cached.matched.id, "20001")
    t.eq(cached.matched.severity, 3)
end)

t.test("store/lookup 按 tag 隔离", function()
    fresh()
    local ctx = mk_ctx()
    hit_cache.store(cfg, ctx, false, nil, "c1")
    t.eq(hit_cache.lookup(cfg, ctx), nil)
    t.ok(hit_cache.lookup(cfg, ctx, "c1") ~= nil)
    t.eq(hit_cache.lookup(cfg, ctx, "c2"), nil)
end)

t.test("ttl<=0 与禁用时不写入", function()
    fresh()
    local ctx = mk_ctx()
    hit_cache.store({ hit_cache = { enabled = true, ttl = 0 } }, ctx, false)
    t.eq(hit_cache.lookup(cfg, ctx), nil)
    hit_cache.store({ hit_cache = { enabled = false, ttl = 10 } }, ctx, false)
    t.eq(hit_cache.lookup(cfg, ctx), nil)
    -- 禁用时 lookup 恒未命中（即使值存在）
    hit_cache.store(cfg, ctx, false)
    t.eq(hit_cache.lookup({ hit_cache = { enabled = false } }, ctx), nil)
end)

t.test("坏缓存值按未命中处理", function()
    fresh()
    local ctx = mk_ctx()
    local key = hit_cache.cache_key(cfg, ctx)
    ngx.shared.waf_counter:set(key, "X-broken")
    t.eq(hit_cache.lookup(cfg, ctx), nil)
    ngx.shared.waf_counter:set(key, "B-not-json")
    t.eq(hit_cache.lookup(cfg, ctx), nil)
end)

t.test("primary_matched 取 severity 最高条目", function()
    local ctx = mk_ctx()
    ctx.matched = {
        { id = "1", severity = 1 },
        { id = "2", severity = 5 },
        { id = "3", severity = 3 },
    }
    t.eq(hit_cache.primary_matched(ctx).id, "2")
    -- 无 severity 视为 0；空 matched 返回 nil
    ctx.matched = { { id = "9" }, { id = "8", severity = -1 } }
    t.eq(hit_cache.primary_matched(ctx).id, "9")
    ctx.matched = {}
    t.eq(hit_cache.primary_matched(ctx), nil)
end)

t.test("命中统计计数递增", function()
    fresh()
    local ctx = mk_ctx()
    hit_cache.store(cfg, ctx, false)
    local misses0 = tonumber(ngx.shared.waf_counter:get("hc:stat:misses") or 0)
    hit_cache.lookup(cfg, ctx)  -- hit
    local hits1 = tonumber(ngx.shared.waf_counter:get("hc:stat:hits") or 0)
    t.eq(hits1, 1)
    local other = mk_ctx({ request = { uri = "/other" } })
    hit_cache.lookup(cfg, other)  -- miss
    local misses1 = tonumber(ngx.shared.waf_counter:get("hc:stat:misses") or 0)
    t.ok(misses1 >= misses0 + 1)
end)

t.summary("hit_cache_test")
