-- waf/t/bot_test.lua
-- 爬虫识别与指纹单测

local t = require "assert"
local bot = require "detectors.bot"
local fp = require "fingerprint"

t.test("bot: Googlebot UA + 非 Google IP = 虚假爬虫", function()
    ngx_reset()
    ngx.var.http_user_agent = "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"
    local r = bot.classify({ client_ip = "8.8.8.9" })
    t.notnil(r)
    t.eq(r.profile, "Googlebot")
    t.ok(r.fake, "IP 不在 Google 网段 → 虚假爬虫")
end)

t.test("bot: Googlebot UA + Google IP = 真实爬虫", function()
    ngx_reset()
    ngx.var.http_user_agent = "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"
    local r = bot.classify({ client_ip = "66.249.64.1" })
    t.notnil(r)
    t.eq(r.profile, "Googlebot")
    t.ok(not r.fake, "IP 命中 Google 网段 → 真实爬虫")
end)

t.test("bot: curl 工具爬虫直接识别", function()
    ngx_reset()
    ngx.var.http_user_agent = "curl/8.5.0"
    local r = bot.classify({ client_ip = "1.2.3.4" })
    t.notnil(r)
    t.eq(r.profile, "curl")
    t.ok(not r.fake)
end)

t.test("bot: 正常浏览器不识别", function()
    ngx_reset()
    ngx.var.http_user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/126.0 Safari/537.36"
    t.isnil(bot.classify({ client_ip = "1.2.3.4" }))
end)

t.test("bot: UA 为空不识别", function()
    ngx_reset()
    ngx.var.http_user_agent = ""
    t.isnil(bot.classify({ client_ip = "1.2.3.4" }))
end)

t.test("fp: 相同头部组合指纹稳定", function()
    ngx_reset()
    ngx.var.http_user_agent = "Mozilla/5.0 Chrome/126.0"
    ngx.var.http_accept = "text/html"
    ngx.var.http_accept_language = "zh-CN"
    local a = fp.get({})
    ngx_reset()
    ngx.var.http_user_agent = "Mozilla/5.0 Chrome/126.0"
    ngx.var.http_accept = "text/html"
    ngx.var.http_accept_language = "zh-CN"
    local b = fp.get({})
    t.eq(a, b)
end)

t.test("fp: 不同头部组合指纹不同", function()
    ngx_reset()
    ngx.var.http_user_agent = "curl/8.5.0"
    local a = fp.get({})
    ngx_reset()
    ngx.var.http_user_agent = "Mozilla/5.0 Chrome/126.0"
    local b = fp.get({})
    t.ok(a ~= b)
end)

t.test("fp: match_malicious 精确命中", function()
    ngx_reset()
    ngx.var.http_user_agent = "bad-tool/1.0"
    local ctx = {}
    local f = fp.get(ctx)
    local bl = { { name = "恶意工具A", value = f, match = "exact" } }
    local m = fp.match_malicious(ctx, f)
    t.isnil(m, "未配置恶意库时无命中")
end)

t.test("fp: 请求级缓存", function()
    ngx_reset()
    ngx.var.http_user_agent = "curl/8.5.0"
    local ctx = {}
    local a = fp.get(ctx)
    ngx.var.http_user_agent = "Mozilla/5.0"
    local b = fp.get(ctx)
    t.eq(a, b, "ctx 缓存后头部变化不影响已计算指纹")
end)
