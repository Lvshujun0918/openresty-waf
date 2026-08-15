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

-- ===== JA4 指纹（对齐官方 FoxIO 算法） =====
local ja4 = require "ja4"

t.test("ja4: TLS1.3 官方格式", function()
    local hello = {
        version = "TLSv1.3",
        sn = "example.com",
        alpn = "h2",
        cipher_suites = { 0x1301, 0x1302, 0x1303, 0x1304, 0xc02f, 0xcca8 },
        extensions = { 0, 16, 43, 51, 13 },
        sig_algs = { 0x0403, 0x0503 },
    }
    local j = ja4.calc(hello)
    t.notnil(j)
    -- t13 + d + 06 + 05 + h2
    t.ok(j:sub(1, 3) == "t13", "TLS1.3: " .. tostring(j))
    t.ok(j:sub(4, 4) == "d", "SNI: " .. tostring(j))
    t.ok(j:sub(5, 6) == "06", "cipher_len: " .. tostring(j))
    t.ok(j:sub(7, 8) == "05", "ext_len(含SNI/ALPN): " .. tostring(j))
    t.ok(j:sub(9, 10) == "h2", "alpn: " .. tostring(j))
    t.ok(j:match("^t13d0605h2_%w+_%w+$"), "完整格式: " .. tostring(j))
end)

t.test("ja4: 无 SNI/ALPN 无签名算法", function()
    local hello = {
        version = "TLSv1.2",
        cipher_suites = { 0xc02f, 0xcca8 },
        extensions = { 0 },
    }
    local j = ja4.calc(hello)
    t.notnil(j)
    t.ok(j:sub(1, 4) == "t12i", "TLS1.2 无SNI: " .. tostring(j))
    t.ok(j:sub(5, 6) == "02", "cipher_len 02: " .. tostring(j))
    t.ok(j:sub(7, 8) == "01", "ext_len 01: " .. tostring(j))
    t.ok(j:sub(9, 10) == "00", "alpn 00: " .. tostring(j))
    t.ok(j:match("^t12i020100_%w+_%w+$"), "格式: " .. tostring(j))
end)

t.test("ja4: cipher 排序影响哈希", function()
    local a = ja4.calc({ version = "TLSv1.3", cipher_suites = { 0x1301, 0x1302 }, extensions = { 0 } })
    local b = ja4.calc({ version = "TLSv1.3", cipher_suites = { 0x1302, 0x1301 }, extensions = { 0 } })
    t.eq(a, b, "排序后相同")
end)

t.test("ja4: 相同握手指纹稳定", function()
    local a = ja4.calc({ version = "TLSv1.3", cipher_suites = { 0x1301 }, extensions = { 0 } })
    local b = ja4.calc({ version = "TLSv1.3", cipher_suites = { 0x1301 }, extensions = { 0 } })
    t.eq(a, b)
end)

t.test("ja4: 空列表返回 12 个 0 哈希段", function()
    local j = ja4.calc({ version = "TLSv1.3", cipher_suites = {}, extensions = { 0 } })
    t.notnil(j)
    t.ok(j:match("^t13i000100_000000000000_000000000000$"), "空列表: " .. tostring(j))
end)

t.test("ja4: nil 输入返回 nil", function()
    t.isnil(ja4.calc(nil))
end)

t.test("ja4: 签名算法附加段", function()
    local hello = {
        version = "TLSv1.3",
        cipher_suites = { 0x1301 },
        extensions = { 0, 13 },
        sig_algs = { 0x0403, 0x0804 },
    }
    local j = ja4.calc(hello)
    t.notnil(j)
    -- 扩展去 SNI/ALPN 后剩 [13]（sigalg 在扩展列表里也算一个扩展）
    t.ok(j:match("^t13i010200_%w+_%w+$"), "含 sig_algs: " .. tostring(j))
end)

t.test("fp: effective 优先 ja4", function()
    ngx_reset()
    ngx.var.http_user_agent = "curl/8.5.0"
    local ctx = { ja4 = "t13d1516h2_test_test" }
    local jfp, src = fp.effective(ctx)
    t.eq(jfp, "t13d1516h2_test_test")
    t.eq(src, "ja4")
    -- 无 ja4 回退 http
    local ctx2 = {}
    local hfp, src2 = fp.effective(ctx2)
    t.ok(hfp ~= nil and #hfp > 0)
    t.eq(src2, "http")
end)

t.test("fp: effective TLS 请求用握手指纹", function()
    ngx_reset()
    ngx.var.http_user_agent = "curl/8.5.0"
    ngx.var.ssl_protocol = "TLSv1.3"
    ngx.var.ssl_ciphers = "TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384"
    ngx.var.ssl_curves = "prime256v1:secp384r1"
    local ctx = {}
    local tfp, src = fp.effective(ctx)
    t.eq(src, "tls")
    t.ok(tfp ~= nil and #tfp > 0, "tls 指纹非空")
    t.eq(tfp, ctx.tls_fp, "ctx 缓存")
end)

t.test("fp: 非 TLS 请求回退 http", function()
    ngx_reset()
    ngx.var.http_user_agent = "curl/8.5.0"
    ngx.var.ssl_protocol = ""
    local ctx = {}
    local hfp, src = fp.effective(ctx)
    t.eq(src, "http")
    t.ok(hfp ~= nil and #hfp > 0)
end)

-- ===== JA4H HTTP 客户端指纹 =====
local ja4h = require "ja4h"

t.test("ja4h: GET HTTP/1.1 官方格式", function()
    ngx_reset()
    ngx.req._method = "GET"
    ngx.req._http_version = 1.1
    ngx.var.http_accept_language = "zh-CN,zh;q=0.9"
    ngx.req._headers = { ["user-agent"] = "curl/8.5.0", ["accept"] = "*/*" }
    local j = ja4h.calc()
    t.notnil(j)
    -- ge11nn02zh-c_...
    t.ok(j:match("^ge11nn02zhcn_%w+_000000000000_000000000000$"), "GET 无Cookie: " .. tostring(j))
end)

t.test("ja4h: POST 带 Cookie/Referer", function()
    ngx_reset()
    ngx.req._method = "POST"
    ngx.req._http_version = 2.0
    ngx.var.http_cookie = "session=abc123; theme=dark"
    ngx.var.http_referer = "https://example.com/"
    ngx.req._headers = { ["content-type"] = "application/json" }
    local j = ja4h.calc()
    t.notnil(j)
    t.ok(j:match("^po20cr01zhcn_%w+_%w+_%w+$"), "POST H2 Cookie: " .. tostring(j))
end)

t.test("ja4h: 头部排序稳定", function()
    ngx_reset()
    ngx.req._method = "GET"
    ngx.req._http_version = 1.1
    ngx.req._headers = { ["accept"] = "*/*", ["user-agent"] = "curl" }
    local a = ja4h.calc()
    ngx_reset()
    ngx.req._method = "GET"
    ngx.req._http_version = 1.1
    ngx.req._headers = { ["user-agent"] = "curl", ["accept"] = "*/*" }
    local b = ja4h.calc()
    t.eq(a, b, "排序后稳定")
end)
