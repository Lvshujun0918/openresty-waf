-- waf/t/challenge_test.lua
-- detectors/challenge 人机验证（basic 模式）单测
-- 校验逻辑：签名 cookie "ts:sign"，sign = hash(secret:ip:ts)

local t = require "assert"
local challenge = require "detectors.challenge"

local function base_cfg()
    return {
        challenge = {
            enabled = true,
            mode = "basic",
            cookie_name = "waf_pass",
            cookie_secret = "test-secret",
            cookie_ttl = 300,
            page_path = "/__waf_challenge__",
            verify_path = "/__waf_challenge_verify__",
            captcha = { id = "", key = "", verify_api = "", sdk = "" },
        },
    }
end

local function make_cookie(cfg, ip, ts)
    -- 与 challenge.lua calc_sign 一致：md5(secret:ip:ts)
    local ch = cfg.challenge or cfg
    local sign = ngx.md5(ch.cookie_secret .. ":" .. ip .. ":" .. ts)
    return ts .. ":" .. sign
end

t.test("无 challenge 配置返回 nil", function()
    ngx_reset()
    t.isnil(challenge.check({ client_ip = "1.2.3.4" }, {}))
end)

t.test("未启用返回 nil", function()
    ngx_reset()
    local cfg = base_cfg()
    cfg.challenge.enabled = false
    t.isnil(challenge.check({ client_ip = "1.2.3.4" }, cfg))
end)

t.test("无 cookie → challenge", function()
    ngx_reset()
    ngx.var.http_cookie = "session=abc"
    t.eq(challenge.check({ client_ip = "1.2.3.4" }, base_cfg()), "challenge")
end)

t.test("错误签名 → challenge", function()
    ngx_reset()
    local cfg = base_cfg()
    ngx.var.http_cookie = "waf_pass=" .. tostring(os.time()) .. ":badbadbad"
    t.eq(challenge.check({ client_ip = "1.2.3.4" }, cfg), "challenge")
end)

t.test("正确签名 → 通过返回 nil", function()
    ngx_reset()
    local cfg = base_cfg()
    local ts = os.time()
    ngx.var.http_cookie = "waf_pass=" .. make_cookie(cfg, "1.2.3.4", ts)
    t.isnil(challenge.check({ client_ip = "1.2.3.4" }, cfg))
end)

t.test("过期签名 → challenge", function()
    ngx_reset()
    local cfg = base_cfg()
    local ts = os.time() - 99999
    ngx.var.http_cookie = "waf_pass=" .. make_cookie(cfg, "1.2.3.4", ts)
    t.eq(challenge.check({ client_ip = "1.2.3.4" }, cfg), "challenge")
end)

t.test("非数字 ts → challenge", function()
    ngx_reset()
    local cfg = base_cfg()
    ngx.var.http_cookie = "waf_pass=abc:def"
    t.eq(challenge.check({ client_ip = "1.2.3.4" }, cfg), "challenge")
end)

t.test("IP 维度：签名绑定 client_ip", function()
    ngx_reset()
    local cfg = base_cfg()
    local ts = os.time()
    ngx.var.http_cookie = "waf_pass=" .. make_cookie(cfg, "1.2.3.4", ts)
    -- 用不同 IP 访问 → 签名不匹配
    t.eq(challenge.check({ client_ip = "9.9.9.9" }, cfg), "challenge")
end)

