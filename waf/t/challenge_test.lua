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

t.test("未来时间戳 → challenge", function()
    ngx_reset()
    local cfg = base_cfg()
    local ts = os.time() + 3600
    ngx.var.http_cookie = "waf_pass=" .. make_cookie(cfg, "1.2.3.4", ts)
    t.eq(challenge.check({ client_ip = "1.2.3.4" }, cfg), "challenge")
end)

t.test("cookie_name 含模式特殊字符仍正常匹配", function()
    ngx_reset()
    local cfg = base_cfg()
    cfg.challenge.cookie_name = "waf.pass+"
    local ts = os.time()
    local ch = cfg.challenge
    local sign = ngx.md5(ch.cookie_secret .. ":1.2.3.4:" .. ts)
    ngx.var.http_cookie = "waf.pass+=" .. ts .. ":" .. sign
    t.isnil(challenge.check({ client_ip = "1.2.3.4" }, cfg))
end)

t.test("record: issue 事件异步上报且含规则名", function()
    ngx_reset()
    ngx.var.request_uri = "/"
    local ctx = {
        client_ip = "1.2.3.4",
        req_id = "r1",
        trigger_rule = "测试规则",
        request = { method = "GET", host = "x.com" },
        evidence = {},
    }
    challenge.record(ctx, "issue")
    t.eq(#ngx.timer._at, 1, "应调度 1 个异步上报定时器")
end)

-- ============ 工作量证明（basic 模式 POW） ============

-- 与 challenge.lua 一致的 FNV-1a 32 位哈希（测试内复算找合法 nonce）
local bit = require "bit"
local function fnv1a(s)
    local h = 2166136261
    for i = 1, #s do
        h = bit.bxor(h, string.byte(s, i))
        h = (h * 16777619) % 4294967296
    end
    return h
end

local function find_nonce(challenge, bits)
    local nonce = 0
    while nonce < 100000000 do
        if fnv1a(challenge .. ":" .. tostring(nonce)) < 2 ^ (32 - bits) then
            return nonce
        end
        nonce = nonce + 1
    end
    return nil
end

t.test("verify_pow: 合法 nonce 通过，非法 nonce 拒绝", function()
    local cfg = { pow_bits = 8 }
    local tok = "tok123"
    local nonce = find_nonce(tok, 8)
    t.notnil(nonce, "应找到合法 nonce")
    t.ok(challenge.verify_pow(tok, nonce, cfg))
    -- 相邻 nonce 的判定与服务端复算结果一致（确定性）
    local expected = fnv1a(tok .. ":" .. (nonce + 1)) < 2 ^ 24
    t.eq(challenge.verify_pow(tok, nonce + 1, cfg), expected)
end)

t.test("verify_pow: pow_bits=0 关闭校验，非法 nonce 拒绝", function()
    t.ok(challenge.verify_pow("x", "0", { pow_bits = 0 }))
    t.no(challenge.verify_pow("x", "-1", { pow_bits = 0 }))
    t.no(challenge.verify_pow("x", "abc", { pow_bits = 0 }))
    t.no(challenge.verify_pow("x", "1000000001", { pow_bits = 0 }))
end)

t.test("verify_challenge_token: 签名/时效/IP 绑定", function()
    local cfg = base_cfg().challenge
    local ts = os.time()
    local sign = ngx.md5(cfg.cookie_secret .. ":1.2.3.4:" .. ts)
    t.ok(challenge.verify_challenge_token(ts .. ":" .. sign, "1.2.3.4", cfg))
    -- IP 不匹配
    t.no(challenge.verify_challenge_token(ts .. ":" .. sign, "9.9.9.9", cfg))
    -- 过期
    local old = os.time() - 301
    local old_sign = ngx.md5(cfg.cookie_secret .. ":1.2.3.4:" .. old)
    t.no(challenge.verify_challenge_token(old .. ":" .. old_sign, "1.2.3.4", cfg))
    -- 未来时间戳
    local fut = os.time() + 60
    local fut_sign = ngx.md5(cfg.cookie_secret .. ":1.2.3.4:" .. fut)
    t.no(challenge.verify_challenge_token(fut .. ":" .. fut_sign, "1.2.3.4", cfg))
    -- 格式非法
    t.no(challenge.verify_challenge_token("abc", "1.2.3.4", cfg))
end)

t.test("serve_verify basic: 无有效 POW 不下发 cookie", function()
    ngx_reset()
    local cfg = base_cfg()
    cfg.challenge.pow_bits = 8
    ngx.req._body = '{"challenge":"bad-token","nonce":0}'
    t.exits(function()
        challenge.serve_verify({ client_ip = "1.2.3.4" }, cfg)
    end, 200)
    t.isnil(ngx.header["Set-Cookie"], "未通过校验不得下发 cookie")
end)

t.test("serve_verify basic: 合法 token+POW 下发 cookie", function()
    ngx_reset()
    local cjson = require "cjson.safe"
    local cfg = base_cfg()
    cfg.challenge.pow_bits = 8
    local ch = cfg.challenge
    local ts = os.time()
    local sign = ngx.md5(ch.cookie_secret .. ":1.2.3.4:" .. ts)
    local token = ts .. ":" .. sign
    local nonce = find_nonce(token, 8)
    t.notnil(nonce)
    ngx.req._body = cjson.encode({ challenge = token, nonce = nonce })
    t.exits(function()
        challenge.serve_verify({ client_ip = "1.2.3.4" }, cfg)
    end, 200)
    t.notnil(ngx.header["Set-Cookie"], "通过后应下发 cookie")
    t.match(ngx.header["Set-Cookie"], "waf_pass=")
end)

