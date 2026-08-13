-- detectors/challenge.lua
-- 人机验证：
--   mode = "basic"    基础 JS Challenge（自包含，服务端签名 token，无第三方依赖）
--   mode = "geetest"  极验验证码 GT4
--   mode = "gitee"    Gitee 验证码（与极验 GT4 协议兼容）
--
-- 流程：CC 超限且请求未通过验证 → 302 到挑战页 → 前端验证 → 种签名 cookie →
--       后续请求校验 cookie 通过则解除封禁放行。
-- 高级模式回调校验第三方验证接口：优先 lua-resty-http（支持 HTTPS），
-- 缺失时回退手动 cosocket HTTP（仅 http:// 明文）。

local _M = {}

local cjson = require "cjson.safe"

-- URL 编码
local function urlencode(s)
    s = tostring(s or "")
    return (s:gsub("([^%w%.%-%_%~])", function(c)
        return string.format("%%%02X", string.byte(c))
    end))
end

-- 计算签名（服务端 secret，不暴露给前端）
local function calc_sign(ip, ts, secret)
    return ngx.md5(tostring(secret) .. ":" .. tostring(ip) .. ":" .. tostring(ts))
end

-- 校验验证 cookie 值 "ts:sign"
local function verify_pass(cookie_val, ip, cfg)
    local ts, sign = cookie_val:match("^(%d+):([0-9a-f]+)$")
    if not ts then return false end
    if os.time() - tonumber(ts) > cfg.cookie_ttl then return false end
    return sign == calc_sign(ip, ts, cfg.cookie_secret)
end

-- 检查请求是否已通过验证：通过返回 nil，需要挑战返回 "challenge"
function _M.check(waf_ctx, cfg)
    local ch = cfg.challenge
    if not ch or not ch.enabled then return nil end
    local cookie = ngx.var.http_cookie or ""
    local val = cookie:match(ch.cookie_name .. "=([^;]+)")
    if val and verify_pass(val, waf_ctx.client_ip, ch) then
        return nil
    end
    return "challenge"
end

-- 手动触发路径匹配：uri 命中 trigger_paths 任一前缀（或完全相等）返回 true
function _M.is_triggered(uri, paths)
    if not paths or #paths == 0 then return false end
    uri = uri or ""
    for _, p in ipairs(paths) do
        p = tostring(p)
        if p ~= "" and uri == p then
            return true
        end
        if p ~= "" and uri:sub(1, #p) == p then
            return true
        end
    end
    return false
end

-- 签发验证 cookie
local function set_pass_cookie(cfg, ip)
    local ts = os.time()
    local val = ts .. ":" .. calc_sign(ip, ts, cfg.cookie_secret)
    ngx.header["Set-Cookie"] = cfg.cookie_name .. "=" .. val ..
        "; Path=/; HttpOnly; Max-Age=" .. cfg.cookie_ttl
end

-- 基础 JS 挑战页：token 由服务端签名，前端 JS 执行后种 cookie 并刷新
local function basic_page(cfg, ip)
    local ts = os.time()
    local token = calc_sign(ip, ts, cfg.cookie_secret)
    local cookie = cfg.cookie_name .. "=" .. ts .. ":" .. token
    return [[<!DOCTYPE html>
<html lang="zh-CN"><head><meta charset="utf-8"><title>安全验证</title>
<style>body{font-family:sans-serif;text-align:center;padding:80px 20px;color:#333}
.box{max-width:380px;margin:0 auto;border:1px solid #eee;border-radius:12px;padding:40px}
.spinner{width:36px;height:36px;margin:0 auto 16px;border:3px solid #e2e8f0;border-top-color:#2563eb;border-radius:50%;animation:spin 1s linear infinite}
@keyframes spin{to{transform:rotate(360deg)}}</style>
</head><body><div class="box"><div class="spinner"></div>
<h2>正在验证您的浏览器…</h2><p>请稍候，正在执行安全检测。</p></div>
<script>
document.cookie = ']] .. cookie .. [[; Path=/; Max-Age=]] .. cfg.cookie_ttl .. [[';
setTimeout(function(){ location.reload(); }, 300);
</script></body></html>]]
end

-- 高级验证码（极验 GT4 / Gitee）挑战页：嵌入官方 SDK
local function advanced_page(cfg)
    local sdk = cfg.captcha.sdk or "https://static.geetest.com/v4/gt4.js"
    return [[<!DOCTYPE html>
<html lang="zh-CN"><head><meta charset="utf-8"><title>安全验证</title>
<style>body{font-family:sans-serif;text-align:center;padding:60px 20px;color:#333}</style>
</head><body><h2>请完成安全验证</h2>
<div id="captcha"></div>
<script src="]] .. sdk .. [["></script>
<script>
initGeetest4({
    captchaId: ']] .. cfg.captcha.id .. [[',
    product: 'bind',
    language: 'zho'
}, function (captchaObj) {
    captchaObj.onReady(function () { captchaObj.showCaptcha(); });
    captchaObj.onSuccess(function () {
        var result = captchaObj.getValidate();
        fetch(']] .. cfg.verify_path .. [[', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(result)
        }).then(function (r) { return r.json(); }).then(function (d) {
            if (d.status === 'ok') { location.reload(); }
            else { alert('验证失败，请重试'); captchaObj.showCaptcha(); }
        });
    });
});
</script></body></html>]]
end

-- ============================================================================
-- HTTP 客户端（校验第三方验证接口）
-- ============================================================================

-- 手动 cosocket HTTP GET（仅 http:// 明文；HTTPS 需 lua-resty-http）
local function manual_http_get(url, timeout)
    local rest = url:gsub("^http://", "")
    local hostport, path = rest:match("^([^/]+)(.*)$")
    if not hostport then return nil, "非法 URL" end
    path = (path == "" and "/" or path)
    local host, port = hostport:match("^([^:]+):(%d+)$")
    if not host then host, port = hostport, 80 end

    local sock = ngx.socket.tcp()
    sock:settimeout(timeout or 3000)
    local ok, err = sock:connect(host, tonumber(port))
    if not ok then
        return nil, "连接失败: " .. tostring(err)
    end
    sock:send("GET " .. path .. " HTTP/1.1\r\nHost: " .. host ..
              "\r\nConnection: close\r\n\r\n")
    local resp, err2 = sock:receive("*a")
    sock:close()
    if not resp then return nil, tostring(err2) end
    local body = resp:match("\r\n\r\n(.*)$") or ""
    local status = resp:match("^HTTP/%d%.%d (%d+)")
    return body, nil, status
end

-- 发起 HTTP GET（优先 lua-resty-http 支持 HTTPS；否则手动 cosocket 仅明文）
local function http_get(url)
    local ok, http = pcall(require, "resty.http")
    if ok and http then
        local hc = http.new()
        local res, err = hc:request_uri(url, { method = "GET" })
        if not res then return nil, err end
        return res.body, nil, res.status
    end
    if url:match("^http://") then
        return manual_http_get(url)
    end
    return nil, "缺少 lua-resty-http，无法请求 HTTPS 验证接口（http:// 可手动调用）"
end

-- 校验第三方验证结果（极验 GT4 / Gitee 兼容）
local function verify_geetest(cfg, params)
    local lot = params.lot_number or params.lotNumber or ""
    local sign_token = ngx.md5(tostring(cfg.captcha.key or "") .. lot)
    local url = (cfg.captcha.verify_api or "https://gcaptcha4.geetest.com/validate")
        .. "?captcha_id=" .. urlencode(cfg.captcha.id)
        .. "&lot_number=" .. urlencode(lot)
        .. "&captcha_output=" .. urlencode(params.captcha_output or params.captchaOutput or "")
        .. "&pass_token=" .. urlencode(params.pass_token or params.passToken or "")
        .. "&gen_time=" .. urlencode(params.gen_time or params.genTime or "")
        .. "&sign_token=" .. sign_token

    local body, err = http_get(url)
    if not body then
        return false, err
    end
    local data = cjson.decode(body)
    if not data then
        return false, "验证接口响应解析失败"
    end
    return data.result == "success", nil
end

-- ============================================================================
-- 人机验证事件记录（下发/通过/失败），异步推送到 Redis 供后台展示
-- ============================================================================

-- 本地时区偏移（如 +08:00）
local function tz_offset()
    local now = os.time()
    local utc = os.time(os.date("!*t", now))
    local diff = os.difftime(now, utc)
    local sign = diff < 0 and "-" or "+"
    local a = math.abs(diff)
    return string.format("%s%02d:%02d", sign, math.floor(a / 3600), math.floor((a % 3600) / 60))
end

-- 记录一次人机验证事件
-- action: "issue"（下发挑战页）| "pass"（验证通过）| "fail"（验证失败）
local function record(waf_ctx, action)
    local client_ip = waf_ctx and waf_ctx.client_ip or ngx.var.remote_addr or ""
    local ok, geo = pcall(function()
        return require("ip_region").lookup(client_ip)
    end)
    local rec = {
        time       = os.date("%Y-%m-%dT%H:%M:%S") .. tz_offset(),
        req_id     = waf_ctx and waf_ctx.req_id or "",
        client_ip  = client_ip,
        action     = action,
        uri        = ngx.var.request_uri or "",
        country    = ok and geo and geo.country or "",
        province   = ok and geo and geo.province or "",
        city       = ok and geo and geo.city or "",
    }
    local ok2, err = ngx.timer.at(0, function(premature)
        if premature then return end
        local storage = require "storage"
        storage.redis_lpush("waf:challenge:list", cjson.encode(rec))
    end)
    if not ok2 then
        ngx.log(ngx.ERR, "[waf] 调度人机验证事件上报失败: ", tostring(err))
    end
end

-- ============================================================================
-- 入口
-- ============================================================================

-- 渲染挑战页
function _M.serve_page(waf_ctx, cfg)
    local ch = cfg.challenge
    record(waf_ctx, "issue")
    ngx.header.content_type = "text/html; charset=utf-8"
    if ch.mode == "basic" then
        ngx.say(basic_page(ch, waf_ctx.client_ip))
    else
        ngx.say(advanced_page(ch))
    end
    ngx.exit(ngx.HTTP_OK)
end

-- 处理验证回调（高级模式）：校验第三方结果，成功则种 cookie
function _M.serve_verify(waf_ctx, cfg)
    local ch = cfg.challenge
    ngx.req.read_body()
    local body = ngx.req.get_body_data() or "{}"
    local params = cjson.decode(body) or {}

    local ok, err = verify_geetest(ch, params)
    if ok then
        set_pass_cookie(ch, waf_ctx.client_ip)
        record(waf_ctx, "pass")
        ngx.say(cjson.encode({ status = "ok" }))
    else
        record(waf_ctx, "fail")
        ngx.say(cjson.encode({ status = "fail", error = err or "验证失败" }))
    end
    ngx.exit(ngx.HTTP_OK)
end

return _M
