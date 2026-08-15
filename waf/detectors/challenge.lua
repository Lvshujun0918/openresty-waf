-- detectors/challenge.lua
-- 人机验证：
--   mode = "basic"    基础 JS Challenge（自包含，无第三方依赖）：服务端签发挑战 token，
--                      前端 JS 计算工作量证明（FNV-1a 前导零）后回调验证，
--                      服务端校验通过才下发放行 cookie——无 JS 能力的 bot 无法通过
--   mode = "geetest"  极验验证码 GT4
--   mode = "gitee"    Gitee 验证码（与极验 GT4 协议兼容）
--
-- 流程：CC 超限且请求未通过验证 → 302 到挑战页 → 前端验证 → 种签名 cookie →
--       后续请求校验 cookie 通过则解除封禁放行。
-- 高级模式回调校验第三方验证接口：优先 lua-resty-http（支持 HTTPS），
-- 缺失时回退手动 cosocket HTTP（仅 http:// 明文）。

local _M = {}

local cjson = require "cjson.safe"
local bit = require "bit"
local config  = require "config"
local storage = require "storage"

-- ============================================================================
-- 工作量证明（basic 模式）：JS 与 Lua 两侧同一 FNV-1a 32 位哈希。
-- 挑战页 JS 循环找 nonce 使 hash(challenge:nonce) 前 pow_bits 位为 0，
-- 服务端仅需复算一次即可验证——无 JS 执行能力的 bot 无法通过。
-- ============================================================================
local function fnv1a(s)
    local h = 2166136261
    for i = 1, #s do
        h = bit.bxor(h, string.byte(s, i))
        h = (h * 16777619) % 4294967296
    end
    return h
end

-- 校验工作量证明：nonce 合法且 hash 前 pow_bits 位全 0（pow_bits<=0 视为关闭）
function _M.verify_pow(challenge, nonce, cfg)
    nonce = tonumber(nonce)
    if not nonce or nonce < 0 or nonce > 1000000000 then
        return false
    end
    local bits = tonumber(cfg.pow_bits) or 20
    if bits <= 0 then
        return true
    end
    if bits > 28 then
        bits = 28
    end
    return fnv1a(tostring(challenge) .. ":" .. tostring(nonce)) < 2 ^ (32 - bits)
end

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

-- 校验挑战 token "ts:sign"（签发 5 分钟内有效，绑定客户端 IP）
function _M.verify_challenge_token(token, ip, cfg)
    local ts, sign = tostring(token or ""):match("^(%d+):([0-9a-f]+)$")
    if not ts then return false end
    local now = os.time()
    if tonumber(ts) > now then return false end
    if now - tonumber(ts) > 300 then return false end
    return sign == calc_sign(ip, ts, cfg.cookie_secret)
end

-- 签发挑战 token（不暴露 secret，绑定 IP 与时间）
local function issue_token(cfg, ip)
    local ts = os.time()
    return ts .. ":" .. calc_sign(ip, ts, cfg.cookie_secret)
end

-- 校验验证 cookie 值 "ts:sign"
local function verify_pass(cookie_val, ip, cfg)
    local ts, sign = cookie_val:match("^(%d+):([0-9a-f]+)$")
    if not ts then return false end
    local now = os.time()
    if tonumber(ts) > now then return false end  -- 拒绝未来时间戳（伪造/回拨风险）
    if now - tonumber(ts) > cfg.cookie_ttl then return false end
    return sign == calc_sign(ip, ts, cfg.cookie_secret)
end

-- 检查请求是否已通过验证：通过返回 nil，需要挑战返回 "challenge"
-- force=true 时忽略全局 enabled 开关（触发规则命中的场景：规则级配置即可生效）
function _M.check(waf_ctx, cfg, force)
    local ch = cfg.challenge
    if not ch then return nil end
    if not force and not ch.enabled then return nil end
    local cookie = ngx.var.http_cookie or ""
    -- 纯文本查找 cookie 名（cookie_name 可含 Lua 模式特殊字符，不能直接拼 match pattern）
    local pos = cookie:find(ch.cookie_name .. "=", 1, true)
    if not pos then return "challenge" end
    local val = cookie:sub(pos + #ch.cookie_name + 1):match("^([^;]*)")
    if val and verify_pass(val, waf_ctx.client_ip, ch) then
        return nil
    end
    return "challenge"
end

-- 签发验证 cookie
local function set_pass_cookie(cfg, ip)
    local ts = os.time()
    local val = ts .. ":" .. calc_sign(ip, ts, cfg.cookie_secret)
    ngx.header["Set-Cookie"] = cfg.cookie_name .. "=" .. val ..
        "; Path=/; HttpOnly; Max-Age=" .. cfg.cookie_ttl
end

-- 嵌入 JS 字符串前的安全化：剔除单引号/尖括号/&/控制字符，
-- 防止 redirect 参数以 </script> 闭合标签注入任意 JS（XSS）
local function js_safe(s)
    return (s or ""):gsub("'", "\\'"):gsub("<", ""):gsub(">", "")
        :gsub("&", ""):gsub("[%c]", "")
end

-- 基础 JS 挑战页：前端 JS 计算工作量证明，通过后 POST 验证路径，
-- 服务端校验成功才下发放行 cookie——无 JS 能力的 bot 跟随重定向也拿不到 cookie
local function basic_page(ch, ip, redirect, token, bits)
    local verify = ch.verify_path or "/__waf_challenge_verify__"
    local js = "location.reload();"
    if redirect and redirect ~= "" then
        js = "location.href='" .. js_safe(redirect) .. "';"
    end
    return [[<!DOCTYPE html>
<html lang="zh-CN"><head><meta charset="utf-8"><title>安全验证</title>
<style>body{font-family:sans-serif;text-align:center;padding:80px 20px;color:#333}
.box{max-width:380px;margin:0 auto;border:1px solid #eee;border-radius:12px;padding:40px}
.spinner{width:36px;height:36px;margin:0 auto 16px;border:3px solid #e2e8f0;border-top-color:#2563eb;border-radius:50%;animation:spin 1s linear infinite}
@keyframes spin{to{transform:rotate(360deg)}}</style>
</head><body><div class="box"><div class="spinner"></div>
<h2>正在验证您的浏览器…</h2><p>请稍候，正在执行浏览器环境检测。</p></div>
<script>
var challenge = ']] .. token .. [[', bits = ]] .. tostring(bits) .. [[;
function fnv1a(s){var h=2166136261;for(var i=0;i<s.length;i++){h^=s.charCodeAt(i);h=(h*16777619)>>>0;}return h>>>0;}
function checkNonce(n){return (fnv1a(challenge+':'+n) >>> (32-bits)) === 0;}
var nonce = 0;
while (!checkNonce(nonce)) { nonce++; }
fetch(']] .. verify .. [[', {method:'POST', headers:{'Content-Type':'application/json'},
  body: JSON.stringify({challenge: challenge, nonce: nonce})})
  .then(function(r){ return r.json(); })
  .then(function(d){
    if (d.status === 'ok') { ]] .. js .. [[ }
    else { location.reload(); }
  })
  .catch(function(){ location.reload(); });
</script></body></html>]]
end

-- 高级验证码（极验 GT4 / Gitee）挑战页：嵌入官方 SDK，验证成功后跳回原请求
local function advanced_page(cfg, redirect)
    local sdk = cfg.captcha.sdk or "https://static.geetest.com/v4/gt4.js"
    local js = "location.reload();"
    if redirect and redirect ~= "" then
        js = "location.href='" .. js_safe(redirect) .. "';"
    end
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
            if (d.status === 'ok') { ]] .. js .. [[ }
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

-- 记录一次人机验证事件（含详细参数，供后台「触发记录」详情展示）
-- action: "issue"（下发挑战页）| "pass"（验证通过）| "fail"（验证失败）
function _M.record(waf_ctx, action)
    local client_ip = waf_ctx and waf_ctx.client_ip or ngx.var.remote_addr or ""
    local ok, geo = pcall(function()
        return require("ip_region").lookup(client_ip)
    end)
    local evidence = (waf_ctx and waf_ctx.evidence) or {}
    local config = require "config"
    local rec = {
        time       = os.date("%Y-%m-%dT%H:%M:%S") .. tz_offset(),
        req_id     = waf_ctx and waf_ctx.req_id or "",
        client_ip  = client_ip,
        engine_version = config.version or "",
        action     = action,
        method     = waf_ctx and waf_ctx.request and waf_ctx.request.method or "",
        host       = waf_ctx and waf_ctx.request and waf_ctx.request.host or "",
        uri        = ngx.var.request_uri or "",
        rule_name  = waf_ctx and waf_ctx.trigger_rule or "",
        headers    = cjson.encode(evidence.headers or {}),
        body       = evidence.body or "",
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

-- 本地别名：模块内部（serve_page / serve_verify）沿用旧调用名
local record = _M.record

-- ============================================================================
-- 入口
-- ============================================================================

-- 渲染挑战页
function _M.serve_page(waf_ctx, cfg)
    -- 挑战页请求均为终态响应（渲染/拒绝），标记 _exited 避免外层 fail-open 误报
    waf_ctx._exited = true
    local ch = cfg.challenge
    -- 携带原始请求 URI（access.lua 重定向时 ?redirect=...），验证通过后跳回。
    -- 注意：nginx $arg_redirect 不解码 %2F，需用 ngx.unescape_uri 还原，
    -- 否则根路径 "/" 会被编码成 %2F 并作为字面路径跳转（跳到 /%2F）。
    local redirect = ngx.var.arg_redirect or ""
    if redirect ~= "" then
        redirect = ngx.unescape_uri(redirect)
    end
    -- 触发规则名（access.lua 重定向时携带，用于「触发记录」展示）
    local rule_name = ngx.var.arg_rule or ""
    if rule_name ~= "" then
        rule_name = ngx.unescape_uri(rule_name)
        waf_ctx.trigger_rule = rule_name
    end
    -- 捕获当前请求头作为证据（供「触发记录」详情展示）
    local all_hdrs = ngx.req.get_headers()
    local hdrs = {}
    if all_hdrs then
        for k, v in pairs(all_hdrs) do
            hdrs[#hdrs + 1] = { name = tostring(k), value = tostring(v) }
        end
    end
    table.sort(hdrs, function(a, b) return a.name < b.name end)
    waf_ctx.evidence = { headers = hdrs }

    -- 同 IP 签发挑战页限频：防攻击者反复刷新挑战页消耗日志/验证通道
    -- （POW 计算在客户端，服务端成本低，此处主要保护 issue 事件通道与日志容量）
    local issue_limit = tonumber(ch.issue_limit) or 20
    local issue_window = tonumber(ch.issue_window) or 60
    if issue_limit > 0 then
        local ikey = "waf:ch:issue:" .. waf_ctx.client_ip
        local n = storage.incr_shared(config.dict.counter, ikey, 1, 0, issue_window)
        if n and n > issue_limit then
            ngx.log(ngx.WARN, "[waf] 挑战页签发超限，拒绝渲染: ", waf_ctx.client_ip)
            ngx.exit(444)
            return
        end
    end

    record(waf_ctx, "issue")
    ngx.header.content_type = "text/html; charset=utf-8"
    if ch.mode == "basic" then
        -- 签发挑战 token：前端 JS 完成工作量证明后回调验证路径，
        -- 服务端校验通过才下发放行 cookie（不再无条件 Set-Cookie 放行）
        local token = issue_token(ch, waf_ctx.client_ip)
        local bits = tonumber(ch.pow_bits) or 20
        ngx.say(basic_page(ch, waf_ctx.client_ip, redirect, token, bits))
    else
        ngx.say(advanced_page(ch, redirect))
    end
    ngx.exit(ngx.HTTP_OK)
end

-- 处理验证回调：
--   basic 模式：校验挑战 token 与工作量证明，通过才种 cookie；
--   高级模式：校验第三方验证接口结果，成功则种 cookie
function _M.serve_verify(waf_ctx, cfg)
    -- 验证回调均为终态响应，标记 _exited 避免外层 fail-open 误报
    waf_ctx._exited = true
    local ch = cfg.challenge
    ngx.req.read_body()
    local body = ngx.req.get_body_data() or "{}"
    local params = cjson.decode(body) or {}

    if ch.mode == "basic" then
        local token = params.challenge or ""
        if not _M.verify_challenge_token(token, waf_ctx.client_ip, ch) then
            record(waf_ctx, "fail")
            ngx.say(cjson.encode({ status = "fail", error = "挑战已过期，请刷新重试" }))
            ngx.exit(ngx.HTTP_OK)
            return
        end
        if not _M.verify_pow(token, params.nonce, ch) then
            record(waf_ctx, "fail")
            ngx.say(cjson.encode({ status = "fail", error = "浏览器环境检测未通过" }))
            ngx.exit(ngx.HTTP_OK)
            return
        end
        set_pass_cookie(ch, waf_ctx.client_ip)
        record(waf_ctx, "pass")
        ngx.say(cjson.encode({ status = "ok" }))
        ngx.exit(ngx.HTTP_OK)
        return
    end

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
