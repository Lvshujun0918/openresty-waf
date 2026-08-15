-- fingerprint.lua
-- HTTP 客户端指纹：由核心请求头组合的哈希。
-- 浏览器与爬虫工具的头部组合差异明显（Sec-CH-UA 系、Accept-Language 等），
-- 同一客户端（浏览器/工具）的指纹稳定，可用于：
--   - 恶意指纹库比对（access 阶段拦截）
--   - 爬虫识别（结合 UA / IP 判定真实爬虫与虚假爬虫）
--
-- 注意：指纹为概率性识别（非加密安全），仅作统计与辅助判定，不单独作为放行依据。

local _M = {}

-- 参与指纹的请求头（按固定顺序拼接，顺序变化会导致指纹不同，保持稳定）
local FP_HEADERS = {
    "http_user_agent",
    "http_accept",
    "http_accept_language",
    "http_accept_encoding",
    "http_sec_ch_ua",
    "http_sec_ch_ua_platform",
    "http_sec_ch_ua_mobile",
    "http_sec_fetch_mode",
    "http_sec_fetch_dest",
}

-- 请求级缓存：同一请求多次调用不重复拼接/哈希
-- 计算当前请求的指纹（32 位 hex，基于 ngx.var 头部组合）
function _M.get(ctx)
    if ctx and ctx.fingerprint then
        return ctx.fingerprint
    end
    local parts = {}
    for i, v in ipairs(FP_HEADERS) do
        parts[i] = ngx.var[v] or ""
    end
    local fp = ngx.md5(table.concat(parts, "|"))
    if ctx then
        ctx.fingerprint = fp
    end
    return fp
end

-- 当前请求的比对用指纹：
--   TLS 连接优先使用 JA4（ssl_client_hello 阶段计算，抗伪造）；
--   非 TLS 连接（或未挂载钩子）回退 HTTP 组合指纹。
-- 返回 fp, source（"ja4" | "http"）
function _M.effective(ctx)
    if ctx and ctx.ja4 and ctx.ja4 ~= "" then
        return ctx.ja4, "ja4"
    end
    return _M.get(ctx), "http"
end

-- 指纹是否命中恶意库（active_config.blacklist.fingerprints）
-- 条目：{ name, value, match("exact"|"regex") }
-- JA4 优先（TLS 连接）；无 JA4 时回退 HTTP 指纹比对。
-- 返回命中的条目名或 nil
function _M.match_malicious(ctx)
    local fp, source = _M.effective(ctx)
    local engine = require "rule_engine.engine"
    local cfg = engine.get_active_config()
    local bl = cfg and cfg.blacklist and cfg.blacklist.fingerprints
    if type(bl) ~= "table" or #bl == 0 then
        return nil, source
    end
    for _, item in ipairs(bl) do
        if type(item) ~= "table" then goto continue end
        local v = tostring(item.value or "")
        if v ~= "" then
            if item.match == "regex" then
                local ok, res = pcall(ngx.re.find, fp, v, "jo")
                if ok and res then
                    return tostring(item.name or v), source
                end
            elseif fp == v then
                return tostring(item.name or v), source
            end
        end
        ::continue::
    end
    return nil, source
end

return _M
