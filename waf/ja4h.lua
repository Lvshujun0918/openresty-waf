-- ja4h.lua
-- JA4H HTTP 客户端指纹（FoxIO JA4H 规范，与官方 python/ja4h.py 对齐）。
--
-- 官方格式：
--   {method:2}{version}{cookie:c/n}{referer:r/n}{header_len:02}{lang:4}_{sha256(headers)12}_{sha256(cookie_names)12}_{sha256(cookie_values)12}
--   method: 前 2 字符小写（GET→ge、POST→po、OPTIONS→op）
--   version: HTTP/2→20、1.1→11、1.0→10
--   header_len: 排除伪头/Cookie/Referer 后的头部数（2 位十进制，上限 99）
--   lang: Accept-Language 去 - 与 ; 参数，取首个逗号前 4 字符补 0
--   哈希：headers 名称逗号连接 → SHA256 前 12（nginx 表无序，排序保证稳定）；
--         Cookie 名称（排序）与值（排序）分别哈希；无 Cookie → 12 个 0
--
-- 说明：官方按报文原始头顺序，nginx 的 get_headers 无序，故排序保证同一客户端
-- 指纹稳定（识别价值保留，与官方指纹库不可直接比对）。
-- 挂载：access 阶段计算（所有 HTTP 请求，非 TLS 亦可用）。

local _M = {}

-- 摘要实现（同 ja4.lua）：优先 ngx.sha256_bin，回退 resty.sha256
local sha256_hex12
do
    local has_builtin = type(ngx.sha256_bin) == "function"
    local resty_ok, resty_sha256 = pcall(require, "resty.sha256")
    sha256_hex12 = function(s)
        if not s or s == "" then return "0" end
        local bin
        if has_builtin then
            bin = ngx.sha256_bin(s)
        elseif resty_ok then
            local h = resty_sha256:new()
            h:update(s)
            bin = h:final()
        end
        if not bin then return "0" end
        return (bin:gsub(".", function(ch)
            return string.format("%02x", ch:byte())
        end)):sub(1, 12)
    end
end

-- Accept-Language → 4 字符（去 - ;，首个逗号前）
local function http_language(lang)
    if not lang or lang == "" then return "0000" end
    local l = lang:gsub("-", ""):gsub(";", ","):lower()
    l = l:match("^([^,]+)") or l
    l = l:sub(1, 4)
    return l .. string.rep("0", 4 - #l)
end

-- 解析 Cookie 头为 {name, value} 对
local function parse_cookies(cookie)
    local pairs = {}
    if not cookie or cookie == "" then return pairs end
    for part in cookie:gmatch("[^;]+") do
        local name, value = part:match("^%s*([^=]+)%s*=%s*(.-)%s*$")
        if name then
            pairs[#pairs + 1] = { name = name, value = value or "" }
        end
    end
    return pairs
end

-- 计算当前请求的 JA4H（纯函数输入来自 ngx，可测）
function _M.calc()
    local method = (ngx.req.get_method() or "GET"):lower():sub(1, 2)
    local ver = ngx.req.http_version() or 1.1
    local version = "11"
    if ver >= 2.0 then
        version = "20"
    elseif ver < 1.1 then
        version = "10"
    end

    local cookie = ngx.var.http_cookie or ""
    local referer = ngx.var.http_referer or ""
    local c = (cookie ~= "") and "c" or "n"
    local r = (referer ~= "") and "r" or "n"

    -- 头部名称：排除 cookie/referer/伪头，排序保证稳定
    local headers = {}
    local all = ngx.req.get_headers()
    if all then
        for k in pairs(all) do
            local lk = k:lower()
            if lk ~= "cookie" and lk ~= "referer" and not lk:match("^:") then
                headers[#headers + 1] = lk
            end
        end
    end
    table.sort(headers)
    local header_len = string.format("%02d", math.min(#headers, 99))

    local lang = http_language(ngx.var.http_accept_language or "")

    local h_hash = #headers > 0 and sha256_hex12(table.concat(headers, ",")) or "000000000000"

    -- Cookie 名/值哈希
    local ck_hash = "000000000000"
    local cv_hash = "000000000000"
    if cookie ~= "" then
        local pairs = parse_cookies(cookie)
        local names, values = {}, {}
        for i, p in ipairs(pairs) do
            names[i] = p.name
            values[i] = p.value
        end
        table.sort(names)
        table.sort(values)
        ck_hash = #names > 0 and sha256_hex12(table.concat(names, ",")) or "000000000000"
        cv_hash = #values > 0 and sha256_hex12(table.concat(values, ",")) or "000000000000"
    end

    return string.format("%s%s%s%s%s%s_%s_%s_%s", method, version, c, r, header_len, lang,
        h_hash, ck_hash, cv_hash)
end

-- access 阶段入口（fail-open：任何错误不影响请求）
function _M.run(ctx)
    local ok, ja4h = pcall(_M.calc)
    if ok and ja4h and ctx then
        ctx.ja4h = ja4h
    end
end

return _M
