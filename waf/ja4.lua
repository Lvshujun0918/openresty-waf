-- ja4.lua
-- JA4 TLS 指纹（FoxIO JA4 规范，与官方 python/ja4.py 算法对齐）。
--
-- 官方格式（ja4_a）：
--   t{version}{sni}{cipher_len:02d}{ext_len:02d}{alpn}_{sha256(ciphers)12}_{sha256(exts)12}
--   version: TLS1.3→13 / 1.2→12 / 1.1→11 / 1.0→10（取 supported_versions 最高值）
--   sni: d（有 SNI）/ i（无）
--   cipher_len: 去 GREASE 后 cipher 数（2 位十进制，上限 99）
--   ext_len: 去 GREASE 后扩展数（含 SNI/ALPN，2 位十进制，上限 99）
--   alpn: 第一个 ALPN 协议（>2 字符取首尾字符，如 http/1.1→h1；无→00）
--   哈希段：ciphers 排序后逗号连接 → SHA256 前 12 hex；
--           extensions 去掉 SNI(0)/ALPN(16) 后排序逗号连接，
--           扩展含签名算法(0x000d)时附加 "_" + 签名算法逗号连接 → SHA256 前 12
--           空列表 → "000000000000"
--
-- 挂载：ssl_client_hello_by_lua（官方 OpenResty 1.31.1.1 纯 Lua 方案）。
-- 双通道传递：ngx.ctx（官方镜像阶段间共享）优先 + shared dict（旧环境兜底）。
-- 注意：JA4 仅 TLS 连接可用，非 TLS 场景由 fingerprint.lua 回退 TLS 变量指纹/HTTP 指纹。

local _M = {}

-- 版本字符串 → JA4 版本号（lua-resty-core get_supported_versions 返回 "TLSv1.3" 等）
local VER_MAP = {
    ["TLSv1.3"] = "13",
    ["TLSv1.2"] = "12",
    ["TLSv1.1"] = "11",
    ["TLSv1"]   = "10",
}

-- GREASE 值表（lua-resty-core 的 ciphers/ext_present 已排除，双保险）
local GREASE = {
    [0x0a0a]=true, [0x1a1a]=true, [0x2a2a]=true, [0x3a3a]=true,
    [0x4a4a]=true, [0x5a5a]=true, [0x6a6a]=true, [0x7a7a]=true,
    [0x8a8a]=true, [0x9a9a]=true, [0xaaaa]=true, [0xbaba]=true,
    [0xcaca]=true, [0xdada]=true, [0xeaea]=true, [0xfafa]=true,
}

-- 摘要实现：优先 ngx.sha256_bin（部分 OpenResty 未提供），
-- 回退 lua-resty-string 的纯 Lua resty.sha256
local sha256_hex12
do
    local has_builtin = type(ngx.sha256_bin) == "function"
    local resty_ok, resty_sha256 = pcall(require, "resty.sha256")
    sha256_hex12 = function(s)
        if not s or s == "" then return "000000000000" end
        local bin
        if has_builtin then
            bin = ngx.sha256_bin(s)
        elseif resty_ok then
            local h = resty_sha256:new()
            h:update(s)
            bin = h:final()
        end
        if not bin then return "000000000000" end
        return (bin:gsub(".", function(ch)
            return string.format("%02x", ch:byte())
        end)):sub(1, 12)
    end
end

-- 数字列表 → 4 位 hex 逗号连接
local function hex_join(list)
    local parts = {}
    for i, v in ipairs(list) do
        parts[i] = string.format("%04x", tonumber(v) or 0)
    end
    return table.concat(parts, ",")
end

-- 解析 ALPN 扩展（16）数据：[list_len 2][proto_len 1][proto]...，返回第一个协议名
local function parse_alpn(data)
    if not data or #data < 2 then return nil end
    local list_len = data:byte(1) * 256 + data:byte(2)
    local i = 3
    while i <= #data and (i - 3) < list_len do
        local plen = data:byte(i)
        i = i + 1
        if plen == 0 or i + plen - 1 > #data then break end
        return data:sub(i, i + plen - 1)
    end
    return nil
end

-- 解析签名算法扩展（13）数据：[len 2][alg 2*n]，返回数字列表（原始顺序）
local function parse_sigalgs(data)
    local out = {}
    if not data or #data < 2 then return out end
    local n = data:byte(1) * 256 + data:byte(2)
    local i = 3
    while i + 1 <= #data and (i - 3) < n do
        local alg = data:byte(i) * 256 + data:byte(i + 1)
        if not GREASE[alg] then
            out[#out + 1] = alg
        end
        i = i + 2
    end
    return out
end

-- ClientHello 解析结果 → JA4（纯函数，可单测）。
-- hello: { version="TLSv1.3", sn=bool, alpn="h2", cipher_suites={num}, extensions={num}, sig_algs={num} }
function _M.calc(hello)
    if type(hello) ~= "table" then return nil end

    local t = VER_MAP[hello.version] or "00"
    local sni = (hello.sn and hello.sn ~= "") and "d" or "i"

    -- ciphers：去 GREASE（双保险）→ 排序 → 逗号连接 → SHA256 前 12
    local ciphers = {}
    for _, c in ipairs(hello.cipher_suites or {}) do
        if not GREASE[tonumber(c) or 0] then
            ciphers[#ciphers + 1] = tonumber(c) or 0
        end
    end
    table.sort(ciphers)
    local c_hash = #ciphers > 0 and sha256_hex12(hex_join(ciphers)) or "000000000000"

    -- extensions：去 GREASE → 去掉 SNI(0)/ALPN(16) → 排序
    local exts = {}
    local exts_all = {}
    for _, e in ipairs(hello.extensions or {}) do
        local ev = tonumber(e) or 0
        if not GREASE[ev] then
            exts_all[#exts_all + 1] = ev
            if ev ~= 0 and ev ~= 16 then
                exts[#exts + 1] = ev
            end
        end
    end
    table.sort(exts)

    -- 签名算法：扩展含 0x000d 时附加（原始顺序，去 GREASE）
    local has_sigalg = false
    for _, e in ipairs(exts_all) do
        if e == 13 then has_sigalg = true break end
    end
    local ext_input = hex_join(exts)
    if has_sigalg and hello.sig_algs and #hello.sig_algs > 0 then
        ext_input = ext_input .. "_" .. hex_join(hello.sig_algs)
    end
    local e_hash = #exts > 0 and sha256_hex12(ext_input) or "000000000000"

    -- 长度（2 位十进制，上限 99；ext_len 含 SNI/ALPN）
    local cipher_len = string.format("%02d", math.min(#ciphers, 99))
    local ext_len = string.format("%02d", math.min(#exts_all, 99))

    -- ALPN：>2 字符取首尾（http/1.1→h1，h2→h2），无 → 00
    local alpn = "00"
    local a = hello.alpn or ""
    if a ~= "" then
        alpn = #a > 2 and (a:sub(1, 1) .. a:sub(-1)) or a
    end

    return string.format("t%s%s%s%s%s_%s_%s", t, sni, cipher_len, ext_len, alpn, c_hash, e_hash)
end

-- 用 lua-resty-core 底层 API 组装 ClientHello 解析结果（全部 pcall 保护）
local function build_hello(ch)
    local hello = {}
    local ok, sn = pcall(ch.get_client_hello_server_name)
    if ok and sn and sn ~= "" then hello.sn = sn end

    local ok2, vers = pcall(ch.get_supported_versions)
    if ok2 and type(vers) == "table" and #vers > 0 then
        -- lua-resty-core 返回低→高（TLSv1 在前），取末项为最高版本
        hello.version = vers[#vers]
    end

    local ok3, alpn_data = pcall(ch.get_client_hello_ext, 16)
    if ok3 and alpn_data and alpn_data ~= "" then
        hello.alpn = parse_alpn(alpn_data)
    end

    local ok4, sig_data = pcall(ch.get_client_hello_ext, 13)
    if ok4 and sig_data and sig_data ~= "" then
        hello.sig_algs = parse_sigalgs(sig_data)
    end

    local ok5, ciphers = pcall(ch.get_client_hello_ciphers)
    if ok5 and type(ciphers) == "table" and #ciphers > 0 then
        hello.cipher_suites = ciphers
    end

    local ok6, exts = pcall(ch.get_client_hello_ext_present)
    if ok6 and type(exts) == "table" and #exts > 0 then
        hello.extensions = exts
    end

    return hello
end

-- ssl_client_hello 阶段入口：解析 ClientHello，计算 JA4。
-- fail-open：任何错误都不影响 TLS 握手（仅记录并放行）。
-- 双通道传递：ngx.ctx（官方镜像阶段间共享，首选）+
--             shared dict（旧环境兜底，按 worker pid 分键）。
function _M.run()
    local ok, clienthello = pcall(require, "ngx.ssl.clienthello")
    if not ok or not clienthello or type(clienthello) ~= "table" then
        return
    end
    local okb, hello = pcall(build_hello, clienthello)
    if not okb or not hello then
        return
    end
    local ok2, ja4 = pcall(_M.calc, hello)
    if not ok2 or not ja4 then
        ngx.log(ngx.ERR, "[waf] JA4 计算失败: ", tostring(ja4))
        return
    end
    local ok3 = pcall(function()
        ngx.ctx.ja4 = ja4
    end)
    local ok4 = pcall(function()
        local d = ngx.shared["waf_rule"]
        if d then
            d:set("ja4:conn:w" .. tostring(ngx.worker.pid()), ja4, 30)
        end
    end)
    if not ok3 and not ok4 then
        ngx.log(ngx.ERR, "[waf] JA4 写入 ctx 与共享内存均失败")
    end
end

-- 脚本入口（按当前阶段分发；测试环境无 get_phase 时仅加载模块）
if ngx.get_phase and ngx.get_phase() == "ssl_client_hello" then
    _M.run()
end

return _M
