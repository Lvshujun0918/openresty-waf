-- ja4.lua
-- JA4 TLS 指纹（FoxIO JA4 规范，ja4_a 部分）：
--   格式 t{version}{d}{c}{e}_{sha256(ciphers前16)前12hex}_{sha256(exts前16)前12hex}
--   version: TLS 1.3→13 / 1.2→12 / 1.1→11 / 1.0→10（无 supported_versions 扩展时按 1.2 处理）
--   d: SNI(+1)/ALPN(+2) 组合（0-3）；c/e: cipher/extension 数量（十六进制，>15 记 f）
-- 挂载阶段：ssl_client_hello_by_lua（每 TLS 连接一次，握手时执行）。
-- 计算结果存入 ngx.ctx.ja4，access 阶段供恶意指纹比对与爬虫记录使用。
--
-- 兼容性：使用 lua-resty-core ngx.ssl.clienthello 的底层 API
--   （get_client_hello_server_name / get_supported_versions / get_client_hello_ext /
--    get_client_hello_ciphers / get_client_hello_ext_present），
--   不依赖较新版本才有的 get_client_hello()。
-- 注意：JA4 仅 TLS 连接可用（HTTP 明文连接无 ClientHello），
-- 非 TLS 场景回退使用 HTTP 组合指纹（fingerprint.lua）。

local _M = {}

-- 版本字符串 → JA4 版本号（lua-resty-core 返回 "TLSv1.3" 等）
local VER_MAP = {
    ["TLSv1.3"] = "13",
    ["TLSv1.2"] = "12",
    ["TLSv1.1"] = "11",
    ["TLSv1"]   = "10",
}

-- ALPN 扩展类型（RFC 7301）
local ALPN_EXT = 16

local function hex1(n)
    n = tonumber(n) or 0
    if n >= 16 then return "f" end
    return string.format("%x", n)
end

-- 摘要实现：优先 ngx.sha256_bin（部分 OpenResty 二进制未提供），
-- 回退 lua-resty-string 的纯 Lua resty.sha256
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

-- ClientHello 解析结果 → JA4（纯函数，可单测）。
-- hello: { version="TLSv1.3", cipher_suites={0x1301,...}, extensions={{type=0x0,...},...}, sn="..", alpn=bool }
function _M.calc(hello)
    if type(hello) ~= "table" then return nil end
    local t = VER_MAP[hello.version] or "12"
    local d = 0
    if hello.sn and hello.sn ~= "" then d = d + 1 end
    if hello.alpn then d = d + 2 end
    local ciphers = hello.cipher_suites or {}
    local exts = hello.extensions or {}

    -- 第二段：前 16 个 cipher 的 2 字节 ID 拼接后 SHA256 前 12 hex
    local cbuf = {}
    local n = math.min(#ciphers, 16)
    for i = 1, n do
        cbuf[i] = string.format("%04x", tonumber(ciphers[i]) or 0)
    end
    -- 第三段：前 16 个 extension type 的 2 字节拼接后 SHA256 前 12 hex
    local ebuf = {}
    local m = math.min(#exts, 16)
    for i = 1, m do
        ebuf[i] = string.format("%04x", tonumber(exts[i].type) or 0)
    end

    return string.format("t%s%d%s%s_%s_%s",
        t, d, hex1(#ciphers), hex1(#exts),
        sha256_hex12(table.concat(cbuf)), sha256_hex12(table.concat(ebuf)))
end

-- 用底层 API 组装 ClientHello 解析结果（全部 pcall 保护，任一失败不影响其他字段）
local function build_hello(ch)
    local hello = {}
    local ok, sn = pcall(ch.get_client_hello_server_name)
    if ok and sn and sn ~= "" then hello.sn = sn end

    local ok2, vers = pcall(ch.get_supported_versions)
    if ok2 and type(vers) == "table" and #vers > 0 then
        hello.version = vers[1]  -- 返回列表首项为最高版本
    end

    local ok3, alpn = pcall(ch.get_client_hello_ext, ALPN_EXT)
    if ok3 and alpn and alpn ~= "" then hello.alpn = true end

    local ok4, ciphers = pcall(ch.get_client_hello_ciphers)
    if ok4 and type(ciphers) == "table" and #ciphers > 0 then
        hello.cipher_suites = ciphers
    end

    local ok5, exts = pcall(ch.get_client_hello_ext_present)
    if ok5 and type(exts) == "table" and #exts > 0 then
        local list = {}
        for i, t in ipairs(exts) do
            list[i] = { type = t }
        end
        hello.extensions = list
    end

    return hello
end

-- ssl_client_hello 阶段入口：解析 ClientHello，将 JA4 写入共享内存
-- （键 ja4:conn:<连接ID>，TTL 30s；access 阶段按连接 ID 读取）。
-- 说明：ssl_client_hello 为连接级阶段，与请求级 ngx.ctx 不共享，
-- HTTP/2 一个连接可复用多个请求（同一连接的 JA4 相同），故按连接传递。
-- fail-open：任何解析/计算/写入错误都不影响 TLS 握手（仅记录错误并放行）。
function _M.run()
    local ok, clienthello = pcall(require, "ngx.ssl.clienthello")
    if not ok then
        ngx.log(ngx.ERR, "[waf] JA4: ngx.ssl.clienthello 加载失败: ", tostring(clienthello))
        return
    end
    if not clienthello or type(clienthello) ~= "table" then
        ngx.log(ngx.ERR, "[waf] JA4: ngx.ssl.clienthello 不可用")
        return
    end
    local okb, hello = pcall(build_hello, clienthello)
    if not okb or not hello then
        ngx.log(ngx.ERR, "[waf] JA4: ClientHello 解析失败: ", tostring(hello))
        return
    end
    local ok2, ja4 = pcall(_M.calc, hello)
    if not ok2 or not ja4 then
        ngx.log(ngx.ERR, "[waf] JA4 计算失败: ", tostring(ja4))
        return
    end
    local ok3, err3 = pcall(function()
        local d = ngx.shared["waf_rule"]
        if d then
            -- ssl_client_hello 阶段无请求上下文，ngx.var.connection 不可用；
            -- ngx.connection() 返回当前连接对象（含 id，与请求阶段一致）
            local conn_id = "u"
            local c = ngx.connection()
            if c and c.id then
                conn_id = tostring(c.id)
            end
            d:set("ja4:conn:" .. conn_id, ja4, 30)
        end
    end)
    if not ok3 then
        ngx.log(ngx.ERR, "[waf] JA4 写入共享内存失败: ", tostring(err3))
    end
end

-- 脚本入口（按当前阶段分发；测试环境无 get_phase 时仅加载模块）
if ngx.get_phase and ngx.get_phase() == "ssl_client_hello" then
    _M.run()
end

return _M
