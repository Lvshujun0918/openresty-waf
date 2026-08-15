-- ja4.lua
-- JA4 TLS 指纹（FoxIO JA4 规范，ja4_a 部分）：
--   格式 t{version}{d}{c}{e}_{sha256(ciphers前16)前12hex}_{sha256(exts前16)前12hex}
--   version: TLS 1.3→13 / 1.2→12 / 1.1→11 / 1.0→10
--   d: SNI(+1)/ALPN(+2) 组合（0-3）；c/e: cipher/extension 数量（十六进制，>15 记 f）
-- 挂载阶段：ssl_client_hello_by_lua（每 TLS 连接一次，握手时执行）。
-- 计算结果存入 ngx.ctx.ja4，access 阶段供恶意指纹比对与爬虫记录使用。
--
-- 注意：JA4 仅 TLS 连接可用（HTTP 明文连接无 ClientHello），
-- 非 TLS 场景回退使用 HTTP 组合指纹（fingerprint.lua）。

local _M = {}

-- ClientHello 解析结果 → JA4（纯函数，可单测）。
-- hello 结构（lua-resty-core ngx.ssl.clienthello.get_client_hello 返回）：
--   { version="TLS 1.3", cipher_suites={0x1301,...}, extensions={{type=0x0,...},...}, sn="..", alpn=.. }
local VER_MAP = {
    ["TLS 1.3"] = "13",
    ["TLS 1.2"] = "12",
    ["TLS 1.1"] = "11",
    ["TLS 1.0"] = "10",
    ["SSL 3.0"] = "09",
}

local function hex1(n)
    n = tonumber(n) or 0
    if n >= 16 then return "f" end
    return string.format("%x", n)
end

local function sha256_hex12(s)
    if not s or s == "" then return "0" end
    local bin = ngx.sha256_bin(s)
    if not bin then return "0" end
    return (bin:gsub(".", function(ch)
        return string.format("%02x", ch:byte())
    end)):sub(1, 12)
end

function _M.calc(hello)
    if type(hello) ~= "table" then return nil end
    local t = VER_MAP[hello.version] or "00"
    local d = 0
    if hello.sn and hello.sn ~= "" then d = d + 1 end
    if hello.alpn and (type(hello.alpn) == "string" and hello.alpn ~= "" or type(hello.alpn) == "table" and #hello.alpn > 0) then
        d = d + 2
    end
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

-- ssl_client_hello 阶段入口：解析 ClientHello 并缓存 JA4 到 ngx.ctx
function _M.run()
    local ok, clienthello = pcall(require, "ngx.ssl.clienthello")
    if not ok or not clienthello then
        return  -- 环境不支持（应不会发生：OpenResty 1.19.3+ 内置）
    end
    local hello, err = clienthello.get_client_hello()
    if not hello then
        return
    end
    local ja4 = _M.calc(hello)
    if ja4 then
        ngx.ctx.ja4 = ja4
    end
end

-- 脚本入口（按当前阶段分发；测试环境无 get_phase 时仅加载模块）
if ngx.get_phase and ngx.get_phase() == "ssl_client_hello" then
    _M.run()
end

return _M
