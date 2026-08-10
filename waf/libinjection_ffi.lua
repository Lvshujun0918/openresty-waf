-- libinjection FFI 绑定：SQLi / XSS 语义检测（词法分析，抗编码/注释绕过）
--
-- 依赖编译后的 libinjection.so（随 WAF 组件分发，安装于 /opt/waf/）：
--   编译：gcc -O2 -fPIC -shared -o libinjection.so libinjection_sqli.c libinjection_html5.c libinjection_xss.c
-- 缺失时 available=false，引擎相应运算符（LIBINJECTION_SQLI / LIBINJECTION_XSS）
-- 自动降级为不匹配，不影响其他检测逻辑。

local ffi = require "ffi"

ffi.cdef[[
int libinjection_sqli(const char *s, size_t slen, char fingerprint[8]);
int libinjection_xss(const char *s, size_t slen);
const char *libinjection_version(void);
]]

local _M = { available = false }

local function try_load()
    for _, name in ipairs({ "/opt/waf/libinjection.so", "libinjection" }) do
        local ok, lib = pcall(ffi.load, name)
        if ok then
            return lib
        end
    end
    return nil
end

local lib = try_load()

if lib then
    _M.available = true
    _M.version = ffi.string(lib.libinjection_version())

    function _M.is_sqli(s)
        if s == nil then return false end
        s = tostring(s)
        if #s == 0 then return false end
        local fp = ffi.new("char[8]")
        local r = lib.libinjection_sqli(s, #s, fp)
        return r == 1
    end

    function _M.is_xss(s)
        if s == nil then return false end
        s = tostring(s)
        if #s == 0 then return false end
        local r = lib.libinjection_xss(s, #s)
        return r == 1
    end
else
    function _M.is_sqli() return false end
    function _M.is_xss() return false end
end

return _M
