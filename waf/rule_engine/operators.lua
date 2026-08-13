-- rule_engine/operators.lua
-- 运算符：REGEX / EQUALS / CONTAINS / PM / CIDR / STARTS_WITH / ENDS_WITH / EXISTS

local _M = {}

local bit = require "bit"
local re_find = ngx.re.find

-- libinjection 语义检测（懒加载；.so 缺失时自动降级为不匹配，不影响其他运算符）
-- 依赖 require 的 package.loaded 缓存，避免重复加载开销
local function get_libinj()
    local ok, m = pcall(require, "libinjection_ffi")
    return ok and m or { available = false }
end

-- IPv4 字符串转 32 位整数
local function ipv4_to_int(ip)
    local a, b, c, d = tostring(ip):match("^(%d+)%.(%d+)%.(%d+)%.(%d+)$")
    if not a then return nil end
    a, b, c, d = tonumber(a), tonumber(b), tonumber(c), tonumber(d)
    if not (a and b and c and d) then return nil end
    if a > 255 or b > 255 or c > 255 or d > 255 then return nil end
    return (a * 16777216) + (b * 65536) + (c * 256) + d
end

local operators = {
    -- 正则匹配（优先使用预编译对象 compiled，避免每请求重复 PCRE 编译）
    -- 注：使用 "u"（UTF-8）选项，多字节字符按整体处理；CRS 中 \W 类通配规则
    --     由规则自身 pattern 显式限定 ASCII 字符范围，避免对 UTF-8 中文误报。
    REGEX = function(value, pattern, compiled)
        if value == nil then return false end
        if compiled then
            local from, _, err = compiled:find(tostring(value))
            if err then
                ngx.log(ngx.WARN, "[waf] 正则执行错误: ", err, " pattern=", pattern)
                return false
            end
            return from ~= nil
        end
        local from, _, err = re_find(tostring(value), pattern, "joiu")
        if err then
            ngx.log(ngx.WARN, "[waf] 正则编译/执行错误: ", err, " pattern=", pattern)
            return false
        end
        return from ~= nil
    end,

    -- 完全相等
    EQUALS = function(value, pattern)
        return value ~= nil and tostring(value) == pattern
    end,

    -- 子串包含（纯文本）
    CONTAINS = function(value, pattern)
        return value ~= nil and tostring(value):find(pattern, 1, true) ~= nil
    end,

    -- 词组匹配：pattern 以 | 分隔，任一词命中即真（纯文本、忽略大小写）
    PM = function(value, pattern)
        if value == nil then return false end
        local s = string.lower(tostring(value))
        for word in string.gmatch(pattern, "[^|]+") do
            if s:find(string.lower(word), 1, true) then
                return true
            end
        end
        return false
    end,

    -- CIDR / 精确 IP 匹配（IPv4）
    CIDR = function(value, pattern)
        if value == nil then return false end
        local ip_str = tostring(value)
        local net, prefix = tostring(pattern):match("^([^/]+)/(%d+)$")
        if not net or not prefix then
            return ip_str == tostring(pattern)
        end
        local ip_int = ipv4_to_int(ip_str)
        local net_int = ipv4_to_int(net)
        if not ip_int or not net_int then return false end
        prefix = tonumber(prefix)
        if prefix <= 0 then return true end
        if prefix >= 32 then return ip_int == net_int end
        local mask = bit.lshift(0xFFFFFFFF, 32 - prefix)
        return bit.band(ip_int, mask) == bit.band(net_int, mask)
    end,

    -- 前缀匹配（纯文本）
    STARTS_WITH = function(value, pattern)
        if value == nil then return false end
        local s = tostring(value)
        return #s >= #pattern and string.sub(s, 1, #pattern) == pattern
    end,

    -- 后缀匹配（纯文本）
    ENDS_WITH = function(value, pattern)
        if value == nil then return false end
        local s = tostring(value)
        return #s >= #pattern and string.sub(s, -#pattern) == pattern
    end,

    -- 存在性
    EXISTS = function(value)
        return value ~= nil and tostring(value) ~= ""
    end,

    -- 语义检测：SQL 注入（libinjection 词法/语法分析，抗编码与注释绕过）
    LIBINJECTION_SQLI = function(value)
        local m = get_libinj()
        if not m.available then return false end
        -- JSON 结构化：只对字段值做语义分析，避免 JSON 语法被误判
        local util = require "rule_engine.util"
        local ok, vals = util.try_parse_json(value)
        if ok then
            for _, v in ipairs(vals) do
                if m.is_sqli(v) then return true end
            end
            return false
        end
        return m.is_sqli(value)
    end,

    -- 语义检测：XSS（libinjection HTML5 解析）
    LIBINJECTION_XSS = function(value)
        local m = get_libinj()
        if not m.available then return false end
        -- JSON 结构化：只对字段值做语义分析
        local util = require "rule_engine.util"
        local ok, vals = util.try_parse_json(value)
        if ok then
            for _, v in ipairs(vals) do
                if m.is_xss(v) then return true end
            end
            return false
        end
        return m.is_xss(value)
    end,
}

-- 求值：name 为运算符名；compiled 为 REGEX 预编译对象（可选）
function _M.eval(name, value, pattern, compiled)
    local fn = operators[name]
    if not fn then
        return false
    end
    return fn(value, pattern, compiled)
end

function _M.is_valid(name)
    return operators[name] ~= nil
end

return _M
