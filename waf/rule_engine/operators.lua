-- rule_engine/operators.lua
-- 运算符：REGEX / EQUALS / CONTAINS / PM / CIDR / STARTS_WITH / ENDS_WITH / EXISTS

local _M = {}

local bit = require "bit"
local re_find = ngx.re.find

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
    -- 正则匹配（PCRE JIT，忽略大小写）
    REGEX = function(value, pattern)
        if value == nil then return false end
        local from, _, err = re_find(tostring(value), pattern, "joi")
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
}

-- 求值：name 为运算符名
function _M.eval(name, value, pattern)
    local fn = operators[name]
    if not fn then
        return false
    end
    return fn(value, pattern)
end

function _M.is_valid(name)
    return operators[name] ~= nil
end

return _M
