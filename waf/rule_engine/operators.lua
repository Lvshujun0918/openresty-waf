-- rule_engine/operators.lua
-- 运算符：REGEX / EQUALS / CONTAINS / PM / CIDR / STARTS_WITH / ENDS_WITH / EXISTS

local _M = {}

local bit = require "bit"
local errlog = require "errlog"
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

-- IPv6 字符串解析为 8 个 16 位整数（纯 Lua，支持 :: 压缩与 IPv4 尾段映射）
local function ipv6_to_words(ip)
    ip = tostring(ip or "")
    if ip == "" then return nil end
    ip = ip:gsub("^%[", ""):gsub("%]$", "")

    -- IPv4 尾段（如 ::ffff:1.2.3.4）：拆出尾部两个 16 位段
    local tail_words
    local v4 = ip:match(":([%d%.]+)$")
    if v4 and v4:find("%.") then
        local a, b, c, d = v4:match("^(%d+)%.(%d+)%.(%d+)%.(%d+)$")
        if not a then return nil end
        a, b, c, d = tonumber(a), tonumber(b), tonumber(c), tonumber(d)
        if not (a and b and c and d) or a > 255 or b > 255 or c > 255 or d > 255 then
            return nil
        end
        tail_words = { a * 256 + b, c * 256 + d }
        ip = ip:sub(1, -#v4 - 1)  -- 去掉 ":v4" 后缀（保留结尾的 ":"）
    end

    -- 解析十六进制段（结尾冒号产生的空段自动跳过）
    local function parse_side(s, out)
        if s == "" then return true end
        for p in string.gmatch(s, "[^:]+") do
            local h = tonumber(p, 16)
            if not h or h > 0xFFFF then return false end
            out[#out + 1] = h
        end
        return true
    end

    local words = {}
    local left_s, right_s = ip:match("^(.-)::(.-)$")
    if left_s then
        -- :: 压缩：左侧 + 补零 + 右侧 + IPv4 尾段
        if not parse_side(left_s, words) then return nil end
        local left_n = #words
        if not parse_side(right_s, words) then return nil end
        local tail_n = tail_words and 2 or 0
        local fill = 8 - #words - tail_n
        if fill < 1 then return nil end  -- :: 至少代表一个全零段
        -- 把右侧段整体后移 fill 位，中间补零
        for i = #words, left_n + 1, -1 do
            words[i + fill] = words[i]
        end
        for i = 1, fill do
            words[left_n + i] = 0
        end
    else
        if not parse_side(ip, words) then return nil end
        local tail_n = tail_words and 2 or 0
        if #words + tail_n ~= 8 then return nil end
    end

    if tail_words then
        if #words + 2 > 8 then return nil end
        words[#words + 1] = tail_words[1]
        words[#words + 1] = tail_words[2]
    end
    return #words == 8 and words or nil
end

-- IPv6 前缀匹配：比较前 prefix 位
local function ipv6_match(net_words, prefix, ip_words)
    if prefix <= 0 then return true end
    if prefix >= 128 then
        for i = 1, 8 do
            if net_words[i] ~= ip_words[i] then return false end
        end
        return true
    end
    local full = math.floor(prefix / 16)
    local rem = prefix % 16
    for i = 1, full do
        if net_words[i] ~= ip_words[i] then return false end
    end
    if rem > 0 then
        local mask = bit.lshift(0xFFFF, 16 - rem)
        return bit.band(net_words[full + 1], mask) == bit.band(ip_words[full + 1], mask)
    end
    return true
end

local operators = {
    -- 正则匹配（优先使用预编译对象 compiled，避免每请求重复 PCRE 编译）
    -- 注：使用 "u"（UTF-8）选项，多字节字符按整体处理；CRS 中 \W 类通配规则
    --     由规则自身 pattern 显式限定 ASCII 字符范围，避免对 UTF-8 中文误报。
    REGEX = function(value, pattern, compiled)
        if value == nil then return false end
        -- 护栏：超长 pattern 直接不匹配（正常规则上限 32KB，与后台校验一致）
        if type(pattern) == "string" and #pattern > 32768 then
            errlog.warn("operators", "正则 pattern 过长，跳过匹配（长度 " .. tostring(#pattern) .. "）")
            return false
        end
        if compiled then
            local from, _, err = compiled:find(tostring(value))
            if err then
                errlog.warn("operators", "正则执行错误: " .. tostring(err) .. " pattern=" .. pattern)
                return false
            end
            return from ~= nil
        end
        local from, _, err = re_find(tostring(value), pattern, "joiu")
        if err then
            errlog.warn("operators", "正则编译/执行错误: " .. tostring(err) .. " pattern=" .. pattern)
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

    -- CIDR / 精确 IP 匹配（IPv4 + IPv6）
    CIDR = function(value, pattern)
        if value == nil then return false end
        local ip_str = tostring(value)
        local net, prefix = tostring(pattern):match("^([^/]+)/(%d+)$")
        if not net or not prefix then
            return ip_str == tostring(pattern)
        end
        prefix = tonumber(prefix)
        -- IPv6：值或网段含 ":" 即走 IPv6 路径（128 位逐字比较）
        if ip_str:find(":", 1, true) or net:find(":", 1, true) then
            local ip_w = ipv6_to_words(ip_str)
            local net_w = ipv6_to_words(net)
            if not ip_w or not net_w then return false end
            return ipv6_match(net_w, prefix, ip_w)
        end
        local ip_int = ipv4_to_int(ip_str)
        local net_int = ipv4_to_int(net)
        if not ip_int or not net_int then return false end
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

    -- 轻量语义分析：token 化 + 结构异常度评分（纯 Lua，无 .so 依赖）
    -- pattern 为分数阈值（0-100），任一值评分达到阈值即命中。
    -- 典型用法：SCORE 弱特征规则（阈值 35 计 +1 / 阈值 60 计 +2），
    -- 与 libinjection 强特征（BLOCK）形成两层语义网。
    SEMANTIC_ANOMALY = function(value, pattern)
        local sem = require "semantic"
        local util = require "rule_engine.util"
        local threshold = tonumber(pattern)
        if not threshold then return false end
        local ok, vals = util.try_parse_json(value)
        if not ok then vals = { value } end
        for _, v in ipairs(vals) do
            if v ~= nil and v ~= "" then
                local score = sem.anomaly(tostring(v))
                if score >= threshold then return true end
            end
        end
        return false
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
