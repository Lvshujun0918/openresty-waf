-- rule_engine/util.lua
-- 通用工具：JSON body 结构化解析。
-- 目的：降低 JSON API 误报——检测时只对字段"值"做匹配/语义分析，
-- 避免 JSON 语法（引号/冒号/逗号）被当作攻击特征误判。

local cjson = require "cjson.safe"

local _M = {}

-- 递归展平 JSON 对象/数组 → 字符串值列表（include_keys 时同时收集字段路径）
local function flatten(obj, include_keys, prefix, out)
    out = out or {}
    prefix = prefix or ""
    if type(obj) == "string" or type(obj) == "number" or type(obj) == "boolean" then
        out[#out + 1] = tostring(obj)
        if include_keys and prefix ~= "" then
            out[#out + 1] = prefix
        end
    elseif type(obj) == "table" then
        for k, v in pairs(obj) do
            local path = prefix == "" and tostring(k) or (prefix .. "." .. tostring(k))
            flatten(v, include_keys, path, out)
        end
    end
    return out
end

-- 尝试将 body 解析为 JSON：
--   成功 -> (true, {字符串值列表})；body 非 JSON 或解析失败 -> (nil, nil)
function _M.try_parse_json(body, include_keys)
    if not body or body == "" then return nil end
    local first = body:match("^%s*([%[%{])")
    if not first then return nil end
    local ok, obj = pcall(cjson.decode, body)
    if not ok or type(obj) ~= "table" then return nil end
    return true, flatten(obj, include_keys)
end

-- 静态资源剪枝判断：路径命中配置的后缀/前缀时返回 true。
-- 静态文件（图片/字体/JS/CSS 等）极少作为攻击载荷，命中时跳过规则引擎检测，
-- 降低普通请求的检测开销（IP 名单 / CC / 人机验证等仍生效）。
function _M.is_static_path(path, skip)
    if not skip or type(path) ~= "string" then return false end
    local p = path:lower()
    for _, ext in ipairs(skip.ext or {}) do
        if type(ext) == "string" and ext ~= "" and p:sub(-#ext) == ext then
            return true
        end
    end
    for _, pre in ipairs(skip.prefix or {}) do
        if type(pre) == "string" and pre ~= "" and p:sub(1, #pre) == pre then
            return true
        end
    end
    return false
end

-- 名单正则匹配：value 命中 patterns 中任一正则时返回 true（空 pattern 跳过）。
-- 用于 whitelist.urls / whitelist.user_agents / blacklist.urls 等名单配置。
function _M.match_regex_list(value, patterns)
    if type(value) ~= "string" or not patterns then return false end
    local operators = require "rule_engine.operators"
    for _, p in ipairs(patterns) do
        if type(p) == "string" and p ~= "" and operators.eval("REGEX", value, p) then
            return true
        end
    end
    return false
end

return _M
