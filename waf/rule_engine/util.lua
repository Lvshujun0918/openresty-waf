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

return _M
