-- rule_engine/util.lua
-- 通用工具：JSON/XML 结构化解析、静态剪枝、名单正则。
-- 目的：降低结构化 API 误报——检测时只对字段"值"做匹配/语义分析，
-- 避免 JSON 语法（引号/冒号/逗号）或 XML 标记被当作攻击特征误判。

local cjson = require "cjson.safe"

local _M = {}

-- 递归展平 JSON 对象/数组 → 字符串值列表（include_keys 时同时收集字段路径）
-- depth 限制递归深度（默认 32），防超深嵌套撑爆 Lua 栈
local function flatten(obj, include_keys, prefix, out, depth)
    out = out or {}
    prefix = prefix or ""
    depth = depth or 0
    if depth > 32 then
        return out
    end
    if type(obj) == "string" or type(obj) == "number" or type(obj) == "boolean" then
        out[#out + 1] = tostring(obj)
        if include_keys and prefix ~= "" then
            out[#out + 1] = prefix
        end
    elseif type(obj) == "table" then
        for k, v in pairs(obj) do
            local path = prefix == "" and tostring(k) or (prefix .. "." .. tostring(k))
            flatten(v, include_keys, path, out, depth + 1)
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
    -- flatten 也放入 pcall：超深嵌套等极端输入失败时按解析失败处理
    local ok2, vals = pcall(flatten, obj, include_keys, "", {}, 0)
    if not ok2 or type(vals) ~= "table" or #vals == 0 then return nil end
    return true, vals
end

-- ============================================================================
-- 轻量纯 Lua XML 解析（扫描式，无递归，防深度攻击）
-- 返回展平字符串列表：标签名 + 属性名 + 属性值 + 文本/CDATA 内容。
-- DOCTYPE 内部声明整体保留（XXE 特征由规则对原始片段匹配）。
-- 非 XML（不含 "<"）返回 nil；片段数量上限 1000，防超大文档拖垮检测。
-- ============================================================================
local function xml_add(out, count, v)
    if v ~= nil and v ~= "" and count < 1000 then
        out[#out + 1] = v
        return count + 1
    end
    return count
end

local function strip_xml_text(s)
    s = s:match("^%s*(.-)%s*$")
    return s
end

function _M.try_parse_xml(body)
    if type(body) ~= "string" or body == "" then return nil end
    if not body:find("<", 1, true) then return nil end

    local out, count = {}, 0
    local i, len = 1, #body
    while i <= len and count < 1000 do
        local lt = body:find("<", i, true)
        if not lt then
            count = xml_add(out, count, strip_xml_text(body:sub(i)))
            break
        end
        count = xml_add(out, count, strip_xml_text(body:sub(i, lt - 1)))
        -- 注释 / CDATA 内容可含 ">"：先按类型定位真正的结束标记
        if body:sub(lt + 1, lt + 3) == "!--" then
            local endc = body:find("-->", lt + 4, true)
            i = endc and (endc + 3) or len + 1
        elseif body:sub(lt + 1, lt + 8) == "![CDATA[" then
            local endc = body:find("]]>", lt + 9, true)
            if endc then
                count = xml_add(out, count, body:sub(lt + 9, endc - 1))
                i = endc + 3
            else
                i = len + 1
            end
        else
            local gt = body:find(">", lt + 1, true)
            if not gt then break end
            local inner = body:sub(lt + 1, gt - 1)
            local first = inner:sub(1, 1)
            if first == "!" then
                -- DOCTYPE：整体保留（含 ENTITY/SYSTEM 声明，供 XXE 规则匹配）
                count = xml_add(out, count, inner)
            elseif first == "?" then
                -- 处理指令（XML 声明）：跳过
            elseif first ~= "/" then
                -- 开始标签：标签名 + 属性名 + 属性值（双引号/单引号）
                local name = inner:match("^([^%s/>]+)")
                if name then
                    count = xml_add(out, count, name)
                    for k, v in string.gmatch(inner, '([^%s=/>]+)%s*=%s*"([^"]*)"') do
                        count = xml_add(out, count, k)
                        count = xml_add(out, count, v)
                    end
                    for k, v in string.gmatch(inner, "([^%s=/>]+)%s*=%s*'([^']*)'") do
                        count = xml_add(out, count, k)
                        count = xml_add(out, count, v)
                    end
                end
            end
            i = gt + 1
        end
    end
    return #out > 0 and out or nil
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
