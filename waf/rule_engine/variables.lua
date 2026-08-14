-- rule_engine/variables.lua
-- 变量集合：按规则声明的变量类型提取请求数据，返回字符串列表。

local _M = {}

local function push(out, v)
    if v ~= nil then
        out[#out + 1] = tostring(v)
    end
end

-- 遍历参数表（处理多值参数），include_keys 时同时收集键名
local function collect_args(args, out, include_keys)
    for k, v in pairs(args or {}) do
        if type(v) == "table" then
            for _, item in ipairs(v) do
                push(out, item)
            end
        else
            push(out, v)
        end
        if include_keys then
            push(out, k)
        end
    end
end

-- 提取指定 key 的值（处理多值）
local function push_specific(args, specific, out)
    local v = args[specific]
    if type(v) == "table" then
        for _, item in ipairs(v) do
            push(out, item)
        end
    else
        push(out, v)
    end
end

-- 实际提取逻辑（无缓存）
local function collect_raw(var, ctx)
    local typ = var.type
    local specific = var.specific
    local parse = var.parse or {}
    local include_keys = parse[1] == "keys"

    local out = {}

    if typ == "URI" then
        push(out, ngx.var.uri)

    elseif typ == "REQUEST_URI" or typ == "REQUEST_LINE" then
        push(out, ngx.var.request_uri)

    elseif typ == "METHOD" then
        push(out, ngx.req.get_method())

    elseif typ == "CLIENT_IP" then
        push(out, require("storage").get_client_ip())

    elseif typ == "USER_AGENT" then
        push(out, ngx.var.http_user_agent)

    elseif typ == "URI_ARGS" then
        local args = ngx.req.get_uri_args()
        if specific and specific ~= "" then
            push_specific(args, specific, out)
        else
            collect_args(args, out, include_keys)
        end

    elseif typ == "ARGS_COUNT" then
        -- 参数总量（URI + POST 表单），用于参数洪泛/DoS 防护
        local n = 0
        local args = ngx.req.get_uri_args() or {}
        for _ in pairs(args) do n = n + 1 end
        if ngx.req.get_method() ~= "GET" then
            ngx.req.read_body()
            local post = ngx.req.get_post_args() or {}
            for _ in pairs(post) do n = n + 1 end
        end
        push(out, tostring(n))

    elseif typ == "URI_ARGS_DUP" then
        -- HPP：收集重复出现的参数名及其全部值（同参数多次提交）
        local args = ngx.req.get_uri_args()
        for k, v in pairs(args or {}) do
            if type(v) == "table" and #v > 1 then
                push(out, k)
                for _, item in ipairs(v) do
                    push(out, item)
                end
            end
        end

    elseif typ == "POST_ARGS" then
        ngx.req.read_body()
        local body = ngx.req.get_body_data()
        -- JSON body 结构化：解析为字段值后检测，避免 JSON 语法（引号/冒号）被误判
        local json_vals
        local ct = ngx.var.content_type or ""
        if body and ct:find("application/json", 1, true) then
            local util = require "rule_engine.util"
            local ok, vals = util.try_parse_json(body, include_keys)
            if ok then
                json_vals = vals
            end
        end
        -- XML/SOAP body 结构化：标签/属性/文本展平，避免 XML 标记被误判
        local xml_vals
        if body and (ct:find("xml", 1, true) or ct:find("soap", 1, true)) then
            local util = require "rule_engine.util"
            xml_vals = util.try_parse_xml(body)
        end
        if json_vals then
            if not (specific and specific ~= "") then
                for _, v in ipairs(json_vals) do
                    push(out, v)
                end
            else
                -- specific 场景：JSON 展平值不含字段名映射，回退默认解析
                local args = ngx.req.get_post_args()
                push_specific(args, specific, out)
            end
        elseif xml_vals then
            for _, v in ipairs(xml_vals) do
                push(out, v)
            end
        else
            local args = ngx.req.get_post_args()
            if specific and specific ~= "" then
                push_specific(args, specific, out)
            else
                collect_args(args, out, include_keys)
            end
        end

    elseif typ == "POST_ARGS_DUP" then
        -- HPP：POST 表单重复参数名及其全部值
        ngx.req.read_body()
        local args = ngx.req.get_post_args()
        for k, v in pairs(args or {}) do
            if type(v) == "table" and #v > 1 then
                push(out, k)
                for _, item in ipairs(v) do
                    push(out, item)
                end
            end
        end

    elseif typ == "HEADERS" then
        local headers = ngx.req.get_headers()
        if specific and specific ~= "" then
            local v = headers[specific]
            if type(v) == "table" then
                for _, item in ipairs(v) do push(out, item) end
            else
                push(out, v)
            end
        else
            collect_args(headers, out, false)
        end

    elseif typ == "HEADERS_COUNT" then
        -- 请求头数量，用于请求头洪泛/慢速攻击防护
        local headers = ngx.req.get_headers() or {}
        local n = 0
        for _ in pairs(headers) do n = n + 1 end
        push(out, tostring(n))

    elseif typ == "COOKIE" then
        local cookie_str = ngx.var.http_cookie or ""
        for part in string.gmatch(cookie_str, "[^;]+") do
            local k, v = part:match("^%s*([^=]+)=(.*)$")
            if k then
                if not specific or specific == "" or k == specific then
                    push(out, v)
                end
                if include_keys then
                    push(out, k)
                end
            end
        end

    elseif typ == "BODY" then
        ngx.req.read_body()
        push(out, ngx.req.get_body_data())

    elseif typ == "RESPONSE_STATUS" then
        push(out, tostring(ngx.status))

    elseif typ == "RESPONSE_HEADERS" then
        -- header_filter 起可用；优先 ngx.resp.get_headers（上游响应头），
        -- 回退 ngx.header（Lua 设置的待发送响应头）
        local hdrs
        if ngx.resp and ngx.resp.get_headers then
            hdrs = ngx.resp.get_headers()
        end
        if not hdrs then hdrs = ngx.header or {} end
        if specific and specific ~= "" then
            local v = hdrs[specific]
            if type(v) == "table" then
                for _, item in ipairs(v) do push(out, item) end
            else
                push(out, v)
            end
        else
            collect_args(hdrs, out, false)
        end

    elseif typ == "RESPONSE_BODY" then
        -- 响应体由 body_filter 阶段累积到 ctx.resp_body（上限 8KB，EOF 时检测）
        if ctx then
            push(out, ctx.resp_body)
        end
    end

    return out
end

-- 提取变量（带请求级缓存）：同一请求内相同变量只解析一次，
-- 显著降低多规则对 URI_ARGS / HEADERS / BODY 的重复提取开销。
function _M.collect(var, ctx)
    local key = tostring(var.type) .. "|" .. tostring(var.specific or "") .. "|" ..
                tostring((var.parse or {})[1] or "values")

    if ctx then
        if ctx.var_cache then
            local cached = ctx.var_cache[key]
            if cached then
                return cached
            end
        end
        ctx.var_cache = ctx.var_cache or {}
    end

    local out = collect_raw(var, ctx)

    if ctx then
        ctx.var_cache[key] = out
    end
    return out
end

return _M
