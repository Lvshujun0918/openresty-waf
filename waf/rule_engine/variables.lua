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

-- 提取变量，返回字符串数组
function _M.collect(var)
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

    elseif typ == "POST_ARGS" then
        ngx.req.read_body()
        local args = ngx.req.get_post_args()
        if specific and specific ~= "" then
            push_specific(args, specific, out)
        else
            collect_args(args, out, include_keys)
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
    end

    return out
end

return _M
