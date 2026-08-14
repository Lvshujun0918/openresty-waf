-- detectors/upload.lua
-- 文件上传检测：multipart/form-data 文件名后缀 / 文件 Content-Type 黑名单。
--
-- 纯 Lua 解析 multipart（不依赖 resty.upload），解析函数独立可单测；
-- 请求体超过 client_body_buffer_size 被 nginx 落临时文件时跳过内容检测
-- （此时 get_body_data 为 nil），避免把超大上传读入内存。

local _M = {}

-- 从 Content-Type 头提取 boundary（支持带引号）
local function get_boundary(content_type)
    if not content_type then return nil end
    return content_type:match('boundary="?([^";%s]+)"?')
end

-- 解析 multipart body → 文件部分列表 { filename, content_type, head }
-- head 保留文件内容前 64 字节（供后续文件头魔数检测扩展）。
-- 部分之间由 \r\n--boundary 分隔；结束分隔行为 --boundary--。
function _M.parse_multipart(body, boundary)
    local parts = {}
    if not body or not boundary or boundary == "" then return parts end
    local delim = "--" .. boundary
    local start = body:find(delim, 1, true)
    while start do
        local after = start + #delim
        if body:sub(after, after + 1) == "--" then break end  -- 结束分隔行
        local head_start = after + 2                        -- 跳过 \r\n
        local header_end = body:find("\r\n\r\n", head_start, true)
        if not header_end then break end
        -- MIME 头字段名不区分大小写（匹配键用小写字符类），保留文件名原大小写
        local headers = body:sub(head_start, header_end - 1)
        local filename = headers:match('[Ff][Ii][Ll][Ee][Nn][Aa][Mm][Ee]="([^"]*)"')
            or headers:match('[Ff][Ii][Ll][Ee][Nn][Aa][Mm][Ee]=([^;%s]+)')
        local content_type = headers:match('[Cc][Oo][Nn][Tt][Ee][Nn][Tt]%-[Tt][Yy][Pp][Ee]:%s*([^\r\n]+)')
        if content_type then content_type = content_type:lower() end
        local data_start = header_end + 4
        local next_delim = body:find("\r\n" .. delim, data_start, true)
        local data = next_delim and body:sub(data_start, next_delim - 1)
            or body:sub(data_start)
        if filename and filename ~= "" then
            parts[#parts + 1] = {
                filename = filename,
                content_type = content_type or nil,
                head = data:sub(1, 64),
            }
        end
        start = next_delim and body:find(delim, next_delim + 2, true) or nil
    end
    return parts
end

-- 值是否命中黑名单（忽略大小写）
local function in_list(list, value)
    if not value or not list then return false end
    local v = value:lower()
    for _, item in ipairs(list) do
        if type(item) == "string" and item ~= "" and item:lower() == v then
            return true
        end
    end
    return false
end

-- 检测当前请求的上传内容。
-- 命中返回描述文本（写入事件 msg），未命中 / 不适用返回 nil。
-- up：cfg.upload 配置（enabled / deny_ext / deny_mime）。
function _M.check(waf_ctx, up)
    if not up or up.enabled == false then return nil end
    local content_type = ngx.var.content_type or ""
    if not content_type:lower():find("multipart/form-data", 1, true) then
        return nil
    end
    local boundary = get_boundary(content_type)
    if not boundary then
        ngx.log(ngx.WARN, "[waf] multipart 缺少 boundary，跳过上传检测")
        return nil
    end
    ngx.req.read_body()
    local body = ngx.req.get_body_data()
    if not body then
        -- body 已落临时文件（超过 client_body_buffer_size）：跳过内容检测，
        -- 避免把超大上传读入内存；后端业务层仍需自行校验文件类型
        ngx.log(ngx.WARN, "[waf] 上传请求体过大（已落临时文件），跳过上传检测")
        return nil
    end
    for _, part in ipairs(_M.parse_multipart(body, boundary)) do
        -- 1. 文件名后缀黑名单（对伪装 Content-Type 的上传有效）
        local ext = part.filename:match("%.([^%.]+)$")
        if ext and in_list(up.deny_ext, ext) then
            return "文件上传：危险后缀 ." .. ext .. "（" .. part.filename .. "）"
        end
        -- 2. 文件 Content-Type 黑名单（对伪造后缀的上传有效）
        if in_list(up.deny_mime, part.content_type) then
            return "文件上传：危险类型 " .. tostring(part.content_type)
                .. "（" .. part.filename .. "）"
        end
    end
    return nil
end

return _M
