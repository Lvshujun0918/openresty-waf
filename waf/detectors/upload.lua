-- detectors/upload.lua
-- 文件上传检测：multipart/form-data 文件名后缀 / 文件 Content-Type 黑名单。
--
-- 纯 Lua 解析 multipart（不依赖 resty.upload），解析函数独立可单测；
-- 请求体超过 client_body_buffer_size 被 nginx 落临时文件时，改为流式读取
-- 文件前 spooled_scan_bytes 字节做同样的后缀/类型检测（默认 512KB），
-- 避免超大上传绕过上传检测；超出扫描上限的部分不再读入内存。

local _M = {}

local errlog = require "errlog"

-- 从 Content-Type 头提取 boundary（支持带引号）
local function get_boundary(content_type)
    if not content_type then return nil end
    return content_type:match('boundary="?([^";%s]+)"?')
end

-- 解析 multipart body → 全部部分列表。
-- 文件 part：{ filename, content_type, head, data }——head 保留文件内容前 128 字节
-- （文件头魔数/脚本标签检测，覆盖长 MIME 头）；data 为完整内容（供图片马/Webshell 内容探测）。
-- 文本字段 part：{ name, value }。
-- 部分之间由 \r\n--boundary 分隔；结束分隔行为 --boundary--。
function _M.parse_parts(body, boundary)
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
        local name = headers:match('[Nn][Aa][Mm][Ee]="([^"]*)"')
            or headers:match('[Nn][Aa][Mm][Ee]=([^;%s]+)')
        local filename = headers:match('[Ff][Ii][Ll][Ee][Nn][Aa][Mm][Ee]="([^"]*)"')
            or headers:match('[Ff][Ii][Ll][Ee][Nn][Aa][Mm][Ee]=([^;%s]+)')
        local content_type = headers:match('[Cc][Oo][Nn][Tt][Ee][Nn][Tt]%-[Tt][Yy][Pp][Ee]:%s*([^\r\n]+)')
        if content_type then content_type = content_type:lower() end
        local data_start = header_end + 4
        local next_delim = body:find("\r\n" .. delim, data_start, true)
        local data = next_delim and body:sub(data_start, next_delim - 1)
            or body:sub(data_start)
        -- 文本字段值以 \r\n 结束（分隔行前），剥掉尾部 CRLF 还原原始值
        if not filename or filename == "" then
            data = data:gsub("\r\n$", "")
            if name and name ~= "" then
                parts[#parts + 1] = { name = name, value = data }
            end
        else
            parts[#parts + 1] = {
                filename = filename,
                content_type = content_type or nil,
                head = data:sub(1, 128),
                data = data,
            }
        end
        start = next_delim and body:find(delim, next_delim + 2, true) or nil
    end
    return parts
end

-- 解析 multipart body → 文件部分列表（兼容旧接口：仅含文件 part，含 head/data）
function _M.parse_multipart(body, boundary)
    local files = {}
    for _, part in ipairs(_M.parse_parts(body, boundary)) do
        if part.filename then
            files[#files + 1] = part
        end
    end
    return files
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

-- 请求体落临时文件时：读取文件前缀做同样的检测
local function check_spooled_file(boundary, up)
    local path = ngx.req.get_body_file()
    if not path or path == "" then
        errlog.warn("upload", "上传请求体过大且无临时文件路径，跳过上传检测")
        return nil
    end
    local max_bytes = tonumber(up.spooled_scan_bytes) or 524288
    local f, err = io.open(path, "rb")
    if not f then
        errlog.warn("upload", "无法打开上传临时文件: " .. tostring(err))
        return nil
    end
    local head = f:read(max_bytes)
    f:close()
    if not head then
        errlog.warn("upload", "读取上传临时文件失败，跳过上传检测")
        return nil
    end
    -- 文件头解析出文件部分（parse_multipart 对截断 body 兼容：
    -- 找不到下一分隔行时取剩余全部内容作为文件数据）
    return _M.scan_body(head, boundary, up)
end

-- 检测当前请求的上传内容。
-- 命中返回描述文本（写入事件 msg），未命中 / 不适用返回 nil。
-- up：cfg.upload 配置（enabled / deny_ext / deny_mime / spooled_scan_bytes）。
function _M.check(waf_ctx, up)
    if not up or up.enabled == false then return nil end
    local content_type = ngx.var.content_type or ""
    if not content_type:lower():find("multipart/form-data", 1, true) then
        return nil
    end
    local boundary = get_boundary(content_type)
    if not boundary then
        errlog.warn("upload", "multipart 缺少 boundary，跳过上传检测")
        return nil
    end
    ngx.req.read_body()
    local body = ngx.req.get_body_data()
    if not body then
        -- body 已落临时文件（超过 client_body_buffer_size）：流式读取文件前
        -- spooled_scan_bytes 字节继续检测，堵住超大上传绕过（超出部分不读入内存）
        return check_spooled_file(boundary, up)
    end
    return _M.scan_body(body, boundary, up)
end

-- 内容特征扫描（Webshell/可执行文件魔数，绕过后缀与类型伪装）
-- 文件头 script 特征：宽松匹配 PHP/ASP/JSP 标签与 shebang；XML 声明不误伤。
local CONTENT_FEATURES = {
    { pattern = "<%?php",     desc = "PHP 脚本标签" },
    { pattern = "<%?%s*=",    desc = "PHP 短标签" },
    { pattern = "<%[%s*[@=]", desc = "ASP/JSP 脚本标签" },
    { pattern = "<%[jsp:%s*:", desc = "JSP 标签" },
    { pattern = "#!%s*/",     desc = "Shebang 脚本" },
    { pattern = "^MZ",        desc = "PE 可执行文件" },
}

-- 图片扩展名（图片马判定：图片文件内嵌脚本代码）
local IMAGE_EXT = {
    "png", "jpg", "jpeg", "gif", "bmp", "webp",
}

-- webshell 危险函数特征：脚本标签上下文内的代码执行函数（低误报组合）。
-- pattern 需同时含脚本标签开启符与危险函数，避免纯文本/正常代码命中。
local WEBSHELL_FEATURES = {
    -- PHP：<?php ...(system|exec|shell_exec|passthru|assert|base64_decode|eval)...(
    { pattern = "<%?php[^>]*%f[%w_](?:system|exec|shell_exec|passthru|assert|base64_decode|eval)%s*%(", desc = "PHP 代码执行" },
    -- PHP 变体：<?= 或短标签 + eval/base64_decode（一句话马常见形态）
    { pattern = "<%?=[^>]*%f[%w_](?:eval|base64_decode)%s*%(", desc = "PHP 短标签代码执行" },
    -- ASP：<% ...(Execute|ExecuteGlobal|Eval|CreateObject("WScript.Shell")...(
    { pattern = "<%%%f[%w_]%s*(?:Execute|ExecuteGlobal|Eval)%s*%(", desc = "ASP 代码执行" },
    -- JSP：<% ...Runtime.getRuntime().exec / javax.script 等
    { pattern = "<%%[^>]*%f[%w_]Runtime%s*%.%s*getRuntime%s*%(%s*%)%s*%.%s*exec", desc = "JSP 命令执行" },
    -- 图片马兜底：任意脚本标签开启符出现在图片魔数之后（由调用方先判图片）
    { pattern = "<%?php", desc = "内嵌 PHP 代码" },
}

-- 单个文件是否图片扩展（小写比较）
local function is_image_ext(filename)
    local ext = filename:match("%.([^%.]+)$")
    if not ext then return false end
    ext = ext:lower()
    for _, img in ipairs(IMAGE_EXT) do
        if ext == img then return true end
    end
    return false
end

-- 内容扫描区间：文件太大时取头部 + 尾部各 half 字节（图片马代码常在文件尾）
local function scan_region(data, limit)
    if not limit or limit <= 0 then limit = 1048576 end
    local n = #data
    if n <= limit then return data end
    local half = math.floor(limit / 2)
    local head = data:sub(1, half)
    local tail = data:sub(-half)
    return head .. "\0" .. tail
end

-- 单个文件部分检测（后缀黑名单 + Content-Type 黑名单 + 内容特征）
local function scan_part(part, up)
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
    -- 3. 内容特征扫描（Webshell/可执行文件魔数，绕过后缀与类型伪装）
    if up.content_scan ~= false and part.head and #part.head > 0 then
        -- 3a. 文件头特征（脚本标签 / shebang / PE 魔数）
        for _, feat in ipairs(CONTENT_FEATURES) do
            local ok, m = pcall(ngx.re.find, part.head, feat.pattern, "joi")
            if ok and m then
                return "文件上传：内容含" .. feat.desc .. "（" .. part.filename .. "）"
            end
        end
        -- 3b. 图片马检测：图片扩展且在文件全程（头+尾采样）发现脚本代码
        if is_image_ext(part.filename) and part.data and #part.data > 0 then
            local region = scan_region(part.data, up.content_scan_limit)
            for _, feat in ipairs(CONTENT_FEATURES) do
                -- 图片文件头的图片魔数属于正常内容，只查脚本特征
                if feat.pattern ~= "^MZ" then
                    local ok, m = pcall(ngx.re.find, region, feat.pattern, "joi")
                    if ok and m then
                        return "文件上传：疑似图片马（图片内嵌" .. feat.desc .. "）（"
                            .. part.filename .. "）"
                    end
                end
            end
        end
        -- 3c. Webshell 危险函数组合（脚本标签 + 代码执行函数）
        if up.webshell_scan ~= false and part.data and #part.data > 0 then
            local region = scan_region(part.data, up.content_scan_limit)
            for _, feat in ipairs(WEBSHELL_FEATURES) do
                local ok, m = pcall(ngx.re.find, region, feat.pattern, "joi")
                if ok and m then
                    return "文件上传：疑似Webshell（" .. feat.desc .. "）（"
                        .. part.filename .. "）"
                end
            end
        end
    end
    return nil
end

-- 扫描内存中的 multipart body，命中返回描述文本
function _M.scan_body(body, boundary, up)
    for _, part in ipairs(_M.parse_multipart(body, boundary)) do
        local hit = scan_part(part, up)
        if hit then return hit end
    end
    return nil
end

return _M
