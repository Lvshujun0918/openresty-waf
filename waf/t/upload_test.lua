-- waf/t/upload_test.lua
-- detectors/upload 文件上传检测单测：multipart 解析 + 后缀/Content-Type 黑名单

local t = require "assert"
local upload = require "detectors.upload"

-- 构造 multipart body（单文件字段 file）
local function multipart(boundary, headers, data, extra)
    local b = "--" .. boundary .. "\r\n"
    local parts = {}
    parts[#parts + 1] = b .. headers .. "\r\n\r\n" .. data .. "\r\n"
    if extra then
        parts[#parts + 1] = b .. extra .. "\r\n\r\nx\r\n"
    end
    return table.concat(parts) .. "--" .. boundary .. "--\r\n"
end

local B = "----WebKitFormBoundaryABC123"

-- ============ parse_multipart ============

t.test("parse_multipart: 提取文件名与 Content-Type", function()
    local body = multipart(B,
        'Content-Disposition: form-data; name="file"; filename="shell.php"\r\nContent-Type: application/x-php',
        '<?php system($_GET[c]);?>')
    local parts = upload.parse_multipart(body, B)
    t.eq(#parts, 1)
    t.eq(parts[1].filename, "shell.php")
    t.eq(parts[1].content_type, "application/x-php")
    t.eq(parts[1].head, "<?php system($_GET[c]);?>")
end)

t.test("parse_multipart: 多部分（含普通文本字段）", function()
    local body = multipart(B,
        'Content-Disposition: form-data; name="file"; filename="a.php"\r\nContent-Type: text/plain',
        "aaa",
        'Content-Disposition: form-data; name="file2"; filename="b.exe"')
    local parts = upload.parse_multipart(body, B)
    t.eq(#parts, 2)
    t.eq(parts[1].filename, "a.php")
    t.eq(parts[2].filename, "b.exe")
    t.isnil(parts[2].content_type, "未声明 Content-Type 应为 nil")
end)

t.test("parse_multipart: 仅文本字段不产生文件部分", function()
    local body = multipart(B,
        'Content-Disposition: form-data; name="desc"',
        "hello")
    t.eq(#upload.parse_multipart(body, B), 0)
end)

t.test("parse_multipart: 头部字段大小写不敏感", function()
    local body = multipart(B,
        'content-disposition: form-data; name="f"; filename="X.PHP"\r\nCONTENT-TYPE: application/x-php',
        "x")
    local parts = upload.parse_multipart(body, B)
    t.eq(parts[1].filename, "X.PHP")
    t.eq(parts[1].content_type, "application/x-php")
end)

t.test("parse_multipart: 健壮性（空 body / 缺 boundary / 截断）", function()
    t.eq(#upload.parse_multipart(nil, B), 0)
    t.eq(#upload.parse_multipart("", B), 0)
    t.eq(#upload.parse_multipart("no boundary here", ""), 0)
    -- 无结束分隔行的截断 body 不抛错
    local body = "--" .. B .. "\r\nContent-Disposition: form-data; name=\"f\"; filename=\"a.php\"\r\n\r\nxx"
    local parts = upload.parse_multipart(body, B)
    t.eq(#parts, 1)
    t.eq(parts[1].head, "xx")
end)

-- ============ check ============

local function up_cfg(over)
    local cfg = {
        enabled = true,
        deny_ext = { "php", "jsp", "exe" },
        deny_mime = { "application/x-php", "application/x-msdownload" },
    }
    if over then
        for k, v in pairs(over) do cfg[k] = v end
    end
    return cfg
end

local function set_request(body, content_type)
    ngx.var.content_type = content_type
    ngx.req._body = body
end

t.test("check: 非 multipart 请求返回 nil", function()
    ngx_reset()
    set_request("a=1", "application/x-www-form-urlencoded")
    t.isnil(upload.check({}, up_cfg()))
end)

t.test("check: 危险后缀命中并返回描述", function()
    ngx_reset()
    local body = multipart(B,
        'Content-Disposition: form-data; name="file"; filename="webshell.php"\r\nContent-Type: image/png',
        "fake png")
    set_request(body, "multipart/form-data; boundary=" .. B)
    local hit = upload.check({}, up_cfg())
    t.notnil(hit, "危险后缀应命中")
    t.match(hit, "webshell.php")
end)

t.test("check: 伪造后缀但 Content-Type 危险仍命中", function()
    ngx_reset()
    local body = multipart(B,
        'Content-Disposition: form-data; name="file"; filename="a.png"\r\nContent-Type: application/x-php',
        "<?php")
    set_request(body, "multipart/form-data; boundary=" .. B)
    t.notnil(upload.check({}, up_cfg()))
end)

t.test("check: 安全文件不命中", function()
    ngx_reset()
    local body = multipart(B,
        'Content-Disposition: form-data; name="file"; filename="photo.jpg"\r\nContent-Type: image/jpeg',
        "jpgdata")
    set_request(body, "multipart/form-data; boundary=" .. B)
    t.isnil(upload.check({}, up_cfg()))
end)

t.test("check: enabled=false 关闭检测", function()
    ngx_reset()
    local body = multipart(B,
        'Content-Disposition: form-data; name="file"; filename="x.php"',
        "x")
    set_request(body, "multipart/form-data; boundary=" .. B)
    t.isnil(upload.check({}, up_cfg({ enabled = false })))
end)

t.test("check: 缺 boundary / 超大落盘（body nil）优雅跳过", function()
    ngx_reset()
    set_request("xx", "multipart/form-data")
    t.isnil(upload.check({}, up_cfg()))
    ngx_reset()
    ngx.var.content_type = "multipart/form-data; boundary=" .. B
    ngx.req._body = nil
    t.isnil(upload.check({}, up_cfg()))
end)

t.test("check: 落盘临时文件读取前缀仍检测危险后缀", function()
    ngx_reset()
    local fname = os.tmpname()
    local f = assert(io.open(fname, "wb"))
    f:write("--" .. B .. "\r\n"
        .. 'Content-Disposition: form-data; name="file"; filename="shell.php"\r\n'
        .. "Content-Type: application/octet-stream\r\n\r\n"
        .. "<?php system($_GET[c]);?>")
    f:close()
    ngx.var.content_type = "multipart/form-data; boundary=" .. B
    ngx.req._body = nil
    ngx.req._body_file = fname
    local hit = upload.check({}, up_cfg())
    os.remove(fname)
    t.notnil(hit)
    t.match(hit, "危险后缀")
end)

t.test("check: 落盘临时文件安全文件不命中", function()
    ngx_reset()
    local fname = os.tmpname()
    local f = assert(io.open(fname, "wb"))
    f:write("--" .. B .. "\r\n"
        .. 'Content-Disposition: form-data; name="file"; filename="photo.jpg"\r\n'
        .. "Content-Type: image/jpeg\r\n\r\n"
        .. "JPEGDATA")
    f:close()
    ngx.var.content_type = "multipart/form-data; boundary=" .. B
    ngx.req._body = nil
    ngx.req._body_file = fname
    t.isnil(upload.check({}, up_cfg()))
    os.remove(fname)
end)

t.test("check: 落盘无临时文件路径优雅跳过", function()
    ngx_reset()
    ngx.var.content_type = "multipart/form-data; boundary=" .. B
    ngx.req._body = nil
    ngx.req._body_file = nil
    t.isnil(upload.check({}, up_cfg()))
end)
t.test("upload: PHP 内容特征命中", function()
    local up = { enabled = true, deny_ext = {}, deny_mime = {}, content_scan = true }
    local body = multipart(B,
        'Content-Disposition: form-data; name="file"; filename="a.png"\r\nContent-Type: image/png',
        '<?php system($_GET[c]); ?>')
    local hit = upload.scan_body(body, B, up)
    t.notnil(hit)
    t.ok(hit:find("PHP", 1, true), "内容特征: " .. tostring(hit))
end)

-- ============ parse_parts：文本字段 + 文件部分 ============

t.test("parse_parts: 文本字段与文件部分共存", function()
    local body = "--" .. B .. "\r\n"
        .. 'Content-Disposition: form-data; name="title"\r\n\r\n'
        .. "标题\r\n"
        .. "--" .. B .. "\r\n"
        .. 'Content-Disposition: form-data; name="file"; filename="a.png"\r\n\r\n'
        .. "\x89PNGdata\r\n"
        .. "--" .. B .. "--\r\n"
    local parts = upload.parse_parts(body, B)
    t.eq(#parts, 2)
    t.eq(parts[1].name, "title")
    t.eq(parts[1].value, "标题")
    t.isnil(parts[1].filename, "文本字段无 filename")
    t.eq(parts[2].filename, "a.png")
    t.eq(parts[2].data, "\x89PNGdata")
end)

t.test("parse_parts: 文本字段值剥离尾部 CRLF", function()
    local body = "--" .. B .. "\r\n"
        .. 'Content-Disposition: form-data; name="d"\r\n\r\n'
        .. "plain\r\n"
        .. "--" .. B .. "--\r\n"
    local parts = upload.parse_parts(body, B)
    t.eq(#parts, 1)
    t.eq(parts[1].value, "plain")
end)

t.test("parse_parts: 文件 data 保留完整内容", function()
    local body = multipart(B,
        'Content-Disposition: form-data; name="file"; filename="x.txt"\r\nContent-Type: text/plain',
        "abcdef")
    local parts = upload.parse_parts(body, B)
    t.eq(parts[1].filename, "x.txt")
    t.eq(parts[1].data, "abcdef")
    t.eq(parts[1].head, "abcdef")
end)

-- ============ 图片马 / Webshell 危险函数 ============

local function img_up(over)
    local cfg = { enabled = true, deny_ext = {}, deny_mime = {}, content_scan = true }
    if over then
        for k, v in pairs(over) do cfg[k] = v end
    end
    return cfg
end

t.test("scan_body: 图片头 + 尾部 PHP 代码命中图片马", function()
    -- 图片马典型形态：合法图片头（GIF89a）+ 尾部嵌入 PHP 一句话
    local gif = "GIF89a\x01\x00\x01\x00\x80\x00\x00" .. string.rep("\x00", 200)
        .. "<?php @eval($_POST['x']);?>"
    local body = multipart(B,
        'Content-Disposition: form-data; name="file"; filename="logo.gif"\r\nContent-Type: image/gif',
        gif)
    local hit = upload.scan_body(body, B, img_up())
    t.notnil(hit, "图片马应命中")
    t.ok(hit:find("图片马", 1, true), "描述应含图片马: " .. tostring(hit))
end)

t.test("scan_body: 尾部 PHP 代码（超 128B head 之外）仍命中图片马", function()
    -- PHP 代码在文件尾部，超出只读 head 128B 的范围——必须靠 data 全程采样
    local png = "\x89PNG\r\n\x1a\n" .. string.rep("\x00\x01\x02", 60)
        .. "<?php system($_GET['c']);?>"
    t.ok(#png > 128, "测试数据应超出 head 128B 窗口")
    local body = multipart(B,
        'Content-Disposition: form-data; name="file"; filename="pic.png"\r\nContent-Type: image/png',
        png)
    local hit = upload.scan_body(body, B, img_up())
    t.notnil(hit, "尾部 PHP 的图片马应命中")
    t.ok(hit:find("图片马", 1, true) or hit:find("Webshell", 1, true), tostring(hit))
end)

t.test("scan_body: 图片文件转储危险函数组合命中 Webshell（代码在尾部）", function()
    -- 200 字节无特征前缀 + 尾部 PHP 危险函数，超出 head 128B 窗口
    local jpg = "\xff\xd8\xff\xe0" .. string.rep("jpegdata", 25) .. "<?php system($_GET[c]);?>"
    t.ok(#jpg > 128, "测试数据应超出 head 128B 窗口")
    local body = multipart(B,
        'Content-Disposition: form-data; name="file"; filename="photo.jpg"\r\nContent-Type: image/jpeg',
        jpg)
    local hit = upload.scan_body(body, B, img_up())
    t.notnil(hit)
    t.ok(hit:find("Webshell", 1, true) or hit:find("图片马", 1, true), tostring(hit))
end)

t.test("scan_body: 非图片文件含危险函数组合命中 Webshell", function()
    local body = multipart(B,
        'Content-Disposition: form-data; name="file"; filename="doc.txt"\r\nContent-Type: text/plain',
        string.rep("ab", 100) .. "<?php system($_GET[c]);?>")
    local hit = upload.scan_body(body, B, img_up())
    t.notnil(hit, "文档内嵌 PHP 代码执行应命中")
    t.ok(hit:find("Webshell", 1, true), tostring(hit))
end)

t.test("scan_body: 普通文本文件无脚本标签不命中", function()
    local body = multipart(B,
        'Content-Disposition: form-data; name="file"; filename="note.txt"\r\nContent-Type: text/plain',
        "只是普通文本，没有代码")
    t.isnil(upload.scan_body(body, B, img_up()))
end)

t.test("scan_body: 正常图片无内嵌代码不命中", function()
    local body = multipart(B,
        'Content-Disposition: form-data; name="file"; filename="real.png"\r\nContent-Type: image/png',
        "\x89PNG\r\n\x1a\n" .. string.rep("data", 50))
    t.isnil(upload.scan_body(body, B, img_up()))
end)

t.test("scan_body: webshell_scan=false 关闭危险函数检测", function()
    local body = multipart(B,
        'Content-Disposition: form-data; name="file"; filename="a.jpg"\r\nContent-Type: image/jpeg',
        "jpeg<?php system($_GET[c]);?>")
    -- 关 webshell 但保留 content_scan：文件头脚本标签仍会命中 CONTENT_FEATURES
    local hit = upload.scan_body(body, B, img_up({ webshell_scan = false }))
    t.notnil(hit, "文件头 PHP 标签仍应命中 CONTENT_FEATURES")
    t.ok(hit:find("PHP 脚本标签", 1, true) or hit:find("图片马", 1, true), tostring(hit))
end)
