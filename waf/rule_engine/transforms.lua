-- rule_engine/transforms.lua
-- 变换链：对提取的变量值做归一化处理，降低绕过（编码、大小写、注释混淆等）。
--
-- 注意：base64/hex/html_entity 解码均带"疑似编码"护栏——只有整体像对应编码
-- 的字符串才解码，避免把任意文本解码成垃圾导致误报/漏报。

local _M = {}

-- ============================================================================
-- 纯 Lua 解码实现（不依赖 ngx，便于单测）
-- ============================================================================

local b64_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
local b64_index = {}
for i = 1, #b64_chars do
    b64_index[b64_chars:sub(i, i)] = i - 1
end

-- base64 解码（纯 Lua；输入非法时尽量容忍，不抛错）
-- 每发射 1 字节后把缓冲掩码到剩余位，避免长输入下双精度浮点精度损失
local function b64_decode(s)
    local out = {}
    local buf, bits = 0, 0
    for i = 1, #s do
        local c = s:sub(i, i)
        if c == "=" then
            break  -- 填充结束
        elseif c ~= "\r" and c ~= "\n" and c ~= " " then
            local v = b64_index[c]
            if v == nil then
                return s  -- 非法字符：放弃解码返回原串（护栏兜底）
            end
            buf = buf * 64 + v
            bits = bits + 6
            if bits >= 8 then
                bits = bits - 8
                out[#out + 1] = string.char(math.floor(buf / (2 ^ bits)) % 256)
                buf = buf % (2 ^ bits)
            end
        end
    end
    return table.concat(out)
end

-- hex 解码（仅整体为偶数长十六进制串时解码，返回 nil 表示不解码）
local function do_hex_decode(s)
    if #s == 0 or #s % 2 ~= 0 or not s:match("^[0-9a-fA-F]+$") then
        return nil
    end
    local out = {}
    for i = 1, #s, 2 do
        out[#out + 1] = string.char(tonumber(s:sub(i, i + 1), 16))
    end
    return table.concat(out)
end

-- HTML 实体解码（常见命名实体 + 十进制/十六进制数字实体）
local function do_html_entity_decode(s)
    if not s:find("&", 1, true) then
        return s
    end
    local named = {
        ["&lt;"] = "<", ["&gt;"] = ">", ["&amp;"] = "&", ["&quot;"] = '"',
        ["&apos;"] = "'", ["&#39;"] = "'", ["&#x27;"] = "'", ["&nbsp;"] = " ",
        ["&colon;"] = ":", ["&sol;"] = "/", ["&lpar;"] = "(", ["&rpar;"] = ")",
    }
    local out = (s:gsub("&[#%a][%w]*;", function(e)
        local v = named[e]
        if v then return v end
        local num = e:match("^&#x([0-9a-fA-F]+);$")
        if num then
            return string.char(tonumber(num, 16) % 256)
        end
        num = e:match("^&#(%d+);$")
        if num then
            local n = tonumber(num)
            if n and n >= 32 and n < 256 then
                return string.char(n)
            end
        end
        return e  -- 未识别：保持原样
    end))
    return out
end

local transforms = {
    -- URL 解码（一次）
    url_decode = function(s)
        return ngx.unescape_uri(s or "")
    end,

    -- 多重 URL 解码（最多 3 次直至不再变化）：识别双重/多重编码绕过
    -- （如 %2520 单次解码后仍为 %20，多重解码还原为空格后被规则命中；
    --   普通 URL 编码中文解码一次后不再含 %，不会误报）
    url_decode_twice = function(s)
        s = s or ""
        for _ = 1, 3 do
            local decoded = ngx.unescape_uri(s)
            if decoded == s then
                break
            end
            s = decoded
        end
        return s
    end,

    -- 小写化
    to_lowercase = function(s)
        return string.lower(s or "")
    end,

    -- 去除 SQL 注释（/* */、--、#）
    remove_comments = function(s)
        s = s or ""
        s = s:gsub("/%*.-%*/", "")
        s = s:gsub("%-%-[^\r\n]*", "")
        s = s:gsub("#[^\r\n]*", "")
        return s
    end,

    -- 压缩连续空白为单个空格
    compress_whitespace = function(s)
        s = s or ""
        return (s:gsub("%s+", " "))
    end,

    -- 规范化路径（压缩重复斜杠）
    normalize_path = function(s)
        s = s or ""
        return (s:gsub("/+", "/"))
    end,

    -- base64 解码（护栏：整体疑似 base64 时才解码——长度 4 的倍数、
    -- 仅含 base64 字符与填充 =；否则返回原串，避免对普通文本误解码）
    base64_decode = function(s)
        s = s or ""
        if s == "" then return s end
        if #s < 8 or #s % 4 ~= 0 then return s end
        if not s:match("^[A-Za-z0-9+/=]+$") then return s end
        return b64_decode(s)
    end,

    -- hex 解码（护栏：整体为偶数长十六进制串才解码，否则原样返回）
    hex_decode = function(s)
        s = s or ""
        local decoded = do_hex_decode(s)
        return decoded or s
    end,

    -- HTML 实体解码（&lt; &gt; &amp; 及数字实体；不含 & 直接原样返回）
    html_entity_decode = function(s)
        return do_html_entity_decode(s or "")
    end,
}

-- 按名称列表依次应用变换
function _M.apply(s, names)
    if not names or #names == 0 then
        return s
    end
    for _, name in ipairs(names) do
        local fn = transforms[name]
        if fn then
            s = fn(s)
        end
    end
    return s
end

function _M.is_valid(name)
    return transforms[name] ~= nil
end

return _M
