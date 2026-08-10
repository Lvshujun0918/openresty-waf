-- rule_engine/transforms.lua
-- 变换链：对提取的变量值做归一化处理，降低绕过（编码、大小写、注释混淆等）。

local _M = {}

local transforms = {
    -- URL 解码（一次）
    url_decode = function(s)
        return ngx.unescape_uri(s or "")
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
