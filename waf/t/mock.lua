-- waf/t/mock.lua
-- 轻量 ngx mock：覆盖被测 WAF 模块用到的 OpenResty API。
-- 纯 luajit 可运行，用于单元测试（非集成）。

-- ============================================================================
-- PCRE → Lua 模式 迷你转换
-- 覆盖常用转义：\s \d \w \. \+ \- \$ \(?: 等。
-- 说明：Lua 模式不支持分组 alternation (a|b)，此类正则不用于单测用例。
-- ============================================================================
local function pcre_to_lua(p)
    p = p:gsub("\\s", "%%s")     -- \s -> %s
    p = p:gsub("\\S", "%%S")
    p = p:gsub("\\d", "%%d")
    p = p:gsub("\\D", "%%D")
    p = p:gsub("\\w", "%%w")
    p = p:gsub("\\W", "%%W")
    p = p:gsub("\\.", "%.")      -- \. -> %.
    p = p:gsub("\\+", "+")       -- \+ -> +（Lua pattern 中 \\+ 是"一个或多个反斜杠"）
    -- 注意：不要写 p:gsub("\\-", "-")：\\- 在 Lua pattern 中是"零或多个反斜杠"，
    -- 会匹配任意位置并在全串插入 "-"；PCRE 的 \- 在 Lua 中 "-" 本身就是字面量。
    p = p:gsub("\\$", "$")       -- \$ -> $
    p = p:gsub("%(?:", "(")      -- (?: -> (
    p = p:gsub("\\b", "")        -- \b 词边界：Lua 无直接等价，测试避免使用
    return p
end

-- ============================================================================
-- 简单确定性哈希（替代 ngx.md5；仅用于验证签名校验逻辑，非真实 MD5）
-- ============================================================================
local function simple_hash(s)
    local h = 5381
    for i = 1, #s do
        h = (h * 33 + string.byte(s, i)) % 4294967296
    end
    return string.format("%08x", h)
end

-- ============================================================================
-- 共享内存 dict（lua_shared_dict 模拟，支持过期）
-- ============================================================================
local function new_dict()
    local store, expires = {}, {}
    local dict = {}
    -- 测试钩子：置 true 模拟 lua_shared_dict 写满（set 返回 nil, "no memory"）
    dict._fail_set = false
    function dict:get(k)
        local v = store[k]
        if v == nil then return nil end
        if expires[k] and expires[k] <= os.time() then
            store[k], expires[k] = nil, nil
            return nil
        end
        return v
    end
    function dict:set(k, v, exptime)
        if self._fail_set then
            return nil, "no memory"
        end
        if v == nil then
            store[k], expires[k] = nil, nil
            return true
        end
        store[k] = v
        if exptime and exptime > 0 then
            expires[k] = os.time() + exptime
        end
        return true
    end
    function dict:incr(k, step, init, exptime)
        local cur = dict:get(k)
        if cur == nil then cur = init or 0 end
        cur = cur + (step or 1)
        dict:set(k, cur, exptime)
        return cur
    end
    function dict:get_keys()
        local ks = {}
        for k in pairs(store) do ks[#ks + 1] = k end
        return ks
    end
    function dict:delete(k)
        store[k], expires[k] = nil, nil
        return true
    end
    function dict:flush_all()
        store, expires = {}, {}
        self._fail_set = false
    end
    -- 测试钩子：强制将 key 置为已过期（模拟 TTL 到期）
    function dict:_expire_at(k, ts)
        expires[k] = ts or 0
    end
    return dict
end

-- ============================================================================
-- ngx 全局
-- ============================================================================
ngx = {
    version = 0x1004006,

    -- 日志级别常量
    DEBUG = 0, INFO = 1, NOTICE = 2, WARN = 3, ERR = 4,

    -- 状态码常量
    HTTP_OK = 200, HTTP_MOVED_TEMPORARILY = 302, HTTP_FORBIDDEN = 403,

    log = function(level, ...) end,

    time = function() return os.time() end,
    now  = function() return os.time() end,

    -- 正则（PCRE → Lua 模式）
    re = {
        find = function(s, p, opts)
            if s == nil then return nil end
            local lp = pcre_to_lua(p)
            local ok, from = pcall(string.find, tostring(s), lp)
            if ok and from then
                return from, from + #s - 1
            end
            return nil
        end,
    },

    -- URL 解码
    unescape_uri = function(s)
        s = s or ""
        s = s:gsub("+", " ")
        s = s:gsub("%%(%x%x)", function(h)
            return string.char(tonumber(h, 16))
        end)
        return s
    end,

    -- 确定性伪哈希（mock ngx.md5）
    md5 = function(s) return simple_hash(tostring(s or "")) end,

    -- 共享内存
    shared = {
        waf_rule    = new_dict(),
        waf_counter = new_dict(),
    },

    -- 请求变量
    var = {
        uri = "/", request_uri = "/", http_user_agent = "Mozilla/5.0 (Test)",
        http_cookie = "", remote_addr = "1.2.3.4",
        http_x_forwarded_for = nil,
    },

    -- 请求 API
    req = {
        _method = "GET",
        _args = {},
        _post = {},
        _headers = {},
        _body = nil,
        _body_file = nil,   -- body 落临时文件路径（超过 client_body_buffer_size）
        get_method    = function() return ngx.req._method end,
        get_uri_args  = function() return ngx.req._args end,
        get_post_args = function() return ngx.req._post end,
        get_headers   = function() return ngx.req._headers end,
        read_body     = function() end,
        get_body_data = function() return ngx.req._body end,
        get_body_file = function() return ngx.req._body_file end,
    },

    -- 响应
    status = 0,
    header = {},
    exit_code = nil,
    redirect_called = nil,
    say = function(...) end,
    exit = function(code)
        ngx.exit_code = code
        error("ngx.exit(" .. tostring(code) .. ")", 0)
    end,
    redirect = function(uri, status)
        ngx.redirect_called = { uri = uri, status = status }
    end,

    -- 响应头读取（header_filter 起可用，模拟 ngx.resp.get_headers）
    resp = {
        _headers = {},
        get_headers = function() return ngx.resp._headers end,
    },

    -- 定时器（记录，不执行）
    timer = {
        _at = {},
        at = function(delay, fn, ...)
            ngx.timer._at[#ngx.timer._at + 1] = { delay = delay, fn = fn }
        end,
    },

    -- cosocket（challenge 高级模式回退用，单测不深入）
    socket = {
        tcp = function()
            return {
                connect = function() return nil, "mock socket" end,
                setTimeout = function() end,
                send = function() return nil, "mock socket" end,
                receive = function() return nil, "mock socket" end,
                close = function() end,
                set_keepalive = function() end,
            }
        end,
    },
}

-- 测试辅助：重置请求态
function ngx_reset()
    ngx.status = 0
    ngx.header = {}
    ngx.exit_code = nil
    ngx.redirect_called = nil
    ngx.resp._headers = {}
    ngx.req._method = "GET"
    ngx.req._args = {}
    ngx.req._post = {}
    ngx.req._headers = {}
    ngx.req._body = nil
    ngx.var.uri = "/"
    ngx.var.request_uri = "/"
    ngx.var.http_user_agent = "Mozilla/5.0 (Test)"
    ngx.var.http_cookie = ""
    ngx.var.remote_addr = "1.2.3.4"
    ngx.var.http_x_forwarded_for = nil
    ngx.shared.waf_rule:flush_all()
    ngx.shared.waf_counter:flush_all()
    ngx.timer._at = {}
end

return ngx
