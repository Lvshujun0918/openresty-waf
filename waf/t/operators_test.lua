-- waf/t/operators_test.lua
-- rule_engine/operators 运算符单测

local t = require "assert"
local operators = require "rule_engine.operators"

t.test("REGEX: 命中", function()
    t.ok(operators.eval("REGEX", "union select", "union%s+select"))
end)

t.test("REGEX: 未命中", function()
    t.no(operators.eval("REGEX", "hello world", "union%s+select"))
end)

t.test("REGEX: nil 值不匹配", function()
    t.no(operators.eval("REGEX", nil, ".*"))
end)

t.test("REGEX: 转义点号", function()
    t.ok(operators.eval("REGEX", "/.git/config", "%.git"))
    t.no(operators.eval("REGEX", "/agit/config", "%.git"))
end)

t.test("REGEX: 非法正则返回 false 不抛错", function()
    -- mock 转换后 [ 未闭合 → string.find 报错，eval 应吞掉返回 false
    t.no(operators.eval("REGEX", "abc", "["))
end)

t.test("EQUALS: 相等", function()
    t.ok(operators.eval("EQUALS", "GET", "GET"))
    t.no(operators.eval("EQUALS", "POST", "GET"))
    t.no(operators.eval("EQUALS", nil, "GET"))
end)

t.test("CONTAINS: 子串", function()
    t.ok(operators.eval("CONTAINS", "select * from users", "from"))
    t.no(operators.eval("CONTAINS", "select", "union"))
    t.no(operators.eval("CONTAINS", nil, "x"))
end)

t.test("PM: 词组任一命中（忽略大小写）", function()
    t.ok(operators.eval("PM", "sqlmap detected", "nikto|sqlmap|nmap"))
    t.ok(operators.eval("PM", "SQLMAP detected", "nikto|sqlmap|nmap"))
    t.no(operators.eval("PM", "curl", "nikto|sqlmap|nmap"))
    t.no(operators.eval("PM", nil, "x|y"))
end)

t.test("CIDR: 精确 IP", function()
    t.ok(operators.eval("CIDR", "192.168.1.1", "192.168.1.1"))
    t.no(operators.eval("CIDR", "192.168.1.2", "192.168.1.1"))
end)

t.test("CIDR: 网段命中", function()
    t.ok(operators.eval("CIDR", "192.168.1.55", "192.168.1.0/24"))
    t.ok(operators.eval("CIDR", "10.0.0.1", "10.0.0.0/8"))
    t.no(operators.eval("CIDR", "192.168.2.55", "192.168.1.0/24"))
end)

t.test("CIDR: /32 与 /0 边界", function()
    t.ok(operators.eval("CIDR", "8.8.8.8", "8.8.8.8/32"))
    t.no(operators.eval("CIDR", "8.8.4.4", "8.8.8.8/32"))
    t.ok(operators.eval("CIDR", "1.2.3.4", "0.0.0.0/0"))
end)

t.test("CIDR: 非法输入不匹配", function()
    t.no(operators.eval("CIDR", "not-an-ip", "10.0.0.0/8"))
    t.no(operators.eval("CIDR", nil, "10.0.0.0/8"))
    t.no(operators.eval("CIDR", "256.1.1.1", "10.0.0.0/8"))
end)

t.test("STARTS_WITH: 前缀", function()
    t.ok(operators.eval("STARTS_WITH", "/admin/login", "/admin"))
    t.no(operators.eval("STARTS_WITH", "/user/login", "/admin"))
    t.no(operators.eval("STARTS_WITH", nil, "/admin"))
end)

t.test("ENDS_WITH: 后缀", function()
    t.ok(operators.eval("ENDS_WITH", "file.php", ".php"))
    t.no(operators.eval("ENDS_WITH", "file.aspx", ".php"))
end)

t.test("EXISTS: 存在性", function()
    t.ok(operators.eval("EXISTS", "x"))
    t.ok(operators.eval("EXISTS", 0))
    t.no(operators.eval("EXISTS", ""))
    t.no(operators.eval("EXISTS", nil))
end)

t.test("eval: 未知运算符返回 false", function()
    t.no(operators.eval("NO_SUCH_OP", "x", "y"))
end)

t.test("is_valid: 校验运算符", function()
    t.ok(operators.is_valid("REGEX"))
    t.ok(operators.is_valid("CIDR"))
    t.no(operators.is_valid("FOO"))
end)

-- ============ libinjection 语义检测 ============

t.test("LIBINJECTION: .so 缺失时降级为不匹配", function()
    package.loaded["libinjection_ffi"] = nil
    package.preload["libinjection_ffi"] = nil
    t.no(operators.eval("LIBINJECTION_SQLI", "1 or 1=1"))
    t.no(operators.eval("LIBINJECTION_XSS", "<script>alert(1)</script>"))
end)

t.test("LIBINJECTION: 可用时按语义结果匹配", function()
    package.loaded["libinjection_ffi"] = nil
    package.preload["libinjection_ffi"] = function()
        return {
            available = true,
            is_sqli = function(s)
                if s == nil then return false end
                return string.find(s, "or 1=1", 1, true) ~= nil
            end,
            is_xss = function(s)
                if s == nil then return false end
                return string.find(s, "<script>", 1, true) ~= nil
            end,
        }
    end
    t.ok(operators.eval("LIBINJECTION_SQLI", "1 or 1=1"))
    t.no(operators.eval("LIBINJECTION_SQLI", "hello"))
    t.ok(operators.eval("LIBINJECTION_XSS", "<script>alert(1)</script>"))
    t.no(operators.eval("LIBINJECTION_XSS", "hello"))
    -- nil 输入不匹配
    t.no(operators.eval("LIBINJECTION_SQLI", nil))
    package.loaded["libinjection_ffi"] = nil
    package.preload["libinjection_ffi"] = nil
end)

t.test("LIBINJECTION: JSON 结构化只检测字段值", function()
    package.loaded["libinjection_ffi"] = nil
    package.preload["libinjection_ffi"] = function()
        return {
            available = true,
            is_sqli = function(s)
                if s == nil then return false end
                return string.find(tostring(s), "union", 1, true) ~= nil
            end,
            is_xss = function(s)
                if s == nil then return false end
                return string.find(tostring(s), "<script>", 1, true) ~= nil
            end,
        }
    end
    -- JSON 语法（引号/冒号/字段名）不误报
    t.no(operators.eval("LIBINJECTION_SQLI", '{"email":"x@163.com","password":"hello","image_captcha_id":"61945958-3ec8-4d50-8e04-c24153cdd87c"}'))
    -- 字段值含注入特征 → 命中
    t.ok(operators.eval("LIBINJECTION_SQLI", '{"q":"1 union select 2"}'))
    t.ok(operators.eval("LIBINJECTION_XSS", '{"q":"<script>alert(1)</script>"}'))
    -- 非 JSON 原样检测
    t.ok(operators.eval("LIBINJECTION_SQLI", "1 union select 2"))
    package.loaded["libinjection_ffi"] = nil
    package.preload["libinjection_ffi"] = nil
end)

t.test("is_valid: 语义运算符有效", function()
    t.ok(operators.is_valid("LIBINJECTION_SQLI"))
    t.ok(operators.is_valid("LIBINJECTION_XSS"))
end)

-- ========== IPv6 CIDR ==========

t.test("CIDR IPv6: 精确匹配与网段", function()
    t.ok(operators.eval("CIDR", "2001:db8::1", "2001:db8::1"))
    t.ok(operators.eval("CIDR", "2001:db8::1", "2001:db8::/32"))
    t.ok(operators.eval("CIDR", "2001:db8:abcd::1", "2001:db8::/32"))
    t.ok(operators.eval("CIDR", "::1", "::1/128"))
    t.ok(operators.eval("CIDR", "::1", "::/0"))
end)

t.test("CIDR IPv6: 不匹配网段", function()
    t.no(operators.eval("CIDR", "2001:db9::1", "2001:db8::/32"))
    t.no(operators.eval("CIDR", "::1", "::2/128"))
    t.no(operators.eval("CIDR", "::1", "2001:db8::/64"))
end)

t.test("CIDR IPv6: 压缩形式与 IPv4 尾段", function()
    -- 全写形式与 :: 压缩形式语义等价（/128 比较）
    t.ok(operators.eval("CIDR", "2001:db8::1", "2001:0db8:0000:0000:0000:0000:0000:0001/128"))
    t.ok(operators.eval("CIDR", "2001:db8::1", "2001:db8:0:0:0:0:0:1/128"))
    -- IPv4 尾段映射（::ffff:192.0.2.1）
    t.ok(operators.eval("CIDR", "::ffff:192.0.2.1", "::ffff:192.0.2.0/120"))
    t.no(operators.eval("CIDR", "::ffff:192.0.2.9", "::ffff:192.0.2.0/125"))
end)

t.test("CIDR IPv6: 非法输入不匹配", function()
    t.no(operators.eval("CIDR", "not-an-ip", "2001:db8::/32"))
    t.no(operators.eval("CIDR", "2001:db8::1", "gggg::/32"))
    t.no(operators.eval("CIDR", "2001:db8::1", "2001:db8::/129"))
end)

t.test("REGEX: 超长 pattern 护栏直接不匹配", function()
    local long = string.rep("a", 32769)
    t.no(operators.eval("REGEX", "aaa", long), "超过 32KB 的 pattern 不执行匹配")
    t.ok(operators.eval("REGEX", "aaa", "aaa"), "正常长度不受影响")
end)

t.test("CIDR IPv6: 前缀边界", function()
    t.ok(operators.eval("CIDR", "fe80::1", "fe80::/10"))
    t.no(operators.eval("CIDR", "ff02::1", "fe80::/10"))
    t.ok(operators.eval("CIDR", "2001:db8::12", "2001:db8::/120"))
    t.no(operators.eval("CIDR", "2001:db8::abcd", "2001:db8::/120"))
    t.ok(operators.eval("CIDR", "2001:db8::1", "2001:db8::/126"))
    t.no(operators.eval("CIDR", "2001:db8::abce", "2001:db8::/126"))
end)
