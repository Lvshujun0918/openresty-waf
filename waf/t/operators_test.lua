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
