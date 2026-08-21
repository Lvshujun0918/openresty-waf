-- waf/t/semantic_test.lua
-- 轻量语义分析：token 化、结构异常度评分（攻击样例得分 / 正常样例低分）

local t       = require "assert"
local sem     = require "semantic"
local ops     = require "rule_engine.operators"

t.test("tokenize 基础切分", function()
    -- 1' OR '1'='1 → num(1) str(" OR") num(1) str("=") num(1)
    local tk = sem.tokenize("1' OR '1'='1")
    local types = {}
    for _, x in ipairs(tk) do types[#types + 1] = x.type end
    t.eq(table.concat(types, ","), "num,str,num,str,num")
    -- ident 统一小写
    local tk2 = sem.tokenize("UNION Select")
    t.eq(tk2[1].value, "union")
    t.eq(tk2[2].value, "select")
    -- 注释折叠
    local tk3 = sem.tokenize("or/**/and")
    t.eq(#tk3, 3)
    t.eq(tk3[2].type, "comment")
end)

t.test("SQL 恒真结构得分", function()
    local score = sem.anomaly("1' OR '1'='1")
    t.ok(score >= 35, "score=" .. score)
    local s2 = sem.anomaly("admin' AND 'x'='x")
    t.ok(s2 >= 35, "score=" .. s2)
end)

t.test("SQL union select 词序与堆叠", function()
    t.ok(sem.anomaly("1 UNION SELECT user,password FROM users") >= 30)
    t.ok(sem.anomaly("1;DROP TABLE users") >= 30)
    -- 注释切断绕过仍命中
    t.ok(sem.anomaly("uni/**/on se/**/lect") >= 25)
end)

t.test("XSS 结构得分", function()
    t.ok(sem.anomaly("javascript:alert(1)") >= 30)
    t.ok(sem.anomaly("<img src=x onerror=alert(1)>") >= 20)
    t.ok(sem.anomaly("<svg onload=alert(1)>") >= 20)
end)

t.test("命令注入结构得分", function()
    t.ok(sem.anomaly("$(whoami)") >= 25)
    t.ok(sem.anomaly("; cat /etc/passwd") >= 35)
    t.ok(sem.anomaly("`id`") >= 25)
end)

t.test("模板注入结构得分", function()
    t.ok(sem.anomaly("{{7*7}}") >= 25)
    t.ok(sem.anomaly("${jndi:ldap://x}") >= 25)
end)

t.test("正常文本零分或低分", function()
    -- 英文句子：单词出现不构成结构
    t.ok(sem.anomaly("the union leaders select their representatives from workers") < 35)
    t.ok(sem.anomaly("please select a few items from the list and update your profile") < 35)
    -- 中文与 URL 编码中文
    t.ok(sem.anomaly("对订单进行更新操作") == 0)
    t.ok(sem.anomaly("%E5%AF%B9%E8%AE%A2%E5%8D%95") < 35)
    -- JSON / base64 / 版本号
    t.ok(sem.anomaly('{"user_id":123,"name":"tom"}') < 35)
    t.ok(sem.anomaly("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9") == 0)
    t.ok(sem.anomaly("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36") < 35)
    -- 普通查询参数
    t.ok(sem.anomaly("page=2&size=20&sort=created_at desc") < 35)
end)

t.test("SEMANTIC_ANOMALY 运算符阈值判定", function()
    t.ok(ops.eval("SEMANTIC_ANOMALY", "1' OR '1'='1", "35"))
    t.no(ops.eval("SEMANTIC_ANOMALY", "hello world", "35"))
    -- 非法阈值不命中
    t.no(ops.eval("SEMANTIC_ANOMALY", "1' OR '1'='1", "abc"))
    -- JSON 体逐值评分：攻击值在深层也命中，干净 JSON 不误报
    t.ok(ops.eval("SEMANTIC_ANOMALY", '{"comment":"x\' OR \'1\'=\'1","id":1}', "35"))
    t.no(ops.eval("SEMANTIC_ANOMALY", '{"comment":"nice post","id":1}', "35"))
    -- 空值安全
    t.no(ops.eval("SEMANTIC_ANOMALY", "", "35"))
end)
