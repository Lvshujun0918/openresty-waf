-- semantic.lua — 轻量语义分析：词法 token 化 + 结构异常度评分（纯 Lua，无外部依赖）
--
-- 设计定位：libinjection（C 库强特征）之下的第二层语义网。
--   - libinjection 布尔判定精准但覆盖面有限（SQLi/XSS 两类）；
--   - 本模块把输入切分为 token 序列后做「结构级」异常判定，
--     抗注释插入/大小写/空白变形（正则难以稳定表达的结构模式），
--     输出 0-100 异常分，经 SEMANTIC_ANOMALY 运算符接入 SCORE 弱特征体系。
--
-- 防误报原则（blazehttp 六轮校准教训）：
--   - 只认 token 序列结构组合，不认单词出现（"select a few items from" 零分）；
--   - 不做 URL 编码连片等高频正常特征（中文参数必然 %XX 连片）；
--   - 单值分数封顶 100，规则侧默认 SCORE 弱特征叠加，不直接拦截。

local _M = {}

-- SQL 关键字表（小写）：用于词序结构与密度统计
local SQL_KEYWORDS = {
    select = true, union = true, insert = true, update = true, delete = true,
    drop = true, from = true, where = true, table = true, database = true,
    schema = true, information_schema = true, sleep = true, benchmark = true,
    concat = true, substring = true, ascii = true, hex = true, unhex = true,
    load_file = true, outfile = true, declare = true, exec = true,
    execute = true, truncate = true, alter = true, create = true,
    waitfor = true, pg_sleep = true, updatexml = true, extractvalue = true,
}

-- 分号/管道后接续的高危动词（堆叠查询/命令拼接）
local STACK_VERBS = {
    drop = true, delete = true, truncate = true, insert = true, update = true,
    exec = true, execute = true, shutdown = true, declare = true,
}
local CMD_WORDS = {
    cat = true, ls = true, id = true, whoami = true, uname = true,
    wget = true, curl = true, nc = true, bash = true, sh = true,
    pwd = true, ifconfig = true, netstat = true, python = true,
    perl = true, php = true, chmod = true, rm = true,
}

-- 已知 DOM 事件名（on<event>= 结构判定，避免 on 前缀普通单词误报）
local DOM_EVENTS = {
    load = true, error = true, click = true, mouseover = true, mouseout = true,
    focus = true, blur = true, submit = true, change = true, keydown = true,
    keyup = true, keypress = true, input = true, abort = true, unload = true,
    dblclick = true, mousedown = true, mouseup = true, touchstart = true,
    pointerover = true, animationstart = true, transitionend = true,
    toggle = true, play = true, seeking = true, scroll = true, wheel = true,
}

local DANGER_TAGS = {
    script = true, iframe = true, svg = true, embed = true,
    object = true, img = true, body = true, style = true,
}

-- 分析输入上限（字节）：超长部分不参与分析（正常参数极少超过此值）
local MAX_INPUT = 8192

-- 词法切分：返回 { {type=..., value=..., quote=...}, ... }
-- type: str / comment / ident / num / op（空白折叠丢弃）
-- ident 统一小写化；str 记录原始内容与引号类型（反引号单独计分）
function _M.tokenize(s)
    local tokens = {}
    local i, n = 1, #s
    while i <= n do
        local c = s:sub(i, i)
        if c:match("^%s$") then
            i = i + 1
        elseif c == "'" or c == '"' or c == "`" then
            -- 字符串字面量：容忍未闭合（攻击载荷常故意不闭合引号）
            local q = c
            local j = i + 1
            while j <= n do
                local cj = s:sub(j, j)
                if cj == "\\" and j < n then
                    j = j + 2
                elseif cj == q then
                    break
                else
                    j = j + 1
                end
            end
            if j > n then j = n + 1 end
            tokens[#tokens + 1] = { type = "str", value = s:sub(i + 1, j - 1), quote = q }
            i = j + (j <= n and 1 or 0)
        elseif s:sub(i, i + 1) == "--" then
            tokens[#tokens + 1] = { type = "comment", value = "--" }
            i = n + 1
        elseif s:sub(i, i + 1) == "/*" then
            local close = s:find("*/", i + 2, true)
            tokens[#tokens + 1] = { type = "comment", value = "/*" }
            i = close and (close + 2) or (n + 1)
        elseif c == "#" then
            tokens[#tokens + 1] = { type = "comment", value = "#" }
            i = n + 1
        elseif c:match("^[%a_]$") then
            local j = i + 1
            while j <= n and s:sub(j, j):match("^[%w_]$") do j = j + 1 end
            tokens[#tokens + 1] = { type = "ident", value = s:sub(i, j - 1):lower() }
            i = j
        elseif c:match("^%d$") then
            local j = i + 1
            while j <= n and s:sub(j, j):match("^[%w%.]$") do j = j + 1 end
            tokens[#tokens + 1] = { type = "num", value = s:sub(i, j - 1):lower() }
            i = j
        else
            tokens[#tokens + 1] = { type = "op", value = c }
            i = i + 1
        end
    end
    return tokens
end

-- 下一个非 comment token 下标（无则 nil）
local function next_solid(tokens, i)
    for j = i + 1, #tokens do
        if tokens[j].type ~= "comment" then return j end
    end
    return nil
end

-- 结构异常度评分：返回 score(0-100), reasons(table)
function _M.anomaly(s)
    if s == nil or s == "" then return 0, {} end
    s = tostring(s)
    if #s > MAX_INPUT then s = s:sub(1, MAX_INPUT) end

    local tokens = _M.tokenize(s)
    local score, reasons = 0, {}
    local function add(pts, name)
        score = score + pts
        reasons[#reasons + 1] = name
    end

    local kw_seen = {}

    for i = 1, #tokens do
        local t = tokens[i]

        -- 记录 SQL 关键字（密度统计用）
        if t.type == "ident" and SQL_KEYWORDS[t.value] then
            kw_seen[t.value] = true
        end

        -- [SQL] 恒真结构：str + (or|and) + str/num，或 str + (=) + str/num
        --   ' OR '1'='1  /  " AND ""="  /  x'='y'
        if t.type == "str" then
            local j = next_solid(tokens, i)
            local nj = j and next_solid(tokens, j)
            if j and nj then
                local mid, tail = tokens[j], tokens[nj]
                if mid.type == "ident" and (mid.value == "or" or mid.value == "and")
                    and (tail.type == "str" or tail.type == "num") then
                    add(35, "sql_tautology")
                elseif mid.type == "op" and mid.value == "="
                    and (tail.type == "str" or tail.type == "num") then
                    add(30, "sql_tautology_eq")
                end
            end
            -- [SQL] 引号间逻辑连接：str 值整体恰为 or/and（' OR ' 闭合再开启形态）
            --   1' OR '1'='1 → num, str(" OR"), num, str("="), num
            local inner = t.value:lower():match("^%s*(%a+)%s*$")
            if (inner == "or" or inner == "and") then
                local prev = nil
                for k = i - 1, 1, -1 do
                    if tokens[k].type ~= "comment" then prev = tokens[k] break end
                end
                local nj2 = next_solid(tokens, i)
                local nxt = nj2 and tokens[nj2] or nil
                -- nxt 含 ident：'x' 的开引号常被上一串当闭合消费，x 退化为裸标识符
                -- （admin' AND 'x'='x / black'or'white 均为此形态）
                if prev and nxt and (prev.type == "str" or prev.type == "num" or prev.type == "ident")
                    and (nxt.type == "str" or nxt.type == "num" or nxt.type == "ident") then
                    add(35, "sql_quote_logic")
                end
            end
        end

        -- [SQL] or/and + num(=)num 数值恒真：or 1=1
        if t.type == "ident" and (t.value == "or" or t.value == "and") then
            local j = next_solid(tokens, i)
            local k = j and next_solid(tokens, j)
            local m = k and next_solid(tokens, k)
            local l = m and next_solid(tokens, m)
            if j and k and m and l
                and tokens[j].type == "num"
                and tokens[k].type == "op" and tokens[k].value == "="
                and tokens[m].type == "num"
                and not (tokens[l].type == "ident" and not SQL_KEYWORDS[tokens[l].value]) then
                add(30, "sql_tautology_num")
            end
        end

        -- [SQL] union ... select 词序（≤3 token 距离，跨注释/括号仍命中）
        if t.type == "ident" and t.value == "union" then
            local j = i
            for _ = 1, 3 do
                j = next_solid(tokens, j)
                if not j then break end
                if tokens[j].type == "ident" and tokens[j].value == "select" then
                    add(30, "sql_union_select")
                    break
                end
                if tokens[j].type ~= "comment" and tokens[j].type ~= "op" then break end
            end
        end

        -- [SQL] 分号堆叠：; drop/delete/insert/...
        if t.type == "op" and t.value == ";" then
            local j = next_solid(tokens, i)
            if j and tokens[j].type == "ident" and STACK_VERBS[tokens[j].value] then
                add(30, "sql_stacked_query")
            end
        end

        -- [SQL] 注释切断绕过：uni/**/on、se/**/lect —— 注释两侧 ident 碎片
        -- 拼接后构成 SQL 关键字（正则难以稳定表达的变形结构）
        if t.type == "comment" then
            local prev, nxt = nil, nil
            for k = i - 1, 1, -1 do
                if tokens[k].type ~= "comment" then prev = tokens[k] break end
            end
            for k = i + 1, #tokens do
                if tokens[k].type ~= "comment" then nxt = tokens[k] break end
            end
            if prev and nxt and prev.type == "ident" and nxt.type == "ident"
                and SQL_KEYWORDS[prev.value .. nxt.value] then
                add(25, "sql_comment_split")
            end
        end

        -- [XSS] 协议头：javascript: / vbscript:
        if t.type == "ident" and (t.value == "javascript" or t.value == "vbscript") then
            local j = next_solid(tokens, i)
            if j and tokens[j].type == "op" and tokens[j].value == ":" then
                add(30, "xss_protocol")
            end
        end

        -- [XSS] 事件属性：on<event>=
        if t.type == "ident" and t.value:match("^on%a%a+$") and DOM_EVENTS[t.value:sub(3)] then
            local j = next_solid(tokens, i)
            if j and tokens[j].type == "op" and tokens[j].value == "=" then
                add(25, "xss_event_handler")
            end
        end

        -- [XSS] 危险标签开头：<script / <iframe / <svg ...
        if t.type == "op" and t.value == "<" then
            local j = next_solid(tokens, i)
            if j and tokens[j].type == "ident" and DANGER_TAGS[tokens[j].value] then
                add(20, "xss_dangerous_tag")
            end
        end

        -- [RCE] 命令替换：$( 、反引号字符串
        if t.type == "op" and t.value == "$" then
            local j = next_solid(tokens, i)
            if j and tokens[j].type == "op" and tokens[j].value == "(" then
                add(25, "cmd_substitution")
            end
        end
        if t.type == "str" and t.quote == "`" then
            add(25, "cmd_backtick")
        end

        -- [RCE] 分隔符命令词：; cat / | whoami / ;wget
        if t.type == "op" and (t.value == ";" or t.value == "|") then
            local j = next_solid(tokens, i)
            if j and tokens[j].type == "ident" and CMD_WORDS[tokens[j].value] then
                add(35, "cmd_separator_word")
            end
        end

        -- [模板注入] {{ }} / ${ } / <% %>
        if t.type == "op" then
            local j = next_solid(tokens, i)
            if j and tokens[j].type == "op" then
                local pair = t.value .. tokens[j].value
                if pair == "{{" or pair == "${" or pair == "<%" then
                    add(25, "template_expression")
                end
            end
        end
    end

    -- [SQL] 关键字密度：同值内多个不同 SQL 关键字
    local kw_n = 0
    for _ in pairs(kw_seen) do kw_n = kw_n + 1 end
    if kw_n >= 7 then
        add(30, "sql_keyword_density")
    elseif kw_n >= 4 then
        add(20, "sql_keyword_density")
    end

    if score > 100 then score = 100 end
    return score, reasons
end

return _M
