-- ruleset/builtin.lua
-- 内置规则集：覆盖 SQLi / XSS / RCE / LFI / SSRF / 协议异常 / 敏感文件 / 扫描器。
-- 规则字段遵循规则引擎 DSL 定义（见 rule_engine/engine.lua）：
--   id / group / phase / severity / enabled
--   vars[] / operator / pattern / transforms[] / actions
-- 后续通过管理后台下发的规则将整体覆盖此内置集。

local builtin = {
    version = "builtin-0.2.0",
    rules = {
        -- ========== 敏感文件 / 扫描器 ==========
        {
            id = "10001", group = "leak", phase = "access", severity = 2, enabled = true,
            vars = { { type = "URI" } },
            operator = "REGEX",
            pattern = [[\.(git|svn|hg)(/|$)|(^|/)(\.env|\.bash_history|\.DS_Store|config\.php\.bak|web\.config\.bak)(/|$)|\.(sql|bak|tar\.gz|zip|log)$]],
            transforms = { "url_decode", "to_lowercase" },
            actions = { disrupt = "BLOCK", status = 403, msg = "敏感文件泄露拦截" },
        },
        {
            id = "10002", group = "scanner", phase = "access", severity = 2, enabled = true,
            vars = { { type = "HEADERS", specific = "user-agent" } },
            operator = "REGEX",
            pattern = [[(sqlmap|nikto|nmap|nessus|acunetix|wpscan|masscan|zgrab|hydra|dirbuster|gobuster)]],
            transforms = { "to_lowercase" },
            actions = { disrupt = "BLOCK", status = 403, msg = "扫描器 UA 拦截" },
        },

        -- ========== SQL 注入 ==========
        {
            id = "20001", group = "sqli", phase = "access", severity = 3, enabled = true,
            vars = { { type = "URI_ARGS" }, { type = "POST_ARGS" }, { type = "BODY" } },
            operator = "REGEX",
            pattern = [[\bunion\b[\s\S]{0,100}?\bselect\b]],
            transforms = { "url_decode", "to_lowercase", "remove_comments", "compress_whitespace" },
            actions = { disrupt = "BLOCK", status = 403, msg = "SQL 注入：union select" },
        },
        {
            id = "20002", group = "sqli", phase = "access", severity = 3, enabled = true,
            vars = { { type = "URI_ARGS" }, { type = "POST_ARGS" }, { type = "BODY" } },
            operator = "REGEX",
            pattern = [[\b(sleep|benchmark|waitfor)\s*\(]],
            transforms = { "url_decode", "to_lowercase", "remove_comments" },
            actions = { disrupt = "BLOCK", status = 403, msg = "SQL 注入：延时探测" },
        },
        {
            id = "20003", group = "sqli", phase = "access", severity = 3, enabled = true,
            vars = { { type = "URI_ARGS" }, { type = "POST_ARGS" }, { type = "BODY" } },
            operator = "REGEX",
            pattern = [[\binformation_schema\b]],
            transforms = { "url_decode", "to_lowercase" },
            actions = { disrupt = "BLOCK", status = 403, msg = "SQL 注入：information_schema" },
        },
        {
            id = "20004", group = "sqli", phase = "access", severity = 3, enabled = true,
            vars = { { type = "URI_ARGS" }, { type = "POST_ARGS" }, { type = "BODY" } },
            operator = "REGEX",
            pattern = [[\b(and|or)\s+\d{1,4}\s*[=<>!]{1,2}\s*\d{1,4}]],
            transforms = { "url_decode", "to_lowercase", "remove_comments" },
            actions = { disrupt = "BLOCK", status = 403, msg = "SQL 注入：布尔盲注" },
        },
        {
            id = "20005", group = "sqli", phase = "access", severity = 3, enabled = true,
            vars = { { type = "URI_ARGS" }, { type = "POST_ARGS" }, { type = "BODY" } },
            operator = "REGEX",
            pattern = [[/\*!?\d*\s*(union|select|from|where|insert|update|delete|drop|alter|truncate|exec)]],
            transforms = { "url_decode", "to_lowercase" },
            actions = { disrupt = "BLOCK", status = 403, msg = "SQL 注入：注释混淆" },
        },
        {
            id = "20006", group = "sqli", phase = "access", severity = 3, enabled = true,
            vars = { { type = "URI_ARGS" }, { type = "POST_ARGS" }, { type = "BODY" } },
            operator = "REGEX",
            pattern = [[\b(load_file|into\s+outfile|into\s+dumpfile|into\s+loadfile)\b]],
            transforms = { "url_decode", "to_lowercase" },
            actions = { disrupt = "BLOCK", status = 403, msg = "SQL 注入：文件读写" },
        },

        -- ========== XSS ==========
        {
            id = "21001", group = "xss", phase = "access", severity = 2, enabled = true,
            vars = { { type = "URI_ARGS" }, { type = "POST_ARGS" }, { type = "BODY" } },
            operator = "REGEX",
            pattern = [[<(script|iframe|object|embed|applet)[^>]*>]],
            transforms = { "url_decode", "to_lowercase" },
            actions = { disrupt = "BLOCK", status = 403, msg = "XSS：脚本标签" },
        },
        {
            id = "21002", group = "xss", phase = "access", severity = 2, enabled = true,
            vars = { { type = "URI_ARGS" }, { type = "POST_ARGS" }, { type = "BODY" } },
            operator = "REGEX",
            pattern = [[\bon(load|error|click|mouseover|mouseout|focus|blur|change|submit|keydown|keyup)\s*=\s*['"]?[^'">]{1,200}]],
            transforms = { "url_decode", "to_lowercase" },
            actions = { disrupt = "BLOCK", status = 403, msg = "XSS：事件处理器" },
        },
        {
            id = "21003", group = "xss", phase = "access", severity = 2, enabled = true,
            vars = { { type = "URI_ARGS" }, { type = "POST_ARGS" }, { type = "BODY" } },
            operator = "REGEX",
            pattern = [[(javascript:|vbscript:|data:text/html|expression\s*\()]],
            transforms = { "url_decode", "to_lowercase" },
            actions = { disrupt = "BLOCK", status = 403, msg = "XSS：危险协议" },
        },
        {
            id = "21004", group = "xss", phase = "access", severity = 2, enabled = true,
            vars = { { type = "URI_ARGS" }, { type = "POST_ARGS" }, { type = "BODY" } },
            operator = "REGEX",
            pattern = [[\b(alert|prompt|confirm|document\.cookie|window\.location)\s*\(]],
            transforms = { "url_decode", "to_lowercase" },
            actions = { disrupt = "BLOCK", status = 403, msg = "XSS：脚本函数" },
        },

        -- ========== 命令执行 ==========
        {
            id = "22001", group = "rce", phase = "access", severity = 3, enabled = true,
            vars = { { type = "URI_ARGS" }, { type = "POST_ARGS" }, { type = "BODY" } },
            operator = "REGEX",
            pattern = [[(;|\|\||&&|`)\s*(id|whoami|pwd|uname|cat\s|ls\s|wget|curl|nc\s|bash\s|sh\s|chmod\s|kill\s|reboot|shutdown)]],
            transforms = { "url_decode", "to_lowercase" },
            actions = { disrupt = "BLOCK", status = 403, msg = "命令执行：命令拼接" },
        },
        {
            id = "22002", group = "rce", phase = "access", severity = 3, enabled = true,
            vars = { { type = "URI_ARGS" }, { type = "POST_ARGS" }, { type = "BODY" } },
            operator = "REGEX",
            pattern = [[\b(cat|tac|tail|head|more|less)\s+(/etc/passwd|/etc/shadow|/etc/hosts)]],
            transforms = { "url_decode", "to_lowercase" },
            actions = { disrupt = "BLOCK", status = 403, msg = "命令执行：读取系统文件" },
        },
        {
            id = "22003", group = "rce", phase = "access", severity = 3, enabled = true,
            vars = { { type = "URI_ARGS" }, { type = "POST_ARGS" }, { type = "BODY" } },
            operator = "REGEX",
            pattern = [[\b(system|exec|passthru|shell_exec|popen|proc_open|pcntl_exec|assert|eval)\s*\(]],
            transforms = { "url_decode", "to_lowercase" },
            actions = { disrupt = "BLOCK", status = 403, msg = "命令执行：危险函数" },
        },

        -- ========== 文件包含 / 路径穿越 ==========
        {
            id = "23001", group = "lfi", phase = "access", severity = 3, enabled = true,
            vars = { { type = "URI" }, { type = "URI_ARGS" } },
            operator = "REGEX",
            pattern = [[(\.\./|\.\.\\|%2e%2e%2f)]],
            transforms = { "url_decode", "to_lowercase" },
            actions = { disrupt = "BLOCK", status = 403, msg = "路径穿越" },
        },
        {
            id = "23002", group = "lfi", phase = "access", severity = 3, enabled = true,
            vars = { { type = "URI" }, { type = "URI_ARGS" } },
            operator = "REGEX",
            pattern = [[((^|/)etc/(passwd|shadow|group|hosts)(/|$)|(^|/)windows/(win\.ini|system32)(/|$))]],
            transforms = { "url_decode", "to_lowercase" },
            actions = { disrupt = "BLOCK", status = 403, msg = "敏感系统文件访问" },
        },
        {
            id = "23003", group = "lfi", phase = "access", severity = 3, enabled = true,
            vars = { { type = "URI_ARGS" }, { type = "POST_ARGS" } },
            operator = "REGEX",
            pattern = [[\b(file|php|zip|phar|data|expect|ftp)://]],
            transforms = { "url_decode", "to_lowercase" },
            actions = { disrupt = "BLOCK", status = 403, msg = "危险协议包装器" },
        },

        -- ========== SSRF ==========
        {
            id = "24001", group = "ssrf", phase = "access", severity = 2, enabled = true,
            vars = { { type = "URI_ARGS" }, { type = "POST_ARGS" }, { type = "BODY" } },
            operator = "REGEX",
            pattern = [[https?://(127\.0\.0\.1|localhost|0\.0\.0\.0|10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(1[6-9]|2[0-9]|3[01])\.\d{1,3}\.\d{1,3}|169\.254\.\d{1,3}\.\d{1,3})]],
            transforms = { "url_decode", "to_lowercase" },
            actions = { disrupt = "BLOCK", status = 403, msg = "SSRF：内网/本地地址" },
        },
        {
            id = "24002", group = "ssrf", phase = "access", severity = 2, enabled = true,
            vars = { { type = "URI_ARGS" }, { type = "POST_ARGS" } },
            operator = "REGEX",
            pattern = [[(169\.254\.169\.254|metadata\.google\.internal|100\.100\.100\.200)]],
            transforms = { "url_decode", "to_lowercase" },
            actions = { disrupt = "BLOCK", status = 403, msg = "SSRF：云元数据地址" },
        },

        -- ========== 协议异常 ==========
        {
            id = "25001", group = "protocol", phase = "access", severity = 2, enabled = true,
            vars = { { type = "METHOD" } },
            operator = "REGEX",
            pattern = [[^(?!(get|post|put|delete|head|options|patch|connect|trace)$).+$]],
            transforms = { "to_lowercase" },
            actions = { disrupt = "BLOCK", status = 405, msg = "非标准 HTTP 方法" },
        },
        {
            id = "25002", group = "protocol", phase = "access", severity = 2, enabled = true,
            vars = { { type = "REQUEST_URI" } },
            operator = "REGEX",
            pattern = [[.{8192,}]],
            transforms = { },
            actions = { disrupt = "BLOCK", status = 414, msg = "请求 URI 过长" },
        },
    },
}

return builtin
