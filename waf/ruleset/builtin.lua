-- ruleset/builtin.lua
-- 内置规则集：覆盖 SQLi / XSS / RCE / LFI / SSRF / 协议异常 / 敏感文件 / 扫描器。
-- 规则字段遵循规则引擎 DSL 定义（见 rule_engine/engine.lua）：
--   id / group / phase / severity / enabled
--   vars[] / operator / pattern / transforms[] / actions
-- 后续通过管理后台下发的规则将整体覆盖此内置集。

local builtin = {
    version = "builtin-0.6.1",
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

        -- ========== 语义检测（libinjection 词法分析，需 libinjection.so；
        --             .so 缺失时自动降级为不匹配，不影响其余规则） ==========
        {
            id = "940001", group = "sqli", phase = "access", severity = 3, enabled = true,
            vars = { { type = "URI_ARGS" }, { type = "POST_ARGS" }, { type = "BODY" } },
            operator = "LIBINJECTION_SQLI",
            pattern = "",
            transforms = { "url_decode" },
            actions = { disrupt = "BLOCK", status = 403, msg = "SQL 注入语义检测" },
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
        {
            id = "25003", group = "protocol", phase = "access", severity = 2, enabled = true,
            vars = { { type = "METHOD" } },
            operator = "REGEX",
            pattern = "[^A-Za-z0-9_-]",
            transforms = { },
            actions = { disrupt = "BLOCK", status = 405, msg = "HTTP 方法名非法字符" },
        },
        {
            id = "25004", group = "protocol", phase = "access", severity = 2, enabled = true,
            vars = { { type = "HEADERS", specific = "content-length" } },
            operator = "REGEX",
            pattern = [[\D]],
            transforms = { },
            actions = { disrupt = "BLOCK", status = 400, msg = "Content-Length 非法值" },
        },
        {
            id = "25005", group = "protocol", phase = "access", severity = 2, enabled = true,
            vars = { { type = "REQUEST_URI" } },
            operator = "REGEX",
            pattern = "%00|%0[dD]%0[aA]",
            transforms = { },
            actions = { disrupt = "BLOCK", status = 400, msg = "URI 编码控制字符" },
        },
        {
            id = "25006", group = "protocol", phase = "access", severity = 2, enabled = true,
            vars = { { type = "HEADERS" } },
            operator = "REGEX",
            pattern = "[\x00-\x08\x0B\x0C\x0E-\x1F]",
            transforms = { },
            actions = { disrupt = "BLOCK", status = 400, msg = "请求头控制字符" },
        },
        {
            id = "25007", group = "protocol", phase = "access", severity = 2, enabled = true,
            vars = { { type = "HEADERS_COUNT" } },
            operator = "REGEX",
            pattern = [[\d\d\d]],
            transforms = { },
            actions = { disrupt = "BLOCK", status = 400, msg = "请求头数量异常（>=100 个）" },
        },
        {
            id = "25008", group = "protocol", phase = "access", severity = 2, enabled = true,
            vars = { { type = "ARGS_COUNT" } },
            operator = "REGEX",
            pattern = [[\d\d\d]],
            transforms = { },
            actions = { disrupt = "BLOCK", status = 400, msg = "请求参数数量异常（>=100 个）" },
        },

        -- ========== HPP 参数污染（默认仅监控；多参数提交业务差异大，先记录观察） ==========
        {
            id = "27001", group = "hpp", phase = "access", severity = 2, enabled = true,
            vars = { { type = "URI_ARGS_DUP" } },
            operator = "EXISTS",
            pattern = "",
            transforms = { },
            actions = { disrupt = "LOG_ONLY", msg = "HPP：URI 重复参数（同参数多值提交）" },
        },
        {
            id = "27002", group = "hpp", phase = "access", severity = 2, enabled = true,
            vars = { { type = "POST_ARGS_DUP" } },
            operator = "EXISTS",
            pattern = "",
            transforms = { },
            actions = { disrupt = "LOG_ONLY", msg = "HPP：POST 重复参数（同参数多值提交）" },
        },

        -- ========== API 安全 ==========
        {
            id = "27010", group = "api", phase = "access", severity = 2, enabled = true,
            vars = { { type = "URI" } },
            operator = "REGEX",
            pattern = [[(swagger|openapi\.json|api-docs|actuator|phpinfo|phpmyadmin|debug/pprof|server-status|docker\.sock)]],
            transforms = { "url_decode", "to_lowercase" },
            actions = { disrupt = "BLOCK", status = 403, msg = "API 安全：敏感端点/调试接口暴露" },
        },
        {
            id = "27011", group = "api", phase = "access", severity = 1, enabled = true,
            vars = { { type = "URI_ARGS" }, { type = "POST_ARGS" }, { type = "BODY" } },
            operator = "REGEX",
            pattern = [[(__schema|__type|introspection)]],
            transforms = { "url_decode", "to_lowercase" },
            actions = { disrupt = "LOG_ONLY", msg = "API 安全：GraphQL 内省查询" },
        },
        {
            id = "27012", group = "api", phase = "access", severity = 3, enabled = true,
            vars = { { type = "BODY" } },
            operator = "REGEX",
            pattern = [[<!DOCTYPE[^>]*(ENTITY|SYSTEM|PUBLIC)]],
            transforms = { "to_lowercase" },
            actions = { disrupt = "BLOCK", status = 403, msg = "API 安全：XML 外部实体（XXE）" },
        },

        -- ========== 编码混淆绕过（base64 载荷） ==========
        {
            id = "27013", group = "obfuscation", phase = "access", severity = 3, enabled = true,
            vars = { { type = "URI_ARGS" }, { type = "POST_ARGS" }, { type = "BODY" } },
            operator = "REGEX",
            pattern = [[\b(union|select|sleep|information_schema)\b|<script|javascript:]],
            transforms = { "base64_decode", "to_lowercase" },
            actions = { disrupt = "BLOCK", status = 403, msg = "编码混淆：base64 载荷攻击" },
        },

        -- ========== 爬虫/客户端指纹（默认仅监控；策略可用触发规则 kind=exempt/block/challenge 分级） ==========
        {
            id = "28001", group = "crawler", phase = "access", severity = 1, enabled = true,
            vars = { { type = "HEADERS", specific = "user-agent" } },
            operator = "PM",
            pattern = [[googlebot|bingbot|baiduspider|sogou|360spider|yisouspider|shenma|duckduckbot|applebot|slurp|ia_archiver]],
            transforms = { "to_lowercase" },
            actions = { disrupt = "LOG_ONLY", msg = "爬虫指纹：已知搜索引擎爬虫" },
        },
        {
            id = "28002", group = "crawler", phase = "access", severity = 2, enabled = true,
            vars = { { type = "USER_AGENT" } },
            operator = "REGEX",
            pattern = [[^$]],
            transforms = { },
            actions = { disrupt = "LOG_ONLY", msg = "爬虫指纹：空 User-Agent" },
        },
        {
            id = "28003", group = "crawler", phase = "access", severity = 2, enabled = true,
            vars = { { type = "HEADERS", specific = "user-agent" } },
            operator = "PM",
            pattern = [[python-requests|go-http-client|okhttp|curl/|wget/|scrapy|apache-httpclient|node-fetch|axios|libwww-perl]],
            transforms = { "to_lowercase" },
            actions = { disrupt = "LOG_ONLY", msg = "爬虫指纹：HTTP 客户端库 UA" },
        },
        {
            id = "28004", group = "crawler", phase = "access", severity = 1, enabled = true,
            vars = { { type = "HEADERS", specific = "user-agent" } },
            operator = "PM",
            pattern = [[uptimerobot|uptime-kuma|pingdom|statuscake|monitoring|datadog-agent|healthchecks]],
            transforms = { "to_lowercase" },
            actions = { disrupt = "LOG_ONLY", msg = "爬虫指纹：监控探针" },
        },

        -- ========== 响应检测（默认仅监控 LOG_ONLY，可在后台改为 BLOCK 拦截） ==========
        {
            id = "26001", group = "response", phase = "body_filter", severity = 2, enabled = true,
            vars = { { type = "RESPONSE_BODY" } },
            operator = "REGEX",
            pattern = [[(ORA-[0-9]+|SQLSTATE\s*\[|mysql_fetch_|Fatal error:|Parse error:|Traceback \(most recent call last\)|syntax error, unexpected)]],
            transforms = { },
            actions = { disrupt = "LOG_ONLY", msg = "响应体泄露：错误堆栈/数据库报错" },
        },
        {
            id = "26002", group = "response", phase = "header_filter", severity = 1, enabled = true,
            vars = { { type = "RESPONSE_HEADERS", specific = "x-powered-by" } },
            operator = "EXISTS",
            pattern = "",
            transforms = { },
            actions = { disrupt = "LOG_ONLY", msg = "响应头泄露：X-Powered-By 版本信息" },
        },

        -- ========== DLP 敏感数据防泄露（默认仅监控 LOG_ONLY） ==========
        {
            id = "26010", group = "dlp", phase = "body_filter", severity = 3, enabled = true,
            vars = { { type = "RESPONSE_BODY" } },
            operator = "REGEX",
            pattern = [==[[1-9]\d{5}(18|19|20)\d{2}(0[1-9]|1[0-2])(0[1-9]|[12]\d|3[01])\d{3}[\dXx]]==],
            transforms = { },
            actions = { disrupt = "LOG_ONLY", msg = "DLP：响应体疑似泄露身份证号码" },
        },
        {
            id = "26011", group = "dlp", phase = "body_filter", severity = 3, enabled = true,
            vars = { { type = "RESPONSE_BODY" } },
            operator = "REGEX",
            pattern = [==[\b(62[0-9]{14,17}|[3-6][0-9]{15,18})\b]==],
            transforms = { },
            actions = { disrupt = "LOG_ONLY", msg = "DLP：响应体疑似泄露银行卡号" },
        },
        {
            id = "26012", group = "dlp", phase = "body_filter", severity = 2, enabled = true,
            vars = { { type = "RESPONSE_BODY" } },
            operator = "REGEX",
            pattern = [[1[3-9]\d{9}]],
            transforms = { },
            actions = { disrupt = "LOG_ONLY", msg = "DLP：响应体疑似泄露手机号" },
        },
        {
            id = "26013", group = "dlp", phase = "body_filter", severity = 3, enabled = true,
            vars = { { type = "RESPONSE_BODY" } },
            operator = "REGEX",
            pattern = [==[-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----]==],
            transforms = { },
            actions = { disrupt = "LOG_ONLY", msg = "DLP：响应体疑似泄露私钥" },
        },
        {
            id = "26014", group = "dlp", phase = "body_filter", severity = 3, enabled = true,
            vars = { { type = "RESPONSE_BODY" } },
            operator = "REGEX",
            pattern = [==[(AKIA[0-9A-Z]{16}|AIza[0-9A-Za-z_-]{35}|ghp_[0-9A-Za-z]{36}|sk-[0-9A-Za-z]{20,}|xox[baprs]-[0-9A-Za-z-]{10,})]==],
            transforms = { },
            actions = { disrupt = "LOG_ONLY", msg = "DLP：响应体疑似泄露云服务密钥/令牌" },
        },
    },
}

return builtin
