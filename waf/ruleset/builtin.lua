-- ruleset/builtin.lua
-- 内置规则集（最小可用集）。
-- 规则字段遵循规则引擎 DSL 定义（见 rule_engine/engine.lua）：
--   id / group / phase / severity / enabled
--   vars[] / operator / pattern / transforms[] / actions
-- 后续通过管理后台下发的规则将整体覆盖此内置集。

local builtin = {
    version = "builtin-0.1.0",
    rules = {
        -- 敏感文件 / 目录泄露
        {
            id = "10001",
            group = "leak",
            phase = "access",
            severity = 2,
            enabled = true,
            vars = { { type = "URI" } },
            operator = "REGEX",
            pattern = [[\.(git|svn|hg)(/|$)|(^|/)(\.env|\.bash_history|\.DS_Store|config\.php\.bak|web\.config\.bak)(/|$)|\.(sql|bak|tar\.gz|zip|log)$]],
            transforms = { "url_decode", "to_lowercase" },
            actions = { disrupt = "BLOCK", status = 403, msg = "敏感文件泄露拦截" },
        },

        -- 示例：常见扫描器 User-Agent
        {
            id = "10002",
            group = "scanner",
            phase = "access",
            severity = 2,
            enabled = true,
            vars = { { type = "HEADERS", specific = "user-agent" } },
            operator = "REGEX",
            pattern = [[(sqlmap|nikto|nmap|nessus|acunetix|wpscan|masscan|zgrab|hydra)]],
            transforms = { "to_lowercase" },
            actions = { disrupt = "BLOCK", status = 403, msg = "扫描器 UA 拦截" },
        },
    },
}

return builtin
