package model

// SeedVersion 内置规则种子版本：版本变化时启动自动替换旧种子规则（保留用户自定义规则）。
// v2: libinjection 语义规则 + OWASP CRS 转译规则 + 基础兜底
// v3: 修复 920230/942460 对 URL 编码中文/UTF-8 中文的误报（加 url_decode transform）
// v4: 942460 pattern 限定 ASCII 特殊字符 4 连，彻底避免 UTF-8 中文误报
// v5: 新增协议异常规则 25003-25006（方法字符集/Content-Length/编码与控制字符）
const SeedVersion = "5"

// LegacySeedIDs v1 内置种子规则 ID（旧部署迁移时删除用）
var LegacySeedIDs = []string{
	"10001", "10002", "20001", "20002", "20003", "20004", "20005", "20006",
	"21001", "21002", "21003", "21004", "22001", "22002", "22003",
	"23001", "23002", "23003", "24001", "24002", "25001", "25002",
}

// SeedRules 内置规则种子：libinjection 语义检测 + 基础兜底 + OWASP CRS 转译规则
// （seed_crs.go）。首次启动时导入 Rule 表；导入后可在管理后台增删改，发布后热更新。
//
// 检测分层：
//   1. libinjection 语义规则（SQLi/XSS 词法分析，抗编码/注释绕过，需 libinjection.so）
//   2. OWASP CRS 转译规则（约 180 条正则/语义规则，覆盖 OWASP Top 10）
//   3. 基础兜底（敏感文件泄露、扫描器 UA）
var SeedRules = append(baseRules, SeedRulesCRS...)

// baseRules 基础兜底规则
var baseRules = []Rule{
	// ---- libinjection 语义检测 ----
	{RuleID: "940001", Name: "SQL 注入语义检测", Group: "sqli", Phase: "access", Severity: 3, Enabled: true,
		Operator: "LIBINJECTION_SQLI", Pattern: "",
		Transforms: `[]`, Vars: `[{"type":"URI_ARGS"},{"type":"POST_ARGS"},{"type":"BODY"}]`,
		Actions: `{"disrupt":"BLOCK","status":403,"msg":"SQL 注入语义检测"}`, Status: 403, Message: "SQL 注入语义检测", SortOrder: 1},
	{RuleID: "940002", Name: "XSS 语义检测", Group: "xss", Phase: "access", Severity: 3, Enabled: true,
		Operator: "LIBINJECTION_XSS", Pattern: "",
		Transforms: `[]`, Vars: `[{"type":"URI_ARGS"},{"type":"POST_ARGS"},{"type":"BODY"}]`,
		Actions: `{"disrupt":"BLOCK","status":403,"msg":"XSS 语义检测"}`, Status: 403, Message: "XSS 语义检测", SortOrder: 2},

	// ---- 基础兜底（非注入类，CRS 请求侧覆盖较弱） ----
	{RuleID: "10001", Name: "敏感文件泄露拦截", Group: "leak", Phase: "access", Severity: 2, Enabled: true,
		Operator: "REGEX", Pattern: `\.(git|svn|hg)(/|$)|(^|/)(\.env|\.bash_history|\.DS_Store|config\.php\.bak|web\.config\.bak)(/|$)|\.(sql|bak|tar\.gz|zip|log)$`,
		Transforms: `["url_decode","to_lowercase"]`, Vars: `[{"type":"URI"}]`,
		Actions: `{"disrupt":"BLOCK","status":403,"msg":"敏感文件泄露拦截"}`, Status: 403, Message: "敏感文件泄露拦截", SortOrder: 3},
	{RuleID: "10002", Name: "扫描器 UA 拦截", Group: "scanner", Phase: "access", Severity: 2, Enabled: true,
		Operator: "REGEX", Pattern: `(sqlmap|nikto|nmap|nessus|acunetix|wpscan|masscan|zgrab|hydra|dirbuster|gobuster)`,
		Transforms: `["to_lowercase"]`, Vars: `[{"type":"HEADERS","specific":"user-agent"}]`,
		Actions: `{"disrupt":"BLOCK","status":403,"msg":"扫描器 UA 拦截"}`, Status: 403, Message: "扫描器 UA 拦截", SortOrder: 4},

	// ---- 协议异常（方法/请求头/编码控制字符） ----
	{RuleID: "25003", Name: "HTTP 方法名非法字符", Group: "protocol", Phase: "access", Severity: 2, Enabled: true,
		Operator: "REGEX", Pattern: `[^A-Za-z0-9_-]`,
		Transforms: `[]`, Vars: `[{"type":"METHOD"}]`,
		Actions: `{"disrupt":"BLOCK","status":405,"msg":"HTTP 方法名非法字符"}`, Status: 405, Message: "HTTP 方法名非法字符", SortOrder: 5},
	{RuleID: "25004", Name: "Content-Length 非法值", Group: "protocol", Phase: "access", Severity: 2, Enabled: true,
		Operator: "REGEX", Pattern: `\D`,
		Transforms: `[]`, Vars: `[{"type":"HEADERS","specific":"content-length"}]`,
		Actions: `{"disrupt":"BLOCK","status":400,"msg":"Content-Length 非法值"}`, Status: 400, Message: "Content-Length 非法值", SortOrder: 6},
	{RuleID: "25005", Name: "URI 编码控制字符", Group: "protocol", Phase: "access", Severity: 2, Enabled: true,
		Operator: "REGEX", Pattern: `%00|%0[dD]%0[aA]`,
		Transforms: `[]`, Vars: `[{"type":"REQUEST_URI"}]`,
		Actions: `{"disrupt":"BLOCK","status":400,"msg":"URI 编码控制字符"}`, Status: 400, Message: "URI 编码控制字符", SortOrder: 7},
	{RuleID: "25006", Name: "请求头控制字符", Group: "protocol", Phase: "access", Severity: 2, Enabled: true,
		Operator: "REGEX", Pattern: `[\x00-\x08\x0B\x0C\x0E-\x1F]`,
		Transforms: `[]`, Vars: `[{"type":"HEADERS"}]`,
		Actions: `{"disrupt":"BLOCK","status":400,"msg":"请求头控制字符"}`, Status: 400, Message: "请求头控制字符", SortOrder: 8},
}
