package model

// SeedVersion 内置规则种子版本：版本变化时启动自动替换旧种子规则（保留用户自定义规则）。
// v2: libinjection 语义规则 + OWASP CRS 转译规则 + 基础兜底
// v3: 修复 920230/942460 对 URL 编码中文/UTF-8 中文的误报（加 url_decode transform）
// v4: 942460 pattern 限定 ASCII 特殊字符 4 连，彻底避免 UTF-8 中文误报
// v5: 新增协议异常规则 25003-25006（方法字符集/Content-Length/编码与控制字符）
// v6: 新增响应泄露检测规则 26001/26002（默认 LOG_ONLY 监控，可改 BLOCK）
// v7: 新增协议计数 25007/25008、HPP 27001/27002、API 安全 27010-27012、
//     编码混淆 27013、DLP 26010-26014、爬虫/客户端指纹 28001-28004
// v8: 修复 921170 误报（原 pattern=. 匹配所有参数键）：改为链式规则，
//     仅 GET/HEAD 且请求体存在时记录
// v9: 新增 CVE/HW 指纹规则集（seed_cve.go，94 条）：
//     逆向雷池(SafeLine) libfusion2.so 内置规则库转译，覆盖 ThinkPHP/Struts2/
//     Spring/Drupal/Dedecms/Solr/Weblogic/用友/泛微/Druid/Shiro 等历史 CVE 指纹，
//     risk=3 默认 BLOCK，risk=1/2 默认 LOG_ONLY
const SeedVersion = "10"

// LegacySeedIDs v1 内置种子规则 ID（旧部署迁移时删除用）
var LegacySeedIDs = []string{
	"10001", "10002", "20001", "20002", "20003", "20004", "20005", "20006",
	"21001", "21002", "21003", "21004", "22001", "22002", "22003",
	"23001", "23002", "23003", "24001", "24002", "25001", "25002",
}

// SeedRules 内置规则种子：libinjection 语义检测 + 基础兜底 + OWASP CRS 转译规则
// （seed_crs.go）+ CVE/HW 指纹规则（seed_cve.go）。首次启动时导入 Rule 表；
// 导入后可在管理后台增删改，发布后热更新。
//
// 检测分层：
//   1. libinjection 语义规则（SQLi/XSS 词法分析，抗编码/注释绕过，需 libinjection.so）
//   2. OWASP CRS 转译规则（约 180 条正则/语义规则，覆盖 OWASP Top 10）
//   3. CVE/HW 指纹规则（94 条历史漏洞指纹，逆向雷池检测引擎转译）
//   4. 基础兜底（敏感文件泄露、扫描器 UA）
var SeedRules = append(append(baseRules, SeedRulesCRS...), SeedRulesCVE...)

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

	// ---- 响应检测（默认仅监控，可在后台改为 BLOCK 拦截） ----
	{RuleID: "26001", Name: "响应体泄露检测", Group: "response", Phase: "body_filter", Severity: 2, Enabled: true,
		Operator: "REGEX", Pattern: `(ORA-[0-9]+|SQLSTATE\s*\[|mysql_fetch_|Fatal error:|Parse error:|Traceback \(most recent call last\)|syntax error, unexpected)`,
		Transforms: `[]`, Vars: `[{"type":"RESPONSE_BODY"}]`,
		Actions: `{"disrupt":"LOG_ONLY","msg":"响应体泄露：错误堆栈/数据库报错"}`, Status: 200, Message: "响应体泄露：错误堆栈/数据库报错", SortOrder: 9},
	{RuleID: "26002", Name: "响应头版本泄露", Group: "response", Phase: "header_filter", Severity: 1, Enabled: true,
		Operator: "EXISTS", Pattern: ``,
		Transforms: `[]`, Vars: `[{"type":"RESPONSE_HEADERS","specific":"x-powered-by"}]`,
		Actions: `{"disrupt":"LOG_ONLY","msg":"响应头泄露：X-Powered-By 版本信息"}`, Status: 200, Message: "响应头泄露：X-Powered-By 版本信息", SortOrder: 10},

	// ---- 协议计数 / 参数洪泛（应用层 DoS） ----
	{RuleID: "25007", Name: "请求头数量异常", Group: "protocol", Phase: "access", Severity: 2, Enabled: true,
		Operator: "REGEX", Pattern: `\d\d\d`,
		Transforms: `[]`, Vars: `[{"type":"HEADERS_COUNT"}]`,
		Actions: `{"disrupt":"BLOCK","status":400,"msg":"请求头数量异常（>=100 个）"}`, Status: 400, Message: "请求头数量异常（>=100 个）", SortOrder: 11},
	{RuleID: "25008", Name: "请求参数数量异常", Group: "protocol", Phase: "access", Severity: 2, Enabled: true,
		Operator: "REGEX", Pattern: `\d\d\d`,
		Transforms: `[]`, Vars: `[{"type":"ARGS_COUNT"}]`,
		Actions: `{"disrupt":"BLOCK","status":400,"msg":"请求参数数量异常（>=100 个）"}`, Status: 400, Message: "请求参数数量异常（>=100 个）", SortOrder: 12},

	// ---- HPP 参数污染（默认仅监控） ----
	{RuleID: "27001", Name: "URI 重复参数", Group: "hpp", Phase: "access", Severity: 2, Enabled: true,
		Operator: "EXISTS", Pattern: ``,
		Transforms: `[]`, Vars: `[{"type":"URI_ARGS_DUP"}]`,
		Actions: `{"disrupt":"LOG_ONLY","msg":"HPP：URI 重复参数（同参数多值提交）"}`, Status: 200, Message: "HPP：URI 重复参数（同参数多值提交）", SortOrder: 13},
	{RuleID: "27002", Name: "POST 重复参数", Group: "hpp", Phase: "access", Severity: 2, Enabled: true,
		Operator: "EXISTS", Pattern: ``,
		Transforms: `[]`, Vars: `[{"type":"POST_ARGS_DUP"}]`,
		Actions: `{"disrupt":"LOG_ONLY","msg":"HPP：POST 重复参数（同参数多值提交）"}`, Status: 200, Message: "HPP：POST 重复参数（同参数多值提交）", SortOrder: 14},

	// ---- API 安全 ----
	{RuleID: "27010", Name: "敏感端点/调试接口暴露", Group: "api", Phase: "access", Severity: 2, Enabled: true,
		Operator: "REGEX", Pattern: `(swagger|openapi\.json|api-docs|actuator|phpinfo|phpmyadmin|debug/pprof|server-status|docker\.sock)`,
		Transforms: `["url_decode","to_lowercase"]`, Vars: `[{"type":"URI"}]`,
		Actions: `{"disrupt":"BLOCK","status":403,"msg":"API 安全：敏感端点/调试接口暴露"}`, Status: 403, Message: "API 安全：敏感端点/调试接口暴露", SortOrder: 15},
	{RuleID: "27011", Name: "GraphQL 内省查询", Group: "api", Phase: "access", Severity: 1, Enabled: true,
		Operator: "REGEX", Pattern: `(__schema|__type|introspection)`,
		Transforms: `["url_decode","to_lowercase"]`, Vars: `[{"type":"URI_ARGS"},{"type":"POST_ARGS"},{"type":"BODY"}]`,
		Actions: `{"disrupt":"LOG_ONLY","msg":"API 安全：GraphQL 内省查询"}`, Status: 200, Message: "API 安全：GraphQL 内省查询", SortOrder: 16},
	{RuleID: "27012", Name: "XML 外部实体（XXE）", Group: "api", Phase: "access", Severity: 3, Enabled: true,
		Operator: "REGEX", Pattern: `<!DOCTYPE[^>]*(ENTITY|SYSTEM|PUBLIC)`,
		Transforms: `["to_lowercase"]`, Vars: `[{"type":"BODY"}]`,
		Actions: `{"disrupt":"BLOCK","status":403,"msg":"API 安全：XML 外部实体（XXE）"}`, Status: 403, Message: "API 安全：XML 外部实体（XXE）", SortOrder: 17},

	// ---- 编码混淆绕过 ----
	{RuleID: "27013", Name: "base64 载荷攻击", Group: "obfuscation", Phase: "access", Severity: 3, Enabled: true,
		Operator: "REGEX", Pattern: `\b(union|select|sleep|information_schema)\b|<script|javascript:`,
		Transforms: `["base64_decode","to_lowercase"]`, Vars: `[{"type":"URI_ARGS"},{"type":"POST_ARGS"},{"type":"BODY"}]`,
		Actions: `{"disrupt":"BLOCK","status":403,"msg":"编码混淆：base64 载荷攻击"}`, Status: 403, Message: "编码混淆：base64 载荷攻击", SortOrder: 18},

	// ---- DLP 敏感数据防泄露（默认仅监控） ----
	{RuleID: "26010", Name: "响应体泄露身份证", Group: "dlp", Phase: "body_filter", Severity: 3, Enabled: true,
		Operator: "REGEX", Pattern: `[1-9]\d{5}(18|19|20)\d{2}(0[1-9]|1[0-2])(0[1-9]|[12]\d|3[01])\d{3}[\dXx]`,
		Transforms: `[]`, Vars: `[{"type":"RESPONSE_BODY"}]`,
		Actions: `{"disrupt":"LOG_ONLY","msg":"DLP：响应体疑似泄露身份证号码"}`, Status: 200, Message: "DLP：响应体疑似泄露身份证号码", SortOrder: 19},
	{RuleID: "26011", Name: "响应体泄露银行卡", Group: "dlp", Phase: "body_filter", Severity: 3, Enabled: true,
		Operator: "REGEX", Pattern: `\b(62[0-9]{14,17}|[3-6][0-9]{15,18})\b`,
		Transforms: `[]`, Vars: `[{"type":"RESPONSE_BODY"}]`,
		Actions: `{"disrupt":"LOG_ONLY","msg":"DLP：响应体疑似泄露银行卡号"}`, Status: 200, Message: "DLP：响应体疑似泄露银行卡号", SortOrder: 20},
	{RuleID: "26012", Name: "响应体泄露手机号", Group: "dlp", Phase: "body_filter", Severity: 2, Enabled: true,
		Operator: "REGEX", Pattern: `1[3-9]\d{9}`,
		Transforms: `[]`, Vars: `[{"type":"RESPONSE_BODY"}]`,
		Actions: `{"disrupt":"LOG_ONLY","msg":"DLP：响应体疑似泄露手机号"}`, Status: 200, Message: "DLP：响应体疑似泄露手机号", SortOrder: 21},
	{RuleID: "26013", Name: "响应体泄露私钥", Group: "dlp", Phase: "body_filter", Severity: 3, Enabled: true,
		Operator: "REGEX", Pattern: `-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----`,
		Transforms: `[]`, Vars: `[{"type":"RESPONSE_BODY"}]`,
		Actions: `{"disrupt":"LOG_ONLY","msg":"DLP：响应体疑似泄露私钥"}`, Status: 200, Message: "DLP：响应体疑似泄露私钥", SortOrder: 22},
	{RuleID: "26014", Name: "响应体泄露云密钥", Group: "dlp", Phase: "body_filter", Severity: 3, Enabled: true,
		Operator: "REGEX", Pattern: `(AKIA[0-9A-Z]{16}|AIza[0-9A-Za-z_-]{35}|ghp_[0-9A-Za-z]{36}|sk-[0-9A-Za-z]{20,}|xox[baprs]-[0-9A-Za-z-]{10,})`,
		Transforms: `[]`, Vars: `[{"type":"RESPONSE_BODY"}]`,
		Actions: `{"disrupt":"LOG_ONLY","msg":"DLP：响应体疑似泄露云服务密钥/令牌"}`, Status: 200, Message: "DLP：响应体疑似泄露云服务密钥/令牌", SortOrder: 23},

	// ---- 爬虫/客户端指纹（默认仅监控；策略可通过触发规则 kind=exempt/block/challenge 分级） ----
	{RuleID: "28001", Name: "已知搜索引擎爬虫", Group: "crawler", Phase: "access", Severity: 1, Enabled: true,
		Operator: "PM", Pattern: `googlebot|bingbot|baiduspider|sogou|360spider|yisouspider|shenma|duckduckbot|applebot|slurp|ia_archiver`,
		Transforms: `["to_lowercase"]`, Vars: `[{"type":"HEADERS","specific":"user-agent"}]`,
		Actions: `{"disrupt":"LOG_ONLY","msg":"爬虫指纹：已知搜索引擎爬虫"}`, Status: 200, Message: "爬虫指纹：已知搜索引擎爬虫", SortOrder: 24},
	{RuleID: "28002", Name: "空 User-Agent", Group: "crawler", Phase: "access", Severity: 2, Enabled: true,
		Operator: "REGEX", Pattern: `^$`,
		Transforms: `[]`, Vars: `[{"type":"USER_AGENT"}]`,
		Actions: `{"disrupt":"LOG_ONLY","msg":"爬虫指纹：空 User-Agent"}`, Status: 200, Message: "爬虫指纹：空 User-Agent", SortOrder: 25},
	{RuleID: "28003", Name: "HTTP 客户端库 UA", Group: "crawler", Phase: "access", Severity: 2, Enabled: true,
		Operator: "PM", Pattern: `python-requests|go-http-client|okhttp|curl/|wget/|scrapy|apache-httpclient|node-fetch|axios|libwww-perl`,
		Transforms: `["to_lowercase"]`, Vars: `[{"type":"HEADERS","specific":"user-agent"}]`,
		Actions: `{"disrupt":"LOG_ONLY","msg":"爬虫指纹：HTTP 客户端库 UA"}`, Status: 200, Message: "爬虫指纹：HTTP 客户端库 UA", SortOrder: 26},
	{RuleID: "28004", Name: "监控探针", Group: "crawler", Phase: "access", Severity: 1, Enabled: true,
		Operator: "PM", Pattern: `uptimerobot|uptime-kuma|pingdom|statuscake|monitoring|datadog-agent|healthchecks`,
		Transforms: `["to_lowercase"]`, Vars: `[{"type":"HEADERS","specific":"user-agent"}]`,
		Actions: `{"disrupt":"LOG_ONLY","msg":"爬虫指纹：监控探针"}`, Status: 200, Message: "爬虫指纹：监控探针", SortOrder: 27},
}
