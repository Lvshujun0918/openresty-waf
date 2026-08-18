package model

// SeedRulesMisc 杂项补充规则（seed_misc.go）：逆向雷池 libfusion2.so 内嵌检测模块提取
// Log4j JNDI 注入 / Python 危险函数 / Java 代码注入通用防御 / 路径穿越编码绕过

var SeedRulesMisc = []Rule{
	{RuleID: `65915`, Name: `Log4j JNDI 注入 (CVE-2021-44228)`, Group: `rce`, Phase: "access", Severity: 3, Enabled: true,
		Operator: `REGEX`, Pattern: `(?i)\$\{jndi:(ldap|rmi|dns):`,
		Transforms: "[]", Vars: "[{\"type\":\"BODY\"},{\"type\":\"POST_ARGS\"},{\"type\":\"URI_ARGS\"},{\"type\":\"HEADERS\"}]",
		Actions: "{\"disrupt\":\"BLOCK\",\"status\":403,\"msg\":\"Log4j JNDI 注入 (CVE-2021-44228)\"}", Status: 403, Message: `Log4j JNDI 注入 (CVE-2021-44228)`, SortOrder: 2100},
	{RuleID: `65916`, Name: `Python 危险函数调用`, Group: `rce`, Phase: "access", Severity: 3, Enabled: true,
		Operator: `REGEX`, Pattern: "(?i)((\\bos|\\A(\\w+['\"])?)\\s*\\.\\s*(system|execute|popen)\\s*\\(\\s*((([\\x20-\\x7E]{1,10}\\s*\\.\\s*)*[\\x20-\\x7E]{1,10})|(\\w?['\"`]+[\\x20-\\x7E]+))\\))|(subprocess\\s*\\.\\s*Popen\\s*\\(.*\\))|(subprocess\\s*\\.\\s*call\\s*\\(.*\\))|(subprocess\\s*\\.\\s*run\\s*\\(.*\\))|(subprocess\\s*\\.\\s*getstatusoutput\\s*\\(.*\\))|(python[23]?(\\.(exe|sh))?\\s+-c\\s+((\\+)?['\"].*(import|exec|os\\.|sys\\.)\\s+))|(__import__\\s*\\(\\s*\"subprocess\"\\s*\\))",
		Transforms: "[]", Vars: "[{\"type\":\"BODY\"},{\"type\":\"POST_ARGS\"}]",
		Actions: "{\"disrupt\":\"BLOCK\",\"status\":403,\"msg\":\"Python 危险函数调用\"}", Status: 403, Message: `Python 危险函数调用`, SortOrder: 2100},
	{RuleID: `65917`, Name: `Java 代码注入/OGNL 反射链`, Group: `deser`, Phase: "access", Severity: 3, Enabled: true,
		Operator: `REGEX`, Pattern: `.*(\(|\{).*(java\.io\.File|java\.lang\.ProcessBuilder|java\.lang\.Runtime|java\.lang\.System|java\.lang\.Class|java\.lang\.ClassLoader|java\.lang\.Shutdown|javax\.script\.ScriptEngineManager|ognl\.OgnlContext|ognl\.MemberAccess|ognl\.ClassResolver|ognl\.TypeConverter|com\.opensymphony\.xwork2\.ActionContext|_memberAccess)`,
		Transforms: "[]", Vars: "[{\"type\":\"BODY\"},{\"type\":\"POST_ARGS\"},{\"type\":\"URI_ARGS\"}]",
		Actions: "{\"disrupt\":\"BLOCK\",\"status\":403,\"msg\":\"Java 代码注入/OGNL 反射链\"}", Status: 403, Message: `Java 代码注入/OGNL 反射链`, SortOrder: 2100},
	{RuleID: `65918`, Name: `路径穿越编码绕过 (Struts2/WebLogic)`, Group: `lfi`, Phase: "access", Severity: 3, Enabled: true,
		Operator: `REGEX`, Pattern: `(?i)((\\|\/)|((\xc0(\x2f|\x6f|\xaf|\xef))|(\xc1(\x1c|\x5c|\x9c|\xdc)))|(((((%|=)(25)?)(%(32|35))?)c0(((%|=)(25)?)(%(32|35))?)(2f|6f|af|ef))|((((%|=)(25)?)(%(32|35))?)c1(((%|=)(25)?)(%(32|35))?)(1c|5c|9c|dc)))|((0x|\\x?|(((%|=)(25)?)(%(32|35))?))(2f|5c))|(((((%|=)(25)?)(%(32|35))?)|\\)u(ff0f|ff3c|2215|2216))|((\xef\xbc\x8f)|(\xef\xbc\xbc)))services((\\|\/)|((\xc0(\x2f|\x6f|\xaf|\xef))|(\xc1(\x1c|\x5c|\x9c|\xdc)))|(((((%|=)(25)?)(%(32|35))?)c0(((%|=)(25)?)(%(32|35))?)(2f|6f|af|ef))|((((%|=)(25)?)(%(32|35))?)c1(((%|=)(25)?)(%(32|35))?)(1c|5c|9c|dc)))|((0x|\\x?|(((%|=)(25)?)(%(32|35))?))(2f|5c))|(((((%|=)(25)?)(%(32|35))?)|\\)u(ff0f|ff3c|2215|2216))|((\xef\xbc\x8f)|(\xef\xbc\xbc)))(adminservice|freemarkerservice)`,
		Transforms: "[]", Vars: "[{\"type\":\"URI\"},{\"type\":\"REQUEST_URI\"}]",
		Actions: "{\"disrupt\":\"BLOCK\",\"status\":403,\"msg\":\"路径穿越编码绕过 (Struts2/WebLogic)\"}", Status: 403, Message: `路径穿越编码绕过 (Struts2/WebLogic)`, SortOrder: 2100},
	{RuleID: `65941`, Name: `命令序列直接执行 (分隔符+命令词)`, Group: `rce`, Phase: "access", Severity: 3, Enabled: true,
		Operator: `REGEX`, Pattern: "(?i)(?:[;&|`\n\r])\\s*(?:whoami|id|cat|ls|pwd|uname|ifconfig|netstat|wget|curl|nc|bash|sh|python|perl|php|rm|mv|cp|chmod|chown|kill|pkill|systemctl|service|apt|yum|base64|xxd)\\b(?:\\s|;|\\||&|`|$)",
		Transforms: "[]", Vars: "[{\"type\":\"URI_ARGS\"},{\"type\":\"POST_ARGS\"},{\"type\":\"BODY\"}]",
		Actions: "{\"disrupt\":\"BLOCK\",\"status\":403,\"msg\":\"命令序列直接执行 (分隔符+命令词)\"}", Status: 403, Message: `命令序列直接执行 (分隔符+命令词)`, SortOrder: 2101},
	// 编码混淆载荷（雷池 preprocess 解码思想：先解码再检测；链式=先命中超长 base64 形态再解码验证内容）
	{RuleID: `65942-1`, Name: `编码混淆载荷-超长 base64 形态`, Group: `obfuscation`, Phase: "access", Severity: 2, Enabled: true,
		Operator: `REGEX`, Pattern: "[A-Za-z0-9+/=]{100,}",
		Transforms: "[]", Vars: "[{\"type\":\"URI_ARGS\"},{\"type\":\"POST_ARGS\"},{\"type\":\"BODY\"}]",
		Actions: "{\"chain\":true}", Status: 0, Message: `编码混淆载荷-超长 base64 形态`, SortOrder: 2200},
	{RuleID: `65942-2`, Name: `编码混淆载荷-解码后危险内容`, Group: `obfuscation`, Phase: "access", Severity: 3, Enabled: true,
		Operator: `REGEX`, Pattern: "(?i)((?:\\\\u[0-9a-fA-F]{4}){3,}|(?:\\\\x[0-9a-fA-F]{2}){3,}|\\{\\{[^}]{2,}\\}\\})",
		Transforms: "[\"base64_decode\"]", Vars: "[{\"type\":\"URI_ARGS\"},{\"type\":\"POST_ARGS\"},{\"type\":\"BODY\"}]",
		Actions: "{\"chain\":true,\"disrupt\":\"BLOCK\",\"status\":403,\"msg\":\"编码混淆载荷：base64 解码后含 unicode/hex 转义连串或模板表达式\"}", Status: 403, Message: `编码混淆载荷-解码后危险内容`, SortOrder: 2201},
	// 路径内 SQL 注入（如 /api/products/123 and 1=1/reviews）
	{RuleID: `65943`, Name: `路径内 SQL 注入特征`, Group: `sqli`, Phase: "access", Severity: 3, Enabled: true,
		Operator: `REGEX`, Pattern: "(?i)\\d+\\s+and\\s+\\d+\\s*=\\s*\\d+",
		Transforms: "[]", Vars: "[{\"type\":\"URI\"},{\"type\":\"REQUEST_URI\"}]",
		Actions: "{\"disrupt\":\"BLOCK\",\"status\":403,\"msg\":\"路径内 SQL 注入特征 (数字 and 数字=数字)\"}", Status: 403, Message: `路径内 SQL 注入特征 (数字 and 数字=数字)`, SortOrder: 2202},
	// 分号路径穿越（..; 绕过，如 /tmui/login.jsp/..;/）
	{RuleID: `65944`, Name: `分号路径穿越`, Group: `lfi`, Phase: "access", Severity: 3, Enabled: true,
		Operator: `REGEX`, Pattern: "\\.\\.;",
		Transforms: "[]", Vars: "[{\"type\":\"URI\"},{\"type\":\"REQUEST_URI\"}]",
		Actions: "{\"disrupt\":\"BLOCK\",\"status\":403,\"msg\":\"分号路径穿越 (..;)\"}", Status: 403, Message: `分号路径穿越 (..;)`, SortOrder: 2203},
	// 双重编码路径遍历（.%252e / %252e%252e / %c0%ae 等原始形态；url_decode 后 .%252e 变 .%2e 字面，故直接匹配原始形态）
	// 注意：%252f 单出现太常见（Google Analytics uafvl=Not.A%252FBrand Sec-CH-UA 标准编码、微信 pass_ticket），已移除该分支，仅保留路径穿越强特征
	{RuleID: `65945`, Name: `双重编码路径遍历`, Group: `lfi`, Phase: "access", Severity: 3, Enabled: true,
		Operator: `REGEX`, Pattern: "(?i)(\\.%252e|%252e%252e|%c0%ae|%c0%af)",
		Transforms: "[]", Vars: "[{\"type\":\"REQUEST_URI\"}]",
		Actions: "{\"disrupt\":\"BLOCK\",\"status\":403,\"msg\":\"双重编码路径遍历\"}", Status: 403, Message: `双重编码路径遍历`, SortOrder: 2204},
}
