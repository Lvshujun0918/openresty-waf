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
}
