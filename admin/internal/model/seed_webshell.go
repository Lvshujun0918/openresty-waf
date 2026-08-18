package model

// SeedRulesWebshell 加密 Webshell 流量特征规则（seed_webshell.go）：
// 逆向雷池 libfusion2.so 的 rskynet::modules::webshell 检测模块提炼。
// 雷池原实现对冰蝎(Behinder)/哥斯拉(Godzilla)/天蝎(SkyScorpion)等工具流量做
// XOR/AES 解密后再语义检测；openresty-waf 纯 Lua 引擎无 crypto 依赖，无法复刻解密链路，
// 故落地为高置信流量指纹规则（不解密）：利用工具握手阶段的固定协议特征识别恶意流量。

var SeedRulesWebshell = []Rule{
	// 冰蝎 3.x：AES 加密 payload 固定格式 = base64(密文) + "@" + md5(key)前16位
	// 正常业务请求体几乎不可能出现 >200 字符 base64 且以 @+16hex 结尾
	{RuleID: "65919", Name: "冰蝎 3.x 加密流量特征", Group: "webshell", Phase: "access", Severity: 3, Enabled: true,
		Operator: `REGEX`, Pattern: `[A-Za-z0-9+/=]{200,}@[0-9a-f]{16}$`,
		Transforms: `[]`, Vars: `[{"type":"BODY"},{"type":"POST_ARGS"}]`,
		Actions: `{"disrupt":"BLOCK","status":403,"msg":"Webshell：冰蝎 3.x 加密流量特征"}`, Status: 403, Message: "Webshell：冰蝎 3.x 加密流量特征", SortOrder: 2200},
	// 哥斯拉 PHP 马：固定结构 function encode($A,$K){...} 定义加密函数 + @$_POST 取参执行
	{RuleID: "65920-1", Name: "哥斯拉 PHP 马特征-加密函数", Group: "webshell", Phase: "access", Severity: 3, Enabled: true,
		Operator: `REGEX`, Pattern: `(?i)function\s+encode\s*\(\s*\$[A-Z]\s*,\s*\$[A-Z]`,
		Transforms: `[]`, Vars: `[{"type":"BODY"}]`,
		Actions: `{"chain":true}`, Status: 0, Message: "Webshell：哥斯拉 PHP 马特征", SortOrder: 2201},
	{RuleID: "65920-2", Name: "哥斯拉 PHP 马特征-参数执行", Group: "webshell", Phase: "access", Severity: 3, Enabled: true,
		Operator: `REGEX`, Pattern: `@\s*\$_POST`,
		Transforms: `[]`, Vars: `[{"type":"BODY"}]`,
		Actions: `{"chain":true,"disrupt":"BLOCK","status":403,"msg":"Webshell：哥斯拉 PHP 马特征"}`, Status: 403, Message: "Webshell：哥斯拉 PHP 马特征", SortOrder: 2201},
	// 罕见脚本变体后缀（正常业务极少访问；.php/.jsp 主后缀不在此列，避免误报）
	{RuleID: "65921", Name: "罕见脚本后缀访问", Group: "webshell", Phase: "access", Severity: 2, Enabled: true,
		Operator: `REGEX`, Pattern: `(?i)\.(php2|php3|php4|php5|php6|php7|php8|phtml|jspx|jspa|jsw|jsv|asp|aspx|asa|ashx|asmx|cdx|htr|shtml|shtm|cgi|war)(\.\d+)*$`,
		Transforms: `[]`, Vars: `[{"type":"URI"}]`,
		Actions: `{"disrupt":"LOG_ONLY","msg":"Webshell：罕见脚本后缀访问（疑似 webshell）"}`, Status: 200, Message: "Webshell：罕见脚本后缀访问（疑似 webshell）", SortOrder: 2202},
}