package model

// SeedRulesSemantic 轻量语义分析规则集（seed_semantic.go）：
// 基于 waf/semantic.lua 的 token 化结构异常度评分（0-100），经 SEMANTIC_ANOMALY
// 运算符接入 SCORE 弱特征体系。定位为 libinjection（强特征 BLOCK）之下的
// 第二层语义网：抗注释插入/引号变形/大小写变换等正则难以稳定表达的结构模式。
// 阈值 35 灰区 +1 分、阈值 60 高置信 +2 分，均不单独拦截，
// 需与其他弱特征叠加达到 score_threshold 才阻断。

var SeedRulesSemantic = []Rule{
	{RuleID: "65946", Name: "语义结构异常-高置信", Group: "semantic", Phase: "access", Severity: 2, Enabled: true,
		Operator: `SEMANTIC_ANOMALY`, Pattern: `60`,
		Transforms: "[]", Vars: "[{\"type\":\"URI_ARGS\"},{\"type\":\"POST_ARGS\"},{\"type\":\"BODY\"}]",
		Actions: "{\"disrupt\":\"SCORE\",\"value\":2,\"msg\":\"语义结构异常（token 化评分≥60）\"}", Status: 200, Message: "语义结构异常-高置信", SortOrder: 2320},
	{RuleID: "65947", Name: "语义结构异常-灰区", Group: "semantic", Phase: "access", Severity: 1, Enabled: true,
		Operator: `SEMANTIC_ANOMALY`, Pattern: `35`,
		Transforms: "[]", Vars: "[{\"type\":\"URI_ARGS\"},{\"type\":\"POST_ARGS\"},{\"type\":\"BODY\"}]",
		Actions: "{\"disrupt\":\"SCORE\",\"value\":1,\"msg\":\"语义结构异常（token 化评分≥35）\"}", Status: 200, Message: "语义结构异常-灰区", SortOrder: 2321},
}
