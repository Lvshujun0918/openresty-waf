package ruletest

import (
	"testing"

	"openresty-waf/admin/internal/model"
)

func mkRule(ruleID, op, pattern, vars, transforms string) model.Rule {
	return model.Rule{RuleID: ruleID, Operator: op, Pattern: pattern, Vars: vars, Transforms: transforms}
}

func TestMatch_URIArgs_Regex(t *testing.T) {
	r := mkRule("20001", "REGEX", `\bunion\b[\s\S]{0,100}?\bselect\b`,
		`[{"type":"URI_ARGS"}]`,
		`["url_decode","to_lowercase","remove_comments","compress_whitespace"]`)
	if !Match(r, TestRequest{URI: "/?id=1 union select 2"}).Matched {
		t.Error("应命中 union select")
	}
	// 编码绕过
	if !Match(r, TestRequest{URI: "/?id=1%20union%20select%202"}).Matched {
		t.Error("URL 编码后应命中")
	}
	if Match(r, TestRequest{URI: "/?id=1"}).Matched {
		t.Error("普通请求不应命中")
	}
}

func TestMatch_JSON_PostArgs(t *testing.T) {
	r := mkRule("942110", "REGEX", "union", `[{"type":"POST_ARGS"}]`, "[]")
	if !Match(r, TestRequest{Method: "POST", URI: "/login",
		ContentType: "application/json", Body: `{"email":"x@163.com","q":"1 union select 2"}`}).Matched {
		t.Error("JSON 字段值应命中")
	}
	if Match(r, TestRequest{Method: "POST", URI: "/login",
		ContentType: "application/json", Body: `{"email":"x@163.com"}`}).Matched {
		t.Error("正常 JSON 不应命中")
	}
}

func TestMatch_Form_PostArgs(t *testing.T) {
	r := mkRule("942110", "REGEX", "union", `[{"type":"POST_ARGS"}]`, "[]")
	if !Match(r, TestRequest{Method: "POST", ContentType: "application/x-www-form-urlencoded",
		Body: "q=1+union+select+2"}).Matched {
		t.Error("表单 body 应命中")
	}
}

func TestMatch_LibInjection_Note(t *testing.T) {
	r := mkRule("940001", "LIBINJECTION_SQLI", "", `[{"type":"BODY"}]`, "[]")
	res := Match(r, TestRequest{Method: "POST", Body: "1 or 1=1"})
	if res.Matched {
		t.Error("libinjection 后台不应匹配")
	}
	if res.Note == "" {
		t.Error("libinjection 应有提示")
	}
}

func TestMatch_Headers_Cookie(t *testing.T) {
	r := mkRule("10002", "REGEX", "(?i)(sqlmap|nikto)", `[{"type":"HEADERS","specific":"user-agent"}]`, `["to_lowercase"]`)
	if !Match(r, TestRequest{Headers: map[string]string{"user-agent": "sqlmap/1.0"}}).Matched {
		t.Error("UA 应命中")
	}
	cr := mkRule("942420", "REGEX", "session", `[{"type":"COOKIE","parse":["keys"]}]`, "[]")
	if !Match(cr, TestRequest{Cookies: "session=abc; theme=dark"}).Matched {
		t.Error("cookie 键名应命中")
	}
	// 无 keys 时只匹配 cookie 值
	cv := mkRule("942420", "REGEX", "abc", `[{"type":"COOKIE"}]`, "[]")
	if !Match(cv, TestRequest{Cookies: "session=abc; theme=dark"}).Matched {
		t.Error("cookie 值应命中")
	}
}

func TestMatch_CIDR(t *testing.T) {
	r := mkRule("10003", "CIDR", "1.2.3.0/24", `[{"type":"CLIENT_IP"}]`, "[]")
	if !Match(r, TestRequest{ClientIP: "1.2.3.4"}).Matched {
		t.Error("CIDR 应命中")
	}
	if Match(r, TestRequest{ClientIP: "1.2.4.4"}).Matched {
		t.Error("CIDR 不应命中")
	}
}
