// Package ruletest 规则测试匹配器：在后台用模拟请求验证规则是否命中。
// 逻辑与 Lua 引擎（variables/transforms/operators）对齐；
// libinjection 语义规则（依赖 .so）无法在后台验证，返回提示。
package ruletest

import (
	"encoding/json"
	"net"
	"regexp"
	"strconv"
	"strings"

	"openresty-waf/admin/internal/model"
)

// TestRequest 模拟请求
type TestRequest struct {
	Method      string            `json:"method"`
	URI         string            `json:"uri"`
	Headers     map[string]string `json:"headers"`
	Cookies     string            `json:"cookies"`
	Body        string            `json:"body"`
	ContentType string            `json:"content_type"`
	ClientIP    string            `json:"client_ip"`
}

// MatchResult 匹配结果
type MatchResult struct {
	Matched bool   `json:"matched"`
	Note    string `json:"note,omitempty"`
}

// ---- 变换（与 waf/rule_engine/transforms.lua 对齐） ----

func hexVal(c byte) (byte, bool) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', true
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10, true
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10, true
	}
	return 0, false
}

// urlDecode 与 ngx.unescape_uri 一致：仅解码 %XX，不把 '+' 当空格
func urlDecode(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		if s[i] == '%' && i+2 < len(s) {
			if hi, ok := hexVal(s[i+1]); ok {
				if lo, ok2 := hexVal(s[i+2]); ok2 {
					b.WriteByte(hi<<4 | lo)
					i += 2
					continue
				}
			}
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

var (
	reBlockComment = regexp.MustCompile(`/\*.*?\*/`)
	reLineComment  = regexp.MustCompile(`--[^\r\n]*`)
	reHashComment  = regexp.MustCompile(`#[^\r\n]*`)
	reWhitespace   = regexp.MustCompile(`\s+`)
	reSlashes      = regexp.MustCompile(`/+`)
)

func applyTransform(name, s string) string {
	switch name {
	case "url_decode":
		return urlDecode(s)
	case "url_decode_twice":
		// 与 Lua transforms 对齐：最多 3 次直至不再变化
		for i := 0; i < 3; i++ {
			decoded := urlDecode(s)
			if decoded == s {
				break
			}
			s = decoded
		}
		return s
	case "to_lowercase":
		return strings.ToLower(s)
	case "remove_comments":
		s = reBlockComment.ReplaceAllString(s, "")
		s = reLineComment.ReplaceAllString(s, "")
		s = reHashComment.ReplaceAllString(s, "")
		return s
	case "compress_whitespace":
		return reWhitespace.ReplaceAllString(s, " ")
	case "normalize_path":
		return reSlashes.ReplaceAllString(s, "/")
	}
	return s
}

// ---- 运算符（与 waf/rule_engine/operators.lua 对齐） ----

var regexCache = map[string]*regexp.Regexp{}

func evalOperator(op, value, pattern string) (bool, error) {
	switch op {
	case "REGEX":
		re, ok := regexCache[pattern]
		if !ok {
			r, err := regexp.Compile(pattern)
			if err != nil {
				return false, err
			}
			re = r
			regexCache[pattern] = re
		}
		return re.MatchString(value), nil
	case "EQUALS":
		return value == pattern, nil
	case "CONTAINS":
		return strings.Contains(value, pattern), nil
	case "PM":
		lower := strings.ToLower(value)
		for _, w := range strings.Split(pattern, "|") {
			if w != "" && strings.Contains(lower, strings.ToLower(w)) {
				return true, nil
			}
		}
		return false, nil
	case "STARTS_WITH":
		return strings.HasPrefix(value, pattern), nil
	case "ENDS_WITH":
		return strings.HasSuffix(value, pattern), nil
	case "EXISTS":
		return value != "", nil
	case "CIDR":
		return cidrMatch(value, pattern), nil
	}
	return false, nil
}

func cidrMatch(ip, pattern string) bool {
	if !strings.Contains(pattern, "/") {
		return ip == pattern
	}
	_, ipNet, err := net.ParseCIDR(pattern)
	if err != nil {
		return ip == pattern
	}
	p := net.ParseIP(ip)
	return p != nil && ipNet.Contains(p)
}

// ---- 变量提取（与 waf/rule_engine/variables.lua 对齐） ----

func parseQuery(q string) map[string][]string {
	out := map[string][]string{}
	for _, part := range strings.Split(q, "&") {
		if part == "" {
			continue
		}
		kv := strings.SplitN(part, "=", 2)
		k := urlDecode(kv[0])
		v := ""
		if len(kv) == 2 {
			v = urlDecode(kv[1])
		}
		out[k] = append(out[k], v)
	}
	return out
}

// 递归展平 JSON 为字符串值列表
func flattenJSON(v interface{}, out *[]string) {
	switch t := v.(type) {
	case string:
		*out = append(*out, t)
	case float64:
		*out = append(*out, strconv.FormatFloat(t, 'f', -1, 64))
	case bool:
		*out = append(*out, strconv.FormatBool(t))
	case map[string]interface{}:
		for _, val := range t {
			flattenJSON(val, out)
		}
	case []interface{}:
		for _, val := range t {
			flattenJSON(val, out)
		}
	}
}

func parsePostArgs(req TestRequest) map[string][]string {
	out := map[string][]string{}
	ct := strings.ToLower(req.ContentType)
	// JSON body：逐字段值（与引擎 JSON 结构化一致）
	if strings.Contains(ct, "application/json") && req.Body != "" {
		var obj interface{}
		if json.Unmarshal([]byte(req.Body), &obj) == nil {
			var vals []string
			flattenJSON(obj, &vals)
			if len(vals) > 0 {
				out[""] = vals
			}
			return out
		}
	}
	for k, vs := range parseQuery(req.Body) {
		out[k] = vs
	}
	return out
}

func extractVariable(spec map[string]interface{}, req TestRequest) []string {
	typ, _ := spec["type"].(string)
	specific, _ := spec["specific"].(string)
	includeKeys := false
	if parse, ok := spec["parse"].([]interface{}); ok {
		for _, p := range parse {
			if p == "keys" {
				includeKeys = true
			}
		}
	}

	path := req.URI
	query := ""
	if i := strings.IndexByte(path, '?'); i >= 0 {
		query = path[i+1:]
		path = path[:i]
	}

	var out []string
	switch typ {
	case "URI":
		out = append(out, path)
	case "REQUEST_URI", "REQUEST_LINE":
		out = append(out, req.URI)
	case "METHOD":
		out = append(out, req.Method)
	case "CLIENT_IP":
		if req.ClientIP != "" {
			out = append(out, req.ClientIP)
		}
	case "USER_AGENT":
		if ua, ok := req.Headers["user-agent"]; ok && ua != "" {
			out = append(out, ua)
		}
	case "URI_ARGS":
		args := parseQuery(query)
		if specific != "" {
			out = append(out, args[specific]...)
		} else {
			for k, vs := range args {
				out = append(out, vs...)
				if includeKeys {
					out = append(out, k)
				}
			}
		}
	case "POST_ARGS":
		args := parsePostArgs(req)
		if specific != "" {
			out = append(out, args[specific]...)
		} else {
			for k, vs := range args {
				out = append(out, vs...)
				if includeKeys {
					out = append(out, k)
				}
			}
		}
	case "HEADERS":
		if specific != "" {
			if v, ok := req.Headers[strings.ToLower(specific)]; ok {
				out = append(out, v)
			}
		} else {
			for _, v := range req.Headers {
				out = append(out, v)
			}
		}
	case "COOKIE":
		for _, part := range strings.Split(req.Cookies, ";") {
			part = strings.TrimSpace(part)
			if i := strings.IndexByte(part, '='); i >= 0 {
				k := strings.TrimSpace(part[:i])
				v := strings.TrimSpace(part[i+1:])
				if specific == "" || k == specific {
					out = append(out, v)
				}
				if includeKeys {
					out = append(out, k)
				}
			}
		}
	case "BODY":
		if req.Body != "" {
			out = append(out, req.Body)
		}
	}
	return out
}

// Match 匹配单条规则；libinjection 语义规则返回需引擎验证提示
func Match(r model.Rule, req TestRequest) MatchResult {
	if r.Operator == "LIBINJECTION_SQLI" || r.Operator == "LIBINJECTION_XSS" {
		return MatchResult{Matched: false, Note: "libinjection 语义规则需在引擎真实流量验证"}
	}
	var varsSpec []map[string]interface{}
	_ = json.Unmarshal([]byte(r.Vars), &varsSpec)
	var transforms []string
	_ = json.Unmarshal([]byte(r.Transforms), &transforms)

	var values []string
	for _, spec := range varsSpec {
		values = append(values, extractVariable(spec, req)...)
	}
	for _, tn := range transforms {
		for i := range values {
			values[i] = applyTransform(tn, values[i])
		}
	}
	for _, v := range values {
		ok, _ := evalOperator(r.Operator, v, r.Pattern)
		if ok {
			return MatchResult{Matched: true}
		}
	}
	return MatchResult{Matched: false}
}
