package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"testing"
)

func newRuleBody() map[string]interface{} {
	return map[string]interface{}{
		"rule_id": "90001", "name": "测试规则", "group": "custom", "phase": "access",
		"severity": 2, "enabled": true, "operator": "REGEX", "pattern": `union\s+select`,
		"transforms": `["url_decode"]`, "vars": `[{"type":"URI_ARGS"}]`,
	}
}

// TestRules_CRUD 规则增删改查全流程
func TestRules_CRUD(t *testing.T) {
	db := newTestDB(t)
	r := newTestRouter(t, db, nil)
	token := doLogin(t, r)

	// 空列表
	w := doReq(r, authedReq(http.MethodGet, "/api/rules", token, nil))
	if w.Code != http.StatusOK {
		t.Fatalf("list: %d", w.Code)
	}
	var rules []map[string]interface{}
	_ = json.Unmarshal(w.Body.Bytes(), &rules)
	if len(rules) != 0 {
		t.Errorf("expected 0 rules, got %d", len(rules))
	}

	// 创建
	w = doReq(r, authedReq(http.MethodPost, "/api/rules", token, newRuleBody()))
	if w.Code != http.StatusCreated {
		t.Fatalf("create: %d %s", w.Code, w.Body.String())
	}
	var created map[string]interface{}
	_ = json.Unmarshal(w.Body.Bytes(), &created)
	id := int(created["id"].(float64))
	if id == 0 {
		t.Fatal("created id = 0")
	}
	if created["rule_id"] != "90001" {
		t.Errorf("rule_id = %v", created["rule_id"])
	}

	// 创建缺字段 → 400
	w = doReq(r, authedReq(http.MethodPost, "/api/rules", token,
		map[string]interface{}{"rule_id": "90002"}))
	if w.Code != http.StatusBadRequest {
		t.Errorf("create invalid: %d", w.Code)
	}

	// 列表含 1 条
	w = doReq(r, authedReq(http.MethodGet, "/api/rules", token, nil))
	_ = json.Unmarshal(w.Body.Bytes(), &rules)
	if len(rules) != 1 {
		t.Errorf("expected 1 rule, got %d", len(rules))
	}

	// 关键词过滤
	w = doReq(r, authedReq(http.MethodGet, "/api/rules?keyword=测试", token, nil))
	_ = json.Unmarshal(w.Body.Bytes(), &rules)
	if len(rules) != 1 {
		t.Errorf("keyword filter: %d", len(rules))
	}
	w = doReq(r, authedReq(http.MethodGet, "/api/rules?keyword=不存在", token, nil))
	_ = json.Unmarshal(w.Body.Bytes(), &rules)
	if len(rules) != 0 {
		t.Errorf("keyword miss: %d", len(rules))
	}
	w = doReq(r, authedReq(http.MethodGet, "/api/rules?group=custom", token, nil))
	_ = json.Unmarshal(w.Body.Bytes(), &rules)
	if len(rules) != 1 {
		t.Errorf("group filter: %d", len(rules))
	}

	// 更新
	w = doReq(r, authedReq(http.MethodPut, fmt.Sprintf("/api/rules/%d", id), token,
		map[string]interface{}{"name": "改名", "pattern": "new-pattern"}))
	if w.Code != http.StatusOK {
		t.Fatalf("update: %d %s", w.Code, w.Body.String())
	}

	// 更新不存在 → 400
	w = doReq(r, authedReq(http.MethodPut, "/api/rules/99999", token, newRuleBody()))
	if w.Code != http.StatusBadRequest {
		t.Errorf("update missing: %d", w.Code)
	}

	// 无效 id → 400
	w = doReq(r, authedReq(http.MethodPut, "/api/rules/abc", token, newRuleBody()))
	if w.Code != http.StatusBadRequest {
		t.Errorf("update bad id: %d", w.Code)
	}

	// 禁用
	w = doReq(r, authedReq(http.MethodPatch, fmt.Sprintf("/api/rules/%d/enabled", id), token,
		map[string]interface{}{"enabled": false}))
	if w.Code != http.StatusOK {
		t.Fatalf("disable: %d %s", w.Code, w.Body.String())
	}
	w = doReq(r, authedReq(http.MethodGet, "/api/rules", token, nil))
	_ = json.Unmarshal(w.Body.Bytes(), &rules)
	if len(rules) != 1 {
		t.Errorf("after disable list: %d", len(rules))
	}
	if rules[0]["enabled"] != false {
		t.Errorf("enabled = %v", rules[0]["enabled"])
	}

	// 删除
	w = doReq(r, authedReq(http.MethodDelete, fmt.Sprintf("/api/rules/%d", id), token, nil))
	if w.Code != http.StatusOK {
		t.Fatalf("delete: %d", w.Code)
	}
	w = doReq(r, authedReq(http.MethodGet, "/api/rules", token, nil))
	_ = json.Unmarshal(w.Body.Bytes(), &rules)
	if len(rules) != 0 {
		t.Errorf("after delete: %d", len(rules))
	}
}

// TestRules_Publish 发布规则集：Redis 存在规则集与版本，版本自增
func TestRules_Publish(t *testing.T) {
	db := newTestDB(t)
	mr, mgr := newTestRedis(t)
	r := newTestRouter(t, db, mgr)
	token := doLogin(t, r)

	// 空规则集发布
	w := doReq(r, authedReq(http.MethodPost, "/api/rules/publish", token, nil))
	if w.Code != http.StatusOK {
		t.Fatalf("publish empty: %d %s", w.Code, w.Body.String())
	}
	var resp struct {
		Status    string `json:"status"`
		RuleCount int    `json:"rule_count"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	if resp.Status != "ok" || resp.RuleCount != 0 {
		t.Errorf("publish empty resp: %+v", resp)
	}

	// 创建规则后发布
	w = doReq(r, authedReq(http.MethodPost, "/api/rules", token, newRuleBody()))
	if w.Code != http.StatusCreated {
		t.Fatalf("create: %d", w.Code)
	}
	w = doReq(r, authedReq(http.MethodPost, "/api/rules/publish", token, nil))
	if w.Code != http.StatusOK {
		t.Fatalf("publish: %d %s", w.Code, w.Body.String())
	}
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	if resp.RuleCount != 1 {
		t.Errorf("rule_count = %d", resp.RuleCount)
	}

	// Redis 中应有规则集与版本
	if _, err := mr.Get("waf:rule:ruleset"); err != nil {
		t.Errorf("ruleset not in redis: %v", err)
	}
	ver1, _ := mr.Get("waf:rule:version")
	if ver1 == "" {
		t.Error("version empty")
	}

	// 再次发布版本自增
	w = doReq(r, authedReq(http.MethodPost, "/api/rules/publish", token, nil))
	if w.Code != http.StatusOK {
		t.Fatalf("publish again: %d", w.Code)
	}
	ver2, _ := mr.Get("waf:rule:version")
	if ver2 == ver1 {
		t.Errorf("version not incremented: %s", ver2)
	}
}

// TestRules_PublishNoRedis 未配置 Redis 发布 → 500
func TestRules_PublishNoRedis(t *testing.T) {
	db := newTestDB(t)
	r := newTestRouter(t, db, nil)
	token := doLogin(t, r)
	w := doReq(r, authedReq(http.MethodPost, "/api/rules/publish", token, nil))
	if w.Code != http.StatusInternalServerError {
		t.Errorf("publish no redis: %d", w.Code)
	}
}
