package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"testing"
)

func newCcRuleBody() map[string]interface{} {
	return map[string]interface{}{
		"name":         "API 限流",
		"host":         "api.example.com",
		"path":         "/v1",
		"rate":         "30/60",
		"ban_duration": 600,
		"enabled":      true,
		"sort_order":   1,
	}
}

func TestCcRules_CRUD(t *testing.T) {
	db := newTestDB(t)
	r := newTestRouter(t, db, nil)
	token := doLogin(t, r)

	// 空列表
	w := doReq(r, authedReq(http.MethodGet, "/api/cc-rules", token, nil))
	if w.Code != http.StatusOK {
		t.Fatalf("list: %d", w.Code)
	}
	var rules []map[string]interface{}
	_ = json.Unmarshal(w.Body.Bytes(), &rules)
	if len(rules) != 0 {
		t.Errorf("expected 0, got %d", len(rules))
	}

	// 创建
	w = doReq(r, authedReq(http.MethodPost, "/api/cc-rules", token, newCcRuleBody()))
	if w.Code != http.StatusCreated {
		t.Fatalf("create: %d %s", w.Code, w.Body.String())
	}
	var created map[string]interface{}
	_ = json.Unmarshal(w.Body.Bytes(), &created)
	id := int(created["id"].(float64))
	if id == 0 {
		t.Fatal("created id = 0")
	}
	if created["rate"] != "30/60" {
		t.Errorf("rate = %v", created["rate"])
	}

	// 缺 rate → 400
	w = doReq(r, authedReq(http.MethodPost, "/api/cc-rules", token,
		map[string]interface{}{"name": "bad"}))
	if w.Code != http.StatusBadRequest {
		t.Errorf("create invalid: %d", w.Code)
	}

	// 更新
	w = doReq(r, authedReq(http.MethodPut, fmt.Sprintf("/api/cc-rules/%d", id), token,
		map[string]interface{}{"name": "改名", "rate": "50/60"}))
	if w.Code != http.StatusOK {
		t.Fatalf("update: %d %s", w.Code, w.Body.String())
	}

	// 启停
	w = doReq(r, authedReq(http.MethodPatch, fmt.Sprintf("/api/cc-rules/%d/enabled", id), token,
		map[string]interface{}{"enabled": false}))
	if w.Code != http.StatusOK {
		t.Fatalf("disable: %d", w.Code)
	}
	w = doReq(r, authedReq(http.MethodGet, "/api/cc-rules", token, nil))
	_ = json.Unmarshal(w.Body.Bytes(), &rules)
	if len(rules) != 1 || rules[0]["enabled"] != false {
		t.Errorf("after disable: %+v", rules)
	}

	// 删除
	w = doReq(r, authedReq(http.MethodDelete, fmt.Sprintf("/api/cc-rules/%d", id), token, nil))
	if w.Code != http.StatusOK {
		t.Fatalf("delete: %d", w.Code)
	}
	w = doReq(r, authedReq(http.MethodGet, "/api/cc-rules", token, nil))
	_ = json.Unmarshal(w.Body.Bytes(), &rules)
	if len(rules) != 0 {
		t.Errorf("after delete: %d", len(rules))
	}
}

func TestCcRules_Publish(t *testing.T) {
	db := newTestDB(t)
	mr, mgr := newTestRedis(t)
	r := newTestRouter(t, db, mgr)
	token := doLogin(t, r)

	// 创建后发布
	w := doReq(r, authedReq(http.MethodPost, "/api/cc-rules", token, newCcRuleBody()))
	if w.Code != http.StatusCreated {
		t.Fatalf("create: %d", w.Code)
	}
	w = doReq(r, authedReq(http.MethodPost, "/api/cc-rules/publish", token, nil))
	if w.Code != http.StatusOK {
		t.Fatalf("publish: %d %s", w.Code, w.Body.String())
	}
	var resp struct {
		Status    string `json:"status"`
		RuleCount int    `json:"rule_count"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	if resp.Status != "ok" || resp.RuleCount != 1 {
		t.Errorf("publish resp: %+v", resp)
	}

	if _, err := mr.Get("waf:cc:rules"); err != nil {
		t.Errorf("cc rules not in redis: %v", err)
	}
	if _, err := mr.Get("waf:cc:version"); err != nil {
		t.Errorf("cc version not in redis: %v", err)
	}
}

func TestCcRules_PublishNoRedis(t *testing.T) {
	db := newTestDB(t)
	r := newTestRouter(t, db, nil)
	token := doLogin(t, r)

	w := doReq(r, authedReq(http.MethodPost, "/api/cc-rules/publish", token, nil))
	if w.Code != http.StatusInternalServerError {
		t.Errorf("publish no redis: %d", w.Code)
	}
}
