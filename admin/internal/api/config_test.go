package api

import (
	"encoding/json"
	"net/http"
	"testing"
)

// TestConfig_GetDefault 未保存配置时返回默认配置
func TestConfig_GetDefault(t *testing.T) {
	db := newTestDB(t)
	r := newTestRouter(t, db, nil)
	token := doLogin(t, r)

	w := doReq(r, authedReq(http.MethodGet, "/api/config", token, nil))
	if w.Code != http.StatusOK {
		t.Fatalf("get: %d", w.Code)
	}
	var resp struct {
		Config map[string]interface{} `json:"config"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	if resp.Config == nil {
		t.Fatal("config nil")
	}
	if resp.Config["mode"] == nil {
		t.Errorf("config missing mode: %v", resp.Config)
	}
	if det, _ := resp.Config["detection"].(map[string]interface{}); det == nil || det["skip_static"] == nil {
		t.Errorf("config missing detection.skip_static: %v", resp.Config)
	}
	if resp.Config["trusted_proxies"] == nil {
		t.Errorf("config missing trusted_proxies: %v", resp.Config)
	}
}

// TestConfig_SaveAndGet 保存配置下发 Redis，再回读
func TestConfig_SaveAndGet(t *testing.T) {
	db := newTestDB(t)
	mr, mgr := newTestRedis(t)
	r := newTestRouter(t, db, mgr)
	token := doLogin(t, r)

	cfg := map[string]interface{}{
		"mode":    "detect",
		"modules": map[string]interface{}{"sqli": true, "xss": false},
	}
	w := doReq(r, authedReq(http.MethodPut, "/api/config", token,
		map[string]interface{}{"config": cfg}))
	if w.Code != http.StatusOK {
		t.Fatalf("save: %d %s", w.Code, w.Body.String())
	}

	// Redis 已下发
	if _, err := mr.Get("waf:config:data"); err != nil {
		t.Errorf("config data not in redis: %v", err)
	}
	if _, err := mr.Get("waf:config:version"); err != nil {
		t.Errorf("config version not in redis: %v", err)
	}

	// 回读
	w = doReq(r, authedReq(http.MethodGet, "/api/config", token, nil))
	if w.Code != http.StatusOK {
		t.Fatalf("get after save: %d", w.Code)
	}
	var resp struct {
		Config map[string]interface{} `json:"config"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	if resp.Config["mode"] != "detect" {
		t.Errorf("mode = %v", resp.Config["mode"])
	}
}

// TestConfig_SaveNoConfig 空 config → 400
func TestConfig_SaveNoConfig(t *testing.T) {
	db := newTestDB(t)
	_, mgr := newTestRedis(t)
	r := newTestRouter(t, db, mgr)
	token := doLogin(t, r)

	w := doReq(r, authedReq(http.MethodPut, "/api/config", token, map[string]interface{}{}))
	if w.Code != http.StatusBadRequest {
		t.Errorf("empty config: %d", w.Code)
	}
}

// TestConfig_SaveNoRedis 未配置 Redis → 400
func TestConfig_SaveNoRedis(t *testing.T) {
	db := newTestDB(t)
	r := newTestRouter(t, db, nil)
	token := doLogin(t, r)

	w := doReq(r, authedReq(http.MethodPut, "/api/config", token,
		map[string]interface{}{"config": map[string]interface{}{"mode": "detect"}}))
	if w.Code != http.StatusBadRequest {
		t.Errorf("no redis: %d %s", w.Code, w.Body.String())
	}
}
