package api

import (
	"encoding/json"
	"net/http"
	"strconv"
	"testing"
	"time"

	"openresty-waf/admin/internal/model"
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
// TestConfig_SaveLargeBody 审计中间件不得截断请求体：
// 完整配置（>2048 字节，含长黑白名单）保存应成功
func TestConfig_SaveLargeBody(t *testing.T) {
	db := newTestDB(t)
	_, mgr := newTestRedis(t)
	r := newTestRouter(t, db, mgr)
	token := doLogin(t, r)

	big := make([]string, 0, 300)
	for i := 0; i < 300; i++ {
		big = append(big, "10.0."+strconv.Itoa(i/256)+"."+strconv.Itoa(i%256))
	}
	cfg := map[string]interface{}{
		"mode": "active",
		"blacklist": map[string]interface{}{
			"ips":  big,
			"urls": []string{},
		},
		"whitelist": map[string]interface{}{
			"ips":  []string{"127.0.0.1"},
			"urls": []string{"/favicon.ico"},
		},
	}
	body, _ := json.Marshal(map[string]interface{}{"config": cfg})
	if len(body) < 2048 {
		t.Fatalf("test body too small: %d bytes", len(body))
	}
	w := doReq(r, authedReq(http.MethodPut, "/api/config", token,
		map[string]interface{}{"config": cfg}))
	if w.Code != http.StatusOK {
		t.Fatalf("save large body: %d %s (body %d bytes)", w.Code, w.Body.String(), len(body))
	}
}

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

// TestConfig_Versions 版本健康信息：Redis 版本号 + 最近事件引擎版本
func TestConfig_Versions(t *testing.T) {
	db := newTestDB(t)
	mr, mgr := newTestRedis(t)
	r := newTestRouter(t, db, mgr)
	token := doLogin(t, r)

	// Redis 版本号 + 一个携带引擎版本的事件
	mr.Set("waf:rule:version", "5")
	mr.Set("waf:config:version", "3")
	db.Create(&model.Event{Time: time.Now(), ClientIP: "1.2.3.4", EngineVersion: "0.6.0"})

	w := doReq(r, authedReq(http.MethodGet, "/api/config/versions", token, nil))
	if w.Code != http.StatusOK {
		t.Fatalf("versions: %d %s", w.Code, w.Body.String())
	}
	var resp struct {
		EngineVersion string `json:"engine_version"`
		RuleVersion   string `json:"rule_version"`
		ConfigVersion string `json:"config_version"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	if resp.EngineVersion != "0.6.0" {
		t.Errorf("engine_version = %q", resp.EngineVersion)
	}
	if resp.RuleVersion != "5" || resp.ConfigVersion != "3" {
		t.Errorf("versions = %q/%q", resp.RuleVersion, resp.ConfigVersion)
	}
}
