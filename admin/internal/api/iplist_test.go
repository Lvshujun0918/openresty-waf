package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestIpListSubs_CRUD(t *testing.T) {
	db := newTestDB(t)
	r := newTestRouter(t, db, nil)
	token := doLogin(t, r)

	// 空列表
	w := doReq(r, authedReq(http.MethodGet, "/api/ip-list-subs", token, nil))
	if w.Code != http.StatusOK {
		t.Fatalf("list: %d", w.Code)
	}
	var subs []map[string]interface{}
	_ = json.Unmarshal(w.Body.Bytes(), &subs)
	if len(subs) != 0 {
		t.Errorf("expected 0, got %d", len(subs))
	}

	// 创建
	body := map[string]interface{}{
		"name": "威胁情报", "url": "http://example.com/list.txt",
		"type": "blacklist", "interval_min": 60, "enabled": true,
	}
	w = doReq(r, authedReq(http.MethodPost, "/api/ip-list-subs", token, body))
	if w.Code != http.StatusCreated {
		t.Fatalf("create: %d %s", w.Code, w.Body.String())
	}
	var created map[string]interface{}
	_ = json.Unmarshal(w.Body.Bytes(), &created)
	id := int(created["id"].(float64))
	if id == 0 {
		t.Fatal("created id = 0")
	}

	// 非法 URL → 400
	w = doReq(r, authedReq(http.MethodPost, "/api/ip-list-subs", token,
		map[string]interface{}{"name": "x", "url": "ftp://x", "type": "whitelist"}))
	if w.Code != http.StatusBadRequest {
		t.Errorf("bad url: %d", w.Code)
	}

	// 更新 / 启停 / 删除
	w = doReq(r, authedReq(http.MethodPut, fmt.Sprintf("/api/ip-list-subs/%d", id), token,
		map[string]interface{}{"name": "改名", "url": "http://example.com/2.txt", "type": "whitelist", "interval_min": 30}))
	if w.Code != http.StatusOK {
		t.Fatalf("update: %d", w.Code)
	}
	w = doReq(r, authedReq(http.MethodPatch, fmt.Sprintf("/api/ip-list-subs/%d/enabled", id), token,
		map[string]interface{}{"enabled": false}))
	if w.Code != http.StatusOK {
		t.Fatalf("patch: %d", w.Code)
	}
	w = doReq(r, authedReq(http.MethodDelete, fmt.Sprintf("/api/ip-list-subs/%d", id), token, nil))
	if w.Code != http.StatusOK {
		t.Fatalf("delete: %d", w.Code)
	}
}

func TestIpListSubs_Sync(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("1.2.3.4\n5.6.7.8\n"))
	}))
	defer srv.Close()

	var subs []map[string]interface{}
	db := newTestDB(t)
	_, mgr := newTestRedis(t)
	r := newTestRouter(t, db, mgr)
	token := doLogin(t, r)

	w := doReq(r, authedReq(http.MethodPost, "/api/ip-list-subs", token,
		map[string]interface{}{"name": "源", "url": srv.URL + "/ip.txt", "type": "blacklist", "interval_min": 60}))
	if w.Code != http.StatusCreated {
		t.Fatalf("create: %d", w.Code)
	}
	var created map[string]interface{}
	_ = json.Unmarshal(w.Body.Bytes(), &created)
	id := int(created["id"].(float64))

	// 立即同步
	w = doReq(r, authedReq(http.MethodPost, fmt.Sprintf("/api/ip-list-subs/%d/sync", id), token, nil))
	if w.Code != http.StatusOK {
		t.Fatalf("sync: %d %s", w.Code, w.Body.String())
	}
	var resp struct {
		Status   string `json:"status"`
		Imported int    `json:"imported"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	if resp.Status != "ok" || resp.Imported != 2 {
		t.Errorf("sync resp: %+v", resp)
	}

	// 列表状态更新
	w = doReq(r, authedReq(http.MethodGet, "/api/ip-list-subs", token, nil))
	_ = json.Unmarshal(w.Body.Bytes(), &subs)
	if len(subs) != 1 {
		t.Fatalf("subs = %d", len(subs))
	}
	if subs[0]["last_status"] != "ok" {
		t.Errorf("last_status = %v", subs[0]["last_status"])
	}
}
