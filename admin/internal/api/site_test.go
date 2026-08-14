package api

import (
	"encoding/json"
	"net/http"
	"strconv"
	"testing"
)

func TestSite_CRUD(t *testing.T) {
	db := newTestDB(t)
	r := newTestRouter(t, db, nil)
	token := doLogin(t, r)

	// 创建
	w := doReq(r, authedReq(http.MethodPost, "/api/sites", token,
		map[string]interface{}{"name": "主站", "domain": "cszj.wang"}))
	if w.Code != http.StatusOK {
		t.Fatalf("create: %d %s", w.Code, w.Body.String())
	}
	var created struct {
		Site struct {
			ID     uint   `json:"id"`
			Domain string `json:"domain"`
		} `json:"site"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &created)
	if created.Site.Domain != "cszj.wang" || created.Site.ID == 0 {
		t.Fatalf("created: %s", w.Body.String())
	}

	// 重复域名 → 400
	w = doReq(r, authedReq(http.MethodPost, "/api/sites", token,
		map[string]interface{}{"name": "x", "domain": "cszj.wang"}))
	if w.Code != http.StatusBadRequest {
		t.Errorf("dup: %d", w.Code)
	}

	// 列表
	w = doReq(r, authedReq(http.MethodGet, "/api/sites", token, nil))
	if w.Code != http.StatusOK {
		t.Fatalf("list: %d", w.Code)
	}
	var list struct {
		Sites []map[string]interface{} `json:"sites"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &list)
	if len(list.Sites) != 1 {
		t.Fatalf("sites = %d", len(list.Sites))
	}

	// 更新
	w = doReq(r, authedReq(http.MethodPut,
		"/api/sites/"+strconv.FormatUint(uint64(created.Site.ID), 10), token,
		map[string]interface{}{"name": "主站2", "domain": "new.wang", "enabled": false}))
	if w.Code != http.StatusOK {
		t.Fatalf("update: %d %s", w.Code, w.Body.String())
	}

	// 删除
	w = doReq(r, authedReq(http.MethodDelete,
		"/api/sites/"+strconv.FormatUint(uint64(created.Site.ID), 10), token, nil))
	if w.Code != http.StatusOK {
		t.Fatalf("delete: %d %s", w.Code, w.Body.String())
	}
	w = doReq(r, authedReq(http.MethodGet, "/api/sites", token, nil))
	_ = json.Unmarshal(w.Body.Bytes(), &list)
	if len(list.Sites) != 0 {
		t.Errorf("after delete: %d", len(list.Sites))
	}
}

func TestSite_Unauthorized(t *testing.T) {
	db := newTestDB(t)
	r := newTestRouter(t, db, nil)
	w := doReq(r, authedReq(http.MethodGet, "/api/sites", "", nil))
	if w.Code != http.StatusUnauthorized {
		t.Errorf("no token: %d", w.Code)
	}
}