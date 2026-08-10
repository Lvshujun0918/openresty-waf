package api

import (
	"encoding/json"
	"net/http"
	"testing"
)

func TestTraffic_ListAndStats(t *testing.T) {
	db := newTestDB(t)
	r := newTestRouter(t, db, nil)
	token := doLogin(t, r)

	// 空列表
	w := doReq(r, authedReq(http.MethodGet, "/api/traffic", token, nil))
	if w.Code != http.StatusOK {
		t.Fatalf("list: %d", w.Code)
	}
	var lr struct {
		Total int `json:"total"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &lr)
	if lr.Total != 0 {
		t.Errorf("total = %d", lr.Total)
	}

	// stats
	w = doReq(r, authedReq(http.MethodGet, "/api/traffic/stats", token, nil))
	if w.Code != http.StatusOK {
		t.Fatalf("stats: %d", w.Code)
	}
	var st struct {
		Total  int `json:"total"`
		Attack int `json:"attack"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &st)
	if st.Total != 0 || st.Attack != 0 {
		t.Errorf("stats: %+v", st)
	}
}

func TestTraffic_Consume(t *testing.T) {
	db := newTestDB(t)
	mr, mgr := newTestRedis(t)
	r := newTestRouter(t, db, mgr)
	token := doLogin(t, r)

	// 压入流量记录后消费
	mr.Lpush("waf:traffic:list",
		`{"time":"2026-01-01T00:00:00Z","client_ip":"1.2.3.4","method":"GET","host":"a.com","uri":"/","status":200,"attack":false}`)
	w := doReq(r, authedReq(http.MethodPost, "/api/traffic/consume", token, nil))
	if w.Code != http.StatusOK {
		t.Fatalf("consume: %d", w.Code)
	}
	var resp struct {
		Consumed int `json:"consumed"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	if resp.Consumed != 1 {
		t.Errorf("consumed = %d", resp.Consumed)
	}

	// 列表有 1 条
	w = doReq(r, authedReq(http.MethodGet, "/api/traffic", token, nil))
	var lr struct {
		Total int `json:"total"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &lr)
	if lr.Total != 1 {
		t.Errorf("total = %d", lr.Total)
	}
}

func TestTraffic_Cleanup(t *testing.T) {
	db := newTestDB(t)
	r := newTestRouter(t, db, nil)
	token := doLogin(t, r)

	w := doReq(r, authedReq(http.MethodPost, "/api/traffic/cleanup?days=7", token, nil))
	if w.Code != http.StatusOK {
		t.Fatalf("cleanup: %d %s", w.Code, w.Body.String())
	}
	var resp struct {
		Status string `json:"status"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	if resp.Status != "ok" {
		t.Errorf("cleanup resp: %+v", resp)
	}
}
