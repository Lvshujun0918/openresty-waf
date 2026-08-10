package api

import (
	"encoding/json"
	"net/http"
	"testing"
)

// TestEvents_EmptyAndConsume 空列表 → 压入事件 → 消费落库 → 过滤查询
func TestEvents_EmptyAndConsume(t *testing.T) {
	db := newTestDB(t)
	mr, mgr := newTestRedis(t)
	r := newTestRouter(t, db, mgr)
	token := doLogin(t, r)

	// 空列表
	w := doReq(r, authedReq(http.MethodGet, "/api/events", token, nil))
	if w.Code != http.StatusOK {
		t.Fatalf("list: %d", w.Code)
	}
	var lr struct {
		Total int           `json:"total"`
		Items []interface{} `json:"items"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &lr)
	if lr.Total != 0 {
		t.Errorf("initial total = %d", lr.Total)
	}

	// 压入一条攻击事件
	payload, _ := json.Marshal(map[string]interface{}{
		"time": "2026-08-10T10:00:00Z", "client_ip": "1.2.3.4", "method": "GET",
		"host": "example.com", "uri": "/?id=1", "rule_id": "20001", "group": "sqli",
		"msg": "SQL 注入", "severity": 2, "status": 403,
	})
	mr.Lpush("waf:event:list", string(payload))

	// 消费
	w = doReq(r, authedReq(http.MethodPost, "/api/events/consume", token, nil))
	if w.Code != http.StatusOK {
		t.Fatalf("consume: %d %s", w.Code, w.Body.String())
	}
	var cr struct {
		Status   string `json:"status"`
		Consumed int    `json:"consumed"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &cr)
	if cr.Status != "ok" || cr.Consumed != 1 {
		t.Errorf("consume resp: %+v", cr)
	}

	// 列表 1 条
	w = doReq(r, authedReq(http.MethodGet, "/api/events", token, nil))
	_ = json.Unmarshal(w.Body.Bytes(), &lr)
	if lr.Total != 1 {
		t.Errorf("total after consume = %d", lr.Total)
	}
	items := lr.Items
	if len(items) != 1 {
		t.Fatalf("items = %d", len(items))
	}
	first := items[0].(map[string]interface{})
	if first["client_ip"] != "1.2.3.4" {
		t.Errorf("client_ip = %v", first["client_ip"])
	}
	if first["rule_id"] != "20001" {
		t.Errorf("rule_id = %v", first["rule_id"])
	}

	// 过滤：命中与未命中
	w = doReq(r, authedReq(http.MethodGet, "/api/events?group=sqli", token, nil))
	_ = json.Unmarshal(w.Body.Bytes(), &lr)
	if lr.Total != 1 {
		t.Errorf("filter sqli total = %d", lr.Total)
	}
	w = doReq(r, authedReq(http.MethodGet, "/api/events?group=xss", token, nil))
	_ = json.Unmarshal(w.Body.Bytes(), &lr)
	if lr.Total != 0 {
		t.Errorf("filter xss total = %d", lr.Total)
	}
	w = doReq(r, authedReq(http.MethodGet, "/api/events?client_ip=1.2.3.4", token, nil))
	_ = json.Unmarshal(w.Body.Bytes(), &lr)
	if lr.Total != 1 {
		t.Errorf("filter ip total = %d", lr.Total)
	}
	w = doReq(r, authedReq(http.MethodGet, "/api/events?rule_id=20001", token, nil))
	_ = json.Unmarshal(w.Body.Bytes(), &lr)
	if lr.Total != 1 {
		t.Errorf("filter rule total = %d", lr.Total)
	}
}

// TestEvents_ConsumeBadData 队列中坏数据被跳过、可解析数据正常落库
func TestEvents_ConsumeBadData(t *testing.T) {
	db := newTestDB(t)
	mr, mgr := newTestRedis(t)
	r := newTestRouter(t, db, mgr)
	token := doLogin(t, r)

	mr.Lpush("waf:event:list", "{not-json")
	payload, _ := json.Marshal(map[string]interface{}{
		"time": "2026-08-10T10:00:00Z", "client_ip": "9.9.9.9", "rule_id": "10001",
	})
	mr.Lpush("waf:event:list", string(payload))

	w := doReq(r, authedReq(http.MethodPost, "/api/events/consume", token, nil))
	if w.Code != http.StatusOK {
		t.Fatalf("consume: %d", w.Code)
	}
	var cr struct {
		Consumed int `json:"consumed"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &cr)
	if cr.Consumed != 1 {
		t.Errorf("consumed = %d (bad data should be skipped)", cr.Consumed)
	}
}

// TestEvents_ConsumeNoRedis 未配置 Redis → 500
func TestEvents_ConsumeNoRedis(t *testing.T) {
	db := newTestDB(t)
	r := newTestRouter(t, db, nil)
	token := doLogin(t, r)

	w := doReq(r, authedReq(http.MethodPost, "/api/events/consume", token, nil))
	if w.Code != http.StatusInternalServerError {
		t.Errorf("consume no redis: %d", w.Code)
	}
}

// TestEvents_Pagination 分页参数边界
func TestEvents_Pagination(t *testing.T) {
	db := newTestDB(t)
	r := newTestRouter(t, db, nil)
	token := doLogin(t, r)

	// page_size 超上限被钳制为 20
	w := doReq(r, authedReq(http.MethodGet, "/api/events?page=0&page_size=999", token, nil))
	if w.Code != http.StatusOK {
		t.Fatalf("list: %d", w.Code)
	}
	var lr struct {
		Page     int `json:"page"`
		PageSize int `json:"page_size"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &lr)
	if lr.Page != 1 {
		t.Errorf("page = %d", lr.Page)
	}
	if lr.PageSize != 20 {
		t.Errorf("page_size = %d", lr.PageSize)
	}
}
