package service

import (
	"context"
	"encoding/json"
	"testing"

	"openresty-waf/admin/internal/model"
)

// newRulePerfSvc 构造使用 miniredis + 内存 sqlite 的画像服务
func newRulePerfSvc(t *testing.T) *RulePerfService {
	t.Helper()
	db := newTestDB(t)
	_, mgr := newTestRedis(t)
	return NewRulePerfService(db, mgr, newTestConfig())
}

// pushSnapshot 向队列推送一条引擎快照（JSON 数组，与 rule_perf.lua flush 一致）
func pushSnapshot(t *testing.T, svc *RulePerfService, arr []map[string]interface{}) {
	t.Helper()
	raw, err := json.Marshal(arr)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if err := svc.mgr.GetClient().RPush(context.Background(), RulePerfKey, raw).Err(); err != nil {
		t.Fatalf("rpush: %v", err)
	}
}

func TestRulePerf_ConsumeUpsertAccumulate(t *testing.T) {
	svc := newRulePerfSvc(t)

	pushSnapshot(t, svc, []map[string]interface{}{
		{"id": "920230", "n": 10, "total_us": 5000, "max_us": 900, "time": 1755000000},
		{"id": "942100", "n": 4, "total_us": 800, "max_us": 300, "time": 1755000000},
	})
	n, err := svc.Consume(100)
	if err != nil || n != 1 {
		t.Fatalf("first consume: n=%d err=%v", n, err)
	}

	pushSnapshot(t, svc, []map[string]interface{}{
		{"id": "920230", "n": 5, "total_us": 2000, "max_us": 1200, "time": 1755000060},
	})
	if _, err := svc.Consume(100); err != nil {
		t.Fatalf("second consume: %v", err)
	}

	var p model.RulePerf
	if err := svc.db.Where("rule_id = ?", "920230").First(&p).Error; err != nil {
		t.Fatalf("load: %v", err)
	}
	if p.Hits != 15 || p.TotalUS != 7000 {
		t.Fatalf("accumulate wrong: hits=%d total=%d", p.Hits, p.TotalUS)
	}
	if p.MaxUS != 1200 { // 历史最大保留
		t.Fatalf("max wrong: %d", p.MaxUS)
	}
	var p2 model.RulePerf
	if err := svc.db.Where("rule_id = ?", "942100").First(&p2).Error; err != nil {
		t.Fatalf("load 942100: %v", err)
	}
	if p2.Hits != 4 || p2.MaxUS != 300 {
		t.Fatalf("942100 wrong: hits=%d max=%d", p2.Hits, p2.MaxUS)
	}
}

func TestRulePerf_ListJoinsRuleMetaAndAvg(t *testing.T) {
	svc := newRulePerfSvc(t)
	svc.db.Create(&model.Rule{RuleID: "90001", Name: "SQL注入-union", Group: "sqli", Message: "sqli", Enabled: true})

	pushSnapshot(t, svc, []map[string]interface{}{
		{"id": "90001", "n": 4, "total_us": 1000, "max_us": 500, "time": 1755000000},
	})
	if _, err := svc.Consume(100); err != nil {
		t.Fatalf("consume: %v", err)
	}

	rows, err := svc.List(100)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("rows=%d", len(rows))
	}
	r := rows[0]
	if r.Name != "SQL注入-union" || r.Group != "sqli" || !r.Enabled {
		t.Fatalf("meta not joined: %+v", r)
	}
	if r.AvgUS != 250 {
		t.Fatalf("avg=%v want 250", r.AvgUS)
	}
}

func TestRulePerf_Reset(t *testing.T) {
	svc := newRulePerfSvc(t)
	pushSnapshot(t, svc, []map[string]interface{}{
		{"id": "1", "n": 1, "total_us": 10, "max_us": 10, "time": 1755000000},
	})
	if _, err := svc.Consume(100); err != nil {
		t.Fatalf("consume: %v", err)
	}
	if err := svc.Reset(); err != nil {
		t.Fatalf("reset: %v", err)
	}
	rows, _ := svc.List(100)
	if len(rows) != 0 {
		t.Fatalf("after reset rows=%d", len(rows))
	}
}

func TestRulePerf_ConsumeWithoutRedis(t *testing.T) {
	db := newTestDB(t)
	svc := NewRulePerfService(db, NewRedisManager(), newTestConfig())
	if _, err := svc.Consume(10); err == nil {
		t.Fatal("expected error when redis unconfigured")
	}
}
