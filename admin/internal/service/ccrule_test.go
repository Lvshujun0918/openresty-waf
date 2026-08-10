package service

import (
	"encoding/json"
	"testing"

	"openresty-waf/admin/internal/model"
)

func TestCcRuleService_CRUD(t *testing.T) {
	db := newTestDB(t)
	s := NewCcRuleService(db, NewRedisManager(), newTestConfig())

	// 空列表
	rules, err := s.List()
	if err != nil || len(rules) != 0 {
		t.Fatalf("list empty: len=%d err=%v", len(rules), err)
	}

	// 创建（rate 必填）
	if err := s.Create(&model.CcRule{Name: "bad"}); err == nil {
		t.Fatal("expected error for empty rate")
	}
	r1 := &model.CcRule{Name: "全局限流", Rate: "100/60", BanDuration: 300, SortOrder: 1}
	if err := s.Create(r1); err != nil {
		t.Fatalf("create: %v", err)
	}
	// BanDuration <= 0 时兜底为 300
	r2 := &model.CcRule{Name: "API 限流", Host: "api.example.com", Path: "/v1", Rate: "30/60", BanDuration: 0, SortOrder: 2}
	if err := s.Create(r2); err != nil {
		t.Fatalf("create2: %v", err)
	}
	if r2.BanDuration != 300 {
		t.Errorf("ban_duration default = %d", r2.BanDuration)
	}

	rules, _ = s.List()
	if len(rules) != 2 {
		t.Fatalf("list = %d", len(rules))
	}
	if rules[0].Rate != "100/60" {
		t.Errorf("sort order: first rate = %s", rules[0].Rate)
	}

	// 更新
	r1.Rate = "200/60"
	if err := s.Update(r1.ID, r1); err != nil {
		t.Fatalf("update: %v", err)
	}
	rules, _ = s.List()
	if rules[0].Rate != "200/60" {
		t.Errorf("after update rate = %s", rules[0].Rate)
	}
	// 更新不存在
	if err := s.Update(99999, r1); err == nil {
		t.Fatal("expected error for missing rule")
	}

	// 启停
	if err := s.SetEnabled(r2.ID, false); err != nil {
		t.Fatalf("set enabled: %v", err)
	}
	rules, _ = s.List()
	for _, r := range rules {
		if r.ID == r2.ID && r.Enabled {
			t.Error("rule 2 should be disabled")
		}
	}

	// 删除
	if err := s.Delete(r1.ID); err != nil {
		t.Fatalf("delete: %v", err)
	}
	rules, _ = s.List()
	if len(rules) != 1 {
		t.Fatalf("after delete = %d", len(rules))
	}
}

func TestCcRuleService_Publish(t *testing.T) {
	// 未配置 Redis
	db := newTestDB(t)
	s := NewCcRuleService(db, NewRedisManager(), newTestConfig())
	if _, err := s.Publish(); err == nil {
		t.Fatal("expected error without redis")
	}

	// 配置 Redis + 发布
	mr, mgr := newTestRedis(t)
	db = newTestDB(t)
	s = NewCcRuleService(db, mgr, newTestConfig())

	// 空规则集发布
	rs, err := s.Publish()
	if err != nil {
		t.Fatalf("publish empty: %v", err)
	}
	if len(rs.Rules) != 0 {
		t.Errorf("empty rules = %d", len(rs.Rules))
	}

	// 创建两条规则（一条禁用）后发布
	db.Create(&model.CcRule{Name: "全局", Rate: "100/60", Enabled: true})
	// bool 零值 false 会被 GORM 跳过（走 DB default:true），用 Update 显式置 false
	disabled := &model.CcRule{Name: "禁用", Rate: "10/60", Enabled: true}
	db.Create(disabled)
	db.Model(&model.CcRule{}).Where("id = ?", disabled.ID).Update("enabled", false)

	rs, err = s.Publish()
	if err != nil {
		t.Fatalf("publish: %v", err)
	}
	if len(rs.Rules) != 1 {
		t.Fatalf("published rules = %d", len(rs.Rules))
	}

	// Redis 中存在规则集与版本
	body, err := mr.Get("waf:cc:rules")
	if err != nil {
		t.Fatalf("cc rules not in redis: %v", err)
	}
	var decoded struct {
		Version string `json:"version"`
		Rules   []model.CcRule `json:"rules"`
	}
	if err := json.Unmarshal([]byte(body), &decoded); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(decoded.Rules) != 1 || decoded.Rules[0].Name != "全局" {
		t.Errorf("redis rules = %+v", decoded.Rules)
	}
	if _, err := mr.Get("waf:cc:version"); err != nil {
		t.Errorf("cc version not in redis: %v", err)
	}
}
