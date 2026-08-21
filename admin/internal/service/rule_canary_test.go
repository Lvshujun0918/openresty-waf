package service

import (
	"encoding/json"
	"testing"

	"openresty-waf/admin/internal/model"
)

func TestRuleService_PublishCanaryValidation(t *testing.T) {
	db := newTestDB(t)
	mr, mgr := newTestRedis(t)
	s := NewRuleService(db, mgr, newTestConfig())
	db.Create(&model.Rule{RuleID: "1", Operator: "REGEX", Pattern: "a", Enabled: true})

	// 比例越界拒绝
	for _, p := range []int{-1, 101, 1000} {
		if _, err := s.PublishCanary(p, nil); err == nil {
			t.Errorf("percent=%d expected error, got nil", p)
		}
	}
	// 边界值合法（0 与 100 允许）
	for _, p := range []int{0, 100} {
		if _, err := s.PublishCanary(p, []string{"10.0.0.1"}); err != nil {
			t.Errorf("percent=%d unexpected error: %v", p, err)
		}
	}

	// 灰度键已写入
	if _, err := mr.Get("waf:rule:canary"); err != nil {
		t.Errorf("canary ruleset key missing: %v", err)
	}
	cfgBody, err := mr.Get("waf:rule:canary_cfg")
	if err != nil {
		t.Fatalf("canary cfg key missing: %v", err)
	}
	var cfg CanaryCfg
	if err := json.Unmarshal([]byte(cfgBody), &cfg); err != nil {
		t.Fatalf("cfg not json: %v", err)
	}
	if cfg.Percent != 100 || len(cfg.IPs) != 1 || cfg.IPs[0] != "10.0.0.1" {
		t.Errorf("unexpected cfg: %+v", cfg)
	}
	if v, _ := mr.Get("waf:rule:canary_version"); v == "" {
		t.Error("canary version key missing")
	}
}

func TestRuleService_CanaryStatus(t *testing.T) {
	db := newTestDB(t)
	_, mgr := newTestRedis(t)
	s := NewRuleService(db, mgr, newTestConfig())

	// 未开启灰度
	res, err := s.CanaryStatus()
	if err != nil {
		t.Fatalf("status: %v", err)
	}
	if res["active"] != false {
		t.Errorf("expected inactive, got %v", res["active"])
	}

	// 开启灰度后
	db.Create(&model.Rule{RuleID: "1", Operator: "REGEX", Pattern: "a", Enabled: true})
	if _, err := s.PublishCanary(25, []string{"192.168.1.1"}); err != nil {
		t.Fatalf("publish canary: %v", err)
	}
	res, err = s.CanaryStatus()
	if err != nil {
		t.Fatalf("status: %v", err)
	}
	if res["active"] != true {
		t.Fatalf("expected active, got %v", res)
	}
	if res["percent"] != 25 {
		t.Errorf("expected percent 25, got %v", res["percent"])
	}
	ips, ok := res["ips"].([]string)
	if !ok || len(ips) != 1 || ips[0] != "192.168.1.1" {
		t.Errorf("unexpected ips: %v", res["ips"])
	}
}

func TestRuleService_PromoteAndAbortCanary(t *testing.T) {
	db := newTestDB(t)
	mr, mgr := newTestRedis(t)
	s := NewRuleService(db, mgr, newTestConfig())

	// 无灰度记录时晋升报错
	if err := s.PromoteCanary(); err == nil {
		t.Fatal("expected error promoting without canary history")
	}

	db.Create(&model.Rule{RuleID: "1", Operator: "REGEX", Pattern: "a", Enabled: true})
	if _, err := s.PublishCanary(50, nil); err != nil {
		t.Fatalf("publish canary: %v", err)
	}

	// 晋升：稳定键写入、灰度三键清除、稳定历史新增
	if err := s.PromoteCanary(); err != nil {
		t.Fatalf("promote: %v", err)
	}
	if body, _ := mr.Get("waf:rule:ruleset"); body == "" {
		t.Error("stable ruleset key missing after promote")
	}
	if _, err := mr.Get("waf:rule:version"); err != nil {
		t.Errorf("stable version key missing: %v", err)
	}
	for _, k := range []string{"waf:rule:canary", "waf:rule:canary_cfg", "waf:rule:canary_version"} {
		if v, _ := mr.Get(k); v != "" {
			t.Errorf("canary key %s should be deleted after promote", k)
		}
	}
	var rulesCount, canaryCount int64
	db.Model(&model.PublishHistory{}).Where("kind = ?", "rules").Count(&rulesCount)
	db.Model(&model.PublishHistory{}).Where("kind = ?", "canary").Count(&canaryCount)
	if rulesCount != 1 {
		t.Errorf("expected 1 rules history after promote, got %d", rulesCount)
	}
	if canaryCount != 1 {
		t.Errorf("expected 1 canary history, got %d", canaryCount)
	}

	// 终止：再次灰度后 Abort 清除全部灰度键，状态回到未开启
	if _, err := s.PublishCanary(10, nil); err != nil {
		t.Fatalf("publish canary: %v", err)
	}
	if err := s.AbortCanary(); err != nil {
		t.Fatalf("abort: %v", err)
	}
	res, err := s.CanaryStatus()
	if err != nil {
		t.Fatalf("status: %v", err)
	}
	if res["active"] != false {
		t.Errorf("expected inactive after abort, got %v", res)
	}
}
