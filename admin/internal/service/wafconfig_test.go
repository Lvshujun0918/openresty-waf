package service

import (
	"testing"
)

func TestWafConfigService_GetDefault(t *testing.T) {
	db := newTestDB(t)
	s := NewWafConfigService(db, nil, newTestConfig())

	cfg, err := s.Get()
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if cfg["mode"] != "active" {
		t.Errorf("mode = %v", cfg["mode"])
	}
	if cc, ok := cfg["cc"].(map[string]interface{}); !ok || cc["rate"] != "100/60" {
		t.Errorf("cc = %#v", cfg["cc"])
	}
	if blk, ok := cfg["block"].(map[string]interface{}); !ok || blk["status"] != 403 {
		t.Errorf("block = %#v", cfg["block"])
	}
	if ch, ok := cfg["challenge"].(map[string]interface{}); !ok || ch["mode"] != "basic" {
		t.Errorf("challenge = %#v", cfg["challenge"])
	}
}

func TestWafConfigService_Save(t *testing.T) {
	db := newTestDB(t)

	// 未配置 Redis → 报错
	s := NewWafConfigService(db, NewRedisManager(), newTestConfig())
	if err := s.Save(map[string]interface{}{"mode": "detect"}); err == nil {
		t.Fatal("expected error without redis")
	}

	// 配置 Redis
	mr, mgr := newTestRedis(t)
	db = newTestDB(t)
	s2 := NewWafConfigService(db, mgr, newTestConfig())
	custom := map[string]interface{}{"mode": "detect"}
	if err := s2.Save(custom); err != nil {
		t.Fatalf("save: %v", err)
	}

	got, err := s2.Get()
	if err != nil {
		t.Fatalf("get after save: %v", err)
	}
	if got["mode"] != "detect" {
		t.Errorf("mode after save = %v", got["mode"])
	}

	if _, err := mr.Get("waf:config:version"); err != nil {
		t.Errorf("config version key missing: %v", err)
	}
	body, err := mr.Get("waf:config:data")
	if err != nil || body == "" {
		t.Errorf("config data key missing: %v", err)
	}
}
