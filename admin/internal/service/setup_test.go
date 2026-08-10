package service

import (
	"testing"

	"github.com/alicebob/miniredis/v2"
)

func TestSetupService_SaveAndGet(t *testing.T) {
	mr := miniredis.RunT(t)
	db := newTestDB(t)
	mgr := NewRedisManager()
	s := NewSetupService(db, mgr)

	// 初始状态
	if s.IsDone() {
		t.Fatal("setup should not be done initially")
	}
	if _, ok := s.GetRedisConfig(); ok {
		t.Fatal("redis should not be configured initially")
	}

	// 保存（连接 miniredis 成功）
	if err := s.SaveRedisConfig(mr.Addr(), "", 0); err != nil {
		t.Fatalf("save redis: %v", err)
	}
	if !s.IsDone() {
		t.Fatal("setup should be done after save")
	}
	cfg, ok := s.GetRedisConfig()
	if !ok || cfg.Addr != mr.Addr() || cfg.DB != 0 {
		t.Fatalf("bad redis config: %+v ok=%v", cfg, ok)
	}
	if mgr.GetClient() == nil {
		t.Fatal("RedisManager should have a client after save")
	}

	// 空地址校验
	if err := s.SaveRedisConfig("", "", 0); err == nil {
		t.Fatal("expected error for empty addr")
	}

	// 不可达地址（端口 1 快速拒绝）
	if err := s.SaveRedisConfig("127.0.0.1:1", "", 0); err == nil {
		t.Fatal("expected error for unreachable addr")
	}
}
