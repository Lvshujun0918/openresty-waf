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

// TestSetupService_SaveRedisProtect 幂等保护：再次保存同地址时，
// 密码留空与 db=0 不应覆盖已保存的值（防前端未回显误覆盖）
func TestSetupService_SaveRedisProtect(t *testing.T) {
	mr := miniredis.RunT(t)
	db := newTestDB(t)
	mgr := NewRedisManager()
	s := NewSetupService(db, mgr)

	// 先保存 db8 + 密码
	if err := s.SaveRedisConfig(mr.Addr(), "secret", 8); err != nil {
		t.Fatalf("save db8: %v", err)
	}

	// 同地址再次保存：db=0、密码空 → 应保留 db8 与密码
	if err := s.SaveRedisConfig(mr.Addr(), "", 0); err != nil {
		t.Fatalf("resave: %v", err)
	}
	cfg, ok := s.GetRedisConfig()
	if !ok {
		t.Fatal("no config after resave")
	}
	if cfg.DB != 8 || cfg.Password != "secret" {
		t.Errorf("protected config = %+v (expect db=8 pass=secret)", cfg)
	}

	// 显式修改 db 为非 0 → 生效
	if err := s.SaveRedisConfig(mr.Addr(), "", 5); err != nil {
		t.Fatalf("save db5: %v", err)
	}
	cfg, _ = s.GetRedisConfig()
	if cfg.DB != 5 {
		t.Errorf("db = %d (expect 5)", cfg.DB)
	}
}
