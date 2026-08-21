package service

import (
	"testing"

	"github.com/alicebob/miniredis/v2"
	"github.com/glebarez/sqlite"
	"gorm.io/gorm"

	"openresty-waf/admin/internal/config"
	"openresty-waf/admin/internal/model"
)

// newTestDB 内存 SQLite + 全量迁移
func newTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	if err := db.AutoMigrate(&model.User{}, &model.Rule{},
		&model.Event{}, &model.Setup{}, &model.IpListSubscription{},
		&model.TrafficLog{}, &model.ChallengeLog{}, &model.TriggerRule{},
		&model.CcLog{}, &model.PublishHistory{},
		&model.AlertChannel{}, &model.AlertRule{}, &model.AuditLog{},
		&model.BotProfile{}, &model.BotFingerprint{}, &model.BotLog{},
		&model.ApiToken{},
		&model.Ja4Profile{}, &model.RulePerf{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return db
}

// newTestRedis 内存 Redis（miniredis）+ 已连接的 RedisManager
func newTestRedis(t *testing.T) (*miniredis.Miniredis, *RedisManager) {
	t.Helper()
	mr := miniredis.RunT(t)
	mgr := NewRedisManager()
	mgr.Replace(&RedisConfig{Addr: mr.Addr()})
	return mr, mgr
}

func newTestConfig() *config.Config {
	return config.Load()
}
