// Package database 初始化 GORM 数据库连接并自动迁移表结构。
package database

import (
	"log"
	"strings"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"

	"openresty-waf/admin/internal/config"
	"openresty-waf/admin/internal/model"
)

func Init(cfg *config.Config) *gorm.DB {
	dsn := cfg.DB.DSN
	// SQLite 优化（glebarez/sqlite 基于 modernc，_pragma 参数对每个新连接生效）：
	//   journal_mode=WAL    并发读写（单写多读），消费 goroutine 与 API 查询不互相阻塞
	//   busy_timeout=5000   写锁竞争时等待而非立即报错
	//   synchronous=NORMAL  WAL 下适度降级 fsync 频率，提升批量入库吞吐
	sep := "?"
	if strings.Contains(dsn, "?") {
		sep = "&"
	}
	dsn = dsn + sep + "_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)&_pragma=synchronous(NORMAL)"

	db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{})
	if err != nil {
		log.Fatalf("初始化数据库失败: %v", err)
	}

	if err := db.AutoMigrate(&model.User{}, &model.Rule{},
		&model.Event{}, &model.Setup{}, &model.IpListSubscription{},
		&model.TrafficLog{}, &model.ChallengeLog{}, &model.TriggerRule{},
		&model.CcLog{}, &model.PublishHistory{},
		&model.AlertChannel{}, &model.AlertRule{}); err != nil {
		log.Fatalf("数据库迁移失败: %v", err)
	}

	return db
}
