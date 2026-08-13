// Package database 初始化 GORM 数据库连接并自动迁移表结构。
package database

import (
	"log"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"

	"openresty-waf/admin/internal/config"
	"openresty-waf/admin/internal/model"
)

func Init(cfg *config.Config) *gorm.DB {
	db, err := gorm.Open(sqlite.Open(cfg.DB.DSN), &gorm.Config{})
	if err != nil {
		log.Fatalf("初始化数据库失败: %v", err)
	}

	if err := db.AutoMigrate(&model.User{}, &model.Rule{}, &model.Site{},
		&model.Event{}, &model.Setup{}, &model.CcRule{}, &model.IpListSubscription{},
		&model.TrafficLog{}, &model.ChallengeLog{}, &model.TriggerRule{}); err != nil {
		log.Fatalf("数据库迁移失败: %v", err)
	}

	return db
}
