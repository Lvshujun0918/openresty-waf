// 管理后台入口：Go + Gin + GORM
package main

import (
	"log"
	"os"

	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"

	"openresty-waf/admin/internal/api"
	"openresty-waf/admin/internal/config"
	"openresty-waf/admin/internal/database"
	"openresty-waf/admin/internal/model"
	"openresty-waf/admin/internal/service"
)

// ensureDefaultAdmin 首次启动时创建默认管理员
// 账号 admin，密码取环境变量 ADMIN_INIT_PASSWORD，默认 admin123
func ensureDefaultAdmin(db *gorm.DB) {
	var count int64
	db.Model(&model.User{}).Count(&count)
	if count > 0 {
		return
	}
	password := os.Getenv("ADMIN_INIT_PASSWORD")
	if password == "" {
		password = "admin123"
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		log.Fatalf("生成默认管理员密码失败: %v", err)
	}
	if err := db.Create(&model.User{Username: "admin", PasswordHash: string(hash)}).Error; err != nil {
		log.Fatalf("创建默认管理员失败: %v", err)
	}
	log.Printf("已创建默认管理员 admin（初始密码: %s，请尽快修改）", password)
}

// seedRules 首次启动时导入内置规则种子（出厂基线防护）
func seedRules(db *gorm.DB) {
	var count int64
	db.Model(&model.Rule{}).Count(&count)
	if count > 0 {
		return
	}
	if err := db.Create(&model.SeedRules).Error; err != nil {
		log.Printf("导入内置规则种子失败: %v", err)
		return
	}
	log.Printf("已导入 %d 条内置规则种子", len(model.SeedRules))
}

func main() {
	cfg := config.Load()
	db := database.Init(cfg)
	ensureDefaultAdmin(db)
	seedRules(db)

	// 动态 Redis 客户端：启动无需 Redis，引导页配置后建立连接
	mgr := service.NewRedisManager()
	setupSvc := service.NewSetupService(db, mgr)
	mgr.LoadFromSetup(setupSvc)

	r := api.NewRouter(cfg, db, mgr)
	log.Printf("WAF 管理后台启动，监听 %s", cfg.Server.Addr)
	if err := r.Run(cfg.Server.Addr); err != nil {
		log.Fatalf("服务启动失败: %v", err)
	}
}
