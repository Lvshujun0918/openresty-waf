// 管理后台入口：Go + Gin + GORM
package main

import (
	"log"
	"os"
	"time"

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

// seedRules 导入内置规则种子（带版本管理：版本变化时自动替换旧种子，保留用户自定义规则）
func seedRules(db *gorm.DB) {
	const key = "seed_version"
	var row model.Setup
	current := ""
	if err := db.Where("key = ?", key).First(&row).Error; err == nil {
		current = row.Value
	}
	if current == model.SeedVersion {
		return
	}

	// 升级/首次：删除旧内置种子（新机制 is_seed 标记 + 旧版本 ID 集合），导入新种子
	if err := db.Where("is_seed = ? OR rule_id IN ?", true, model.LegacySeedIDs).
		Delete(&model.Rule{}).Error; err != nil {
		log.Printf("清理旧内置规则失败: %v", err)
		return
	}
	for i := range model.SeedRules {
		model.SeedRules[i].IsSeed = true
	}
	if err := db.Create(&model.SeedRules).Error; err != nil {
		log.Printf("导入内置规则种子失败: %v", err)
		return
	}
	if row.ID == 0 {
		if err := db.Create(&model.Setup{Key: key, Value: model.SeedVersion}).Error; err != nil {
			log.Printf("记录种子版本失败: %v", err)
		}
	} else if err := db.Model(&row).Update("value", model.SeedVersion).Error; err != nil {
		log.Printf("更新种子版本失败: %v", err)
	}
	log.Printf("已导入 %d 条内置规则种子 (v%s)", len(model.SeedRules), model.SeedVersion)
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

	// 后台定时消费攻击事件队列（每 3 秒），引擎推送到 Redis 的事件实时落库，
	// 前端事件页无需手动触发即可看到最新拦截记录。
	eventSvc := service.NewEventService(db, mgr, cfg)
	go func() {
		ticker := time.NewTicker(3 * time.Second)
		defer ticker.Stop()
		for range ticker.C {
			if mgr.GetClient() == nil {
				continue // Redis 未配置（引导前）静默
			}
			if _, err := eventSvc.Consume(100); err != nil {
				log.Printf("消费攻击事件失败: %v", err)
			}
		}
	}()

	// 远程 IP 列表订阅定时同步（每分钟检查到期订阅）
	ipListSvc := service.NewIpListService(db, mgr, cfg)
	go func() {
		ticker := time.NewTicker(time.Minute)
		defer ticker.Stop()
		for range ticker.C {
			if mgr.GetClient() == nil {
				continue
			}
			ipListSvc.SyncAll()
		}
	}()

	r := api.NewRouter(cfg, db, mgr)
	log.Printf("WAF 管理后台启动，监听 %s", cfg.Server.Addr)
	if err := r.Run(cfg.Server.Addr); err != nil {
		log.Fatalf("服务启动失败: %v", err)
	}
}
