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

	// 人机验证事件：定时消费 Redis 队列实时落库（每 3 秒）
	challengeSvc := service.NewChallengeService(db, mgr, cfg)
	go func() {
		ticker := time.NewTicker(3 * time.Second)
		defer ticker.Stop()
		for range ticker.C {
			if mgr.GetClient() == nil {
				continue
			}
			if _, err := challengeSvc.Consume(100); err != nil {
				log.Printf("消费人机验证事件失败: %v", err)
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

	// 全量流量记录：定时消费队列实时落库 + 按配置保留天数自动清理过期记录
	trafficSvc := service.NewTrafficService(db, mgr, cfg)
	wafCfgSvc := service.NewWafConfigService(db, mgr, cfg)
	go func() {
		ticker := time.NewTicker(3 * time.Second)
		defer ticker.Stop()
		for range ticker.C {
			if mgr.GetClient() == nil {
				continue
			}
			if _, err := trafficSvc.Consume(100); err != nil {
				log.Printf("消费流量记录失败: %v", err)
			}
		}
	}()
	go func() {
		ticker := time.NewTicker(6 * time.Hour)
		defer ticker.Stop()
		for range ticker.C {
			if mgr.GetClient() == nil {
				continue
			}
			days := 7
			if cfgMap, err := wafCfgSvc.Get(); err == nil {
				if tl, ok := cfgMap["traffic_log"].(map[string]interface{}); ok {
					if v, ok := tl["retention_days"].(float64); ok && v > 0 {
						days = int(v)
					}
				}
			}
			if n, err := trafficSvc.Cleanup(days); err != nil {
				log.Printf("清理流量记录失败: %v", err)
			} else if n > 0 {
				log.Printf("已清理 %d 天前的流量记录 %d 条", days, n)
			}
		}
	}()

	// 爬虫识别记录：定时消费 Redis 队列实时落库（每 3 秒）
	botSvc := service.NewBotService(db, mgr, cfg)
	// 内置订阅初始化（爬虫画像库 / JA4 客户端库），替代旧 seed 直接写入
	if err := service.NewIpListService(db, mgr, cfg).EnsureBuiltinSubscriptions(); err != nil {
		log.Printf("初始化内置订阅失败: %v", err)
	}
	go func() {
		ticker := time.NewTicker(3 * time.Second)
		defer ticker.Stop()
		for range ticker.C {
			if mgr.GetClient() == nil {
				continue
			}
			if _, err := botSvc.Consume(100); err != nil {
				log.Printf("消费爬虫记录失败: %v", err)
			}
		}
	}()

	// 告警规则定时检查（每 10 秒）：事件风暴 / 引擎离线 → 通知通道 + 可选自动回滚
	alertSvc := service.NewAlertService(db, mgr, cfg)
	go func() {
		ticker := time.NewTicker(10 * time.Second)
		defer ticker.Stop()
		for range ticker.C {
			if mgr.GetClient() == nil {
				continue
			}
			if n := alertSvc.CheckAll(); n > 0 {
				log.Printf("告警规则触发 %d 条", n)
			}
		}
	}()

	r := api.NewRouter(cfg, db, mgr)
	log.Printf("WAF 管理后台启动，监听 %s", cfg.Server.Addr)
	if err := r.Run(cfg.Server.Addr); err != nil {
		log.Fatalf("服务启动失败: %v", err)
	}
}
