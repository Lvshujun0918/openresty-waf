// 管理后台入口：Go + Gin + GORM
package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"

	"openresty-waf/admin/internal/api"
	"openresty-waf/admin/internal/config"
	"openresty-waf/admin/internal/database"
	"openresty-waf/admin/internal/model"
	"openresty-waf/admin/internal/service"
)

// ensureJWTSecret 保证 JWT 签名密钥不可预测：
// 显式配置了非默认密钥时直接使用；否则从数据库读取已持久化的密钥，
// 首次启动生成随机 32 字节并存储（重启后沿用，已有会话不失效）。
func ensureJWTSecret(cfg *config.Config, db *gorm.DB) {
	if cfg.JWT.Secret != "" && cfg.JWT.Secret != config.DefaultJWTSecret {
		return
	}
	const key = "admin_jwt_secret"
	var row model.Setup
	if err := db.Where("key = ?", key).First(&row).Error; err == nil && row.Value != "" {
		cfg.JWT.Secret = row.Value
		return
	}
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		log.Fatalf("生成 JWT 签名密钥失败: %v", err)
	}
	cfg.JWT.Secret = hex.EncodeToString(buf)
	if err := db.Create(&model.Setup{Key: key, Value: cfg.JWT.Secret}).Error; err != nil {
		log.Fatalf("保存 JWT 签名密钥失败: %v", err)
	}
	log.Printf("已生成随机 JWT 签名密钥并持久化（未配置 ADMIN_JWT_SECRET）")
}

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
		log.Printf("未设置 ADMIN_INIT_PASSWORD，已创建默认初始密码，请尽快登录修改")
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		log.Fatalf("生成默认管理员密码失败: %v", err)
	}
	if err := db.Create(&model.User{Username: "admin", PasswordHash: string(hash)}).Error; err != nil {
		log.Fatalf("创建默认管理员失败: %v", err)
	}
	log.Printf("已创建默认管理员 admin，请尽快登录修改初始密码")
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
	ensureJWTSecret(cfg, db)
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

	// 规则耗时画像：定时消费引擎上报快照累计落库（每 60 秒，与引擎上报周期匹配）
	rulePerfSvc := service.NewRulePerfService(db, mgr, cfg)
	go func() {
		ticker := time.NewTicker(time.Minute)
		defer ticker.Stop()
		for range ticker.C {
			if mgr.GetClient() == nil {
				continue
			}
			if _, err := rulePerfSvc.Consume(100); err != nil {
				log.Printf("消费规则耗时画像失败: %v", err)
			}
		}
	}()

	// 引擎报错汇总：定时消费 Redis 队列落库（每 3 秒，「报错汇总」页展示）
	errorLogSvc := service.NewErrorLogService(db, mgr, cfg)
	go func() {
		ticker := time.NewTicker(3 * time.Second)
		defer ticker.Stop()
		for range ticker.C {
			if mgr.GetClient() == nil {
				continue
			}
			if _, err := errorLogSvc.Consume(200); err != nil {
				log.Printf("消费报错汇总失败: %v", err)
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

	// 远程规则订阅源定时同步（每分钟检查到期订阅）
	ruleSubSvc := service.NewRuleSubService(db, mgr, cfg)
	go func() {
		ticker := time.NewTicker(time.Minute)
		defer ticker.Stop()
		for range ticker.C {
			if mgr.GetClient() == nil {
				continue
			}
			ruleSubSvc.SyncAll()
		}
	}()

	// 全量流量记录：定时消费队列实时落库
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
	// 数据保留轮转（每 6 小时）：按配置保留天数清理 流量记录/攻击事件/审计日志，
	// 防止高频写入表无限膨胀；保留天数从 WAF 配置对应 section 读取，缺省兜底。
	auditSvc := service.NewAuditService(db)
	go func() {
		ticker := time.NewTicker(6 * time.Hour)
		defer ticker.Stop()
		for range ticker.C {
			if mgr.GetClient() == nil {
				continue
			}
			cfgMap := map[string]interface{}{}
			if m, err := wafCfgSvc.Get(); err == nil {
				cfgMap = m
			}
			jobs := []struct {
				name    string
				section string
				defDays int
				run     func(days int) (int64, error)
			}{
				{"流量记录", "traffic_log", 7, trafficSvc.Cleanup},
				{"攻击事件", "event_log", 30, eventSvc.Cleanup},
				{"审计日志", "audit_log", 90, auditSvc.Cleanup},
			}
			for _, j := range jobs {
				days := j.defDays
				if sec, ok := cfgMap[j.section].(map[string]interface{}); ok {
					if v, ok := sec["retention_days"].(float64); ok && v > 0 {
						days = int(v)
					}
				}
				n, err := j.run(days)
				if err != nil {
					log.Printf("清理%s失败: %v", j.name, err)
				} else if n > 0 {
					log.Printf("已清理 %d 天前的%s %d 条", days, j.name, n)
				}
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

	// 优雅关闭：docker stop / kill 发送 SIGTERM 后，停止接收新连接并等待在途请求完成，
	// 避免重启瞬间请求被硬切断；未消费的 Redis 事件队列天然持久，重启后继续消费。
	srv := &http.Server{Addr: cfg.Server.Addr, Handler: r}
	go func() {
		log.Printf("WAF 管理后台启动，监听 %s", cfg.Server.Addr)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("服务启动失败: %v", err)
		}
	}()

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	<-ctx.Done()
	log.Printf("收到退出信号，开始优雅关闭…")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		log.Printf("优雅关闭超时（仍有在途请求未完成）: %v", err)
	} else {
		log.Printf("WAF 管理后台已优雅退出")
	}
}
