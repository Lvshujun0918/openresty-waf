// Package api 路由与 HTTP 处理器。
package api

import (
	"mime"
	"net/http"
	"path/filepath"
	"strings"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"

	"openresty-waf/admin/internal/config"
	"openresty-waf/admin/internal/service"
	"openresty-waf/admin/internal/webui"
)

func NewRouter(cfg *config.Config, db *gorm.DB, mgr *service.RedisManager) *gin.Engine {
	r := gin.Default()
	r.Use(SecurityHeaders())
	r.Use(AllowedIP(cfg))

	authHandler := NewAuthHandler(db, mgr, cfg)
	authSvc := service.NewAuthService(db, mgr, cfg)
	ruleHandler := NewRuleHandler(db, mgr, cfg)
	rulePerfHandler := NewRulePerfHandler(db, mgr, cfg)
	eventHandler := NewEventHandler(db, mgr, cfg)
	setupHandler := NewSetupHandler(db, mgr, cfg)
	configHandler := NewConfigHandler(db, mgr, cfg)
	ipListHandler := NewIpListHandler(db, mgr, cfg)
	trafficHandler := NewTrafficHandler(db, mgr, cfg)
	dashboardHandler := NewDashboardHandler(db)
	challengeHandler := NewChallengeHandler(db, mgr, cfg)
	ccLogHandler := NewCcLogHandler(db, mgr, cfg)
	triggerRuleHandler := NewTriggerRuleHandler(db, mgr, cfg)
	banHandler := NewBanHandler(db, mgr, cfg)
	healthHandler := NewHealthHandler(mgr, cfg)
	alertHandler := NewAlertHandler(db, mgr, cfg)
	auditHandler := NewAuditHandler(db)
	auditSvc := service.NewAuditService(db)
	botHandler := NewBotHandler(db, mgr, cfg)
	ja4Handler := NewJa4Handler(db, mgr, cfg)
	backupHandler := NewBackupHandler(db, cfg)
	apiTokenSvc := service.NewApiTokenService(db)
	apiTokenHandler := NewApiTokenHandler(db)

	r.GET("/api/health", func(c *gin.Context) {
		c.JSON(200, gin.H{"status": "ok"})
	})

	api := r.Group("/api")
	{
		// 登录接口 IP 维度限流：令牌桶限速 + 失败锁定（与账号维度防爆破互补）
		loginLimiter := NewLoginRateLimiter()
		api.POST("/auth/login", loginLimiter.Middleware(), authHandler.Login)

		// 引导相关（公开：状态/组件/脚本下载——引擎机安装无需面板凭据；
		// guide 含 Redis 明文密码，必须登录后可见，见下方 authed 组）
		api.GET("/setup/status", setupHandler.Status)
		api.GET("/setup/waf.tar.gz", setupHandler.DownloadWAF)
		api.GET("/setup/install.sh", setupHandler.InstallScript)

		authed := api.Group("", AuthMiddleware(authSvc, apiTokenSvc))
		authed.Use(CSRFMiddleware())
		authed.Use(AuditMiddleware(auditSvc))
		{
			// API Token 管理（脚本/CI 非交互调用凭证）
			authed.GET("/tokens", apiTokenHandler.List)
			authed.POST("/tokens", apiTokenHandler.Create)
			authed.DELETE("/tokens/:id", apiTokenHandler.Revoke)

			authed.GET("/auth/me", authHandler.Me)
			authed.POST("/auth/totp/setup", authHandler.TotpSetup)
			authed.POST("/auth/totp/confirm", authHandler.TotpConfirm)
			authed.DELETE("/auth/totp", authHandler.TotpDisable)
			authed.GET("/auth/sessions", authHandler.Sessions)
			authed.DELETE("/auth/sessions/:jti", authHandler.KickSession)

			// 引导配置（登录后）
			authed.POST("/setup/redis", setupHandler.SaveRedis)
			authed.GET("/setup/guide", setupHandler.Guide)

			// 规则管理
			authed.GET("/rules", ruleHandler.List)
			authed.POST("/rules", ruleHandler.Create)
			authed.PUT("/rules/:id", ruleHandler.Update)
			authed.DELETE("/rules/:id", ruleHandler.Delete)
			authed.PATCH("/rules/:id/enabled", ruleHandler.SetEnabled)
			authed.POST("/rules/publish", ruleHandler.Publish)
			authed.POST("/rules/test", ruleHandler.Test)
			authed.POST("/rules/test-all", ruleHandler.TestAll)
			authed.GET("/rules/publish-history", ruleHandler.PublishHistory)
			authed.POST("/rules/rollback/:id", ruleHandler.Rollback)
			authed.GET("/rules/export", ruleHandler.Export)
			authed.POST("/rules/import", ruleHandler.Import)
			authed.GET("/rules/stats", ruleHandler.HitStats)
			// 规则耗时画像（引擎 rule_perf.lua 上报 → 后台聚合）
			authed.GET("/rules/perf", rulePerfHandler.List)
			authed.POST("/rules/perf/consume", rulePerfHandler.Consume)
			authed.DELETE("/rules/perf", rulePerfHandler.Reset)

			// IP 列表订阅（远程威胁情报 IP 列表）
			authed.GET("/ip-list-subs", ipListHandler.List)
			authed.POST("/ip-list-subs", ipListHandler.Create)
			authed.PUT("/ip-list-subs/:id", ipListHandler.Update)
			authed.DELETE("/ip-list-subs/:id", ipListHandler.Delete)
			authed.PATCH("/ip-list-subs/:id/enabled", ipListHandler.SetEnabled)
			authed.POST("/ip-list-subs/:id/sync", ipListHandler.Sync)

			// 全量流量记录
			authed.GET("/traffic", trafficHandler.List)
			authed.POST("/traffic/consume", trafficHandler.Consume)
			authed.POST("/traffic/cleanup", trafficHandler.Cleanup)
			authed.GET("/traffic/stats", trafficHandler.Stats)
			authed.GET("/traffic/trend", trafficHandler.Trend)
			authed.GET("/traffic/export", trafficHandler.Export)

			// 攻击事件
			authed.GET("/events", eventHandler.List)
			authed.GET("/events/:id", eventHandler.Detail)
			authed.POST("/events/consume", eventHandler.Consume)
			authed.POST("/events/:id/ban", eventHandler.Ban)
			authed.POST("/events/:id/false-positive", eventHandler.MarkFalsePositive)
			authed.POST("/events/:id/exempt", eventHandler.Exempt)
			authed.GET("/events/export", eventHandler.Export)

			// 封禁管理（临时/永久封禁 IP，支持 IP+UA 维度）
			authed.GET("/bans", banHandler.List)
			authed.POST("/bans", banHandler.Create)
			authed.DELETE("/bans", banHandler.Unban)

			// 仪表盘聚合统计
			authed.GET("/dashboard/stats", dashboardHandler.Stats)
			authed.GET("/dashboard/group-trend", dashboardHandler.GroupTrend)
			authed.GET("/dashboard/top-regions", dashboardHandler.TopRegions)

			// 引擎健康状态与实时监控
			authed.GET("/health/engines", healthHandler.Engines)
			authed.GET("/monitor/realtime", healthHandler.Realtime)

			// 告警通知（通道 + 规则）
			authed.GET("/alerts/channels", alertHandler.ListChannels)
			authed.POST("/alerts/channels", alertHandler.CreateChannel)
			authed.PUT("/alerts/channels/:id", alertHandler.UpdateChannel)
			authed.DELETE("/alerts/channels/:id", alertHandler.DeleteChannel)
			authed.POST("/alerts/channels/:id/test", alertHandler.TestChannel)
			authed.GET("/alerts/rules", alertHandler.ListRules)
			authed.POST("/alerts/rules", alertHandler.CreateRule)
			authed.PUT("/alerts/rules/:id", alertHandler.UpdateRule)
			authed.DELETE("/alerts/rules/:id", alertHandler.DeleteRule)
			authed.PATCH("/alerts/rules/:id/enabled", alertHandler.SetRuleEnabled)

			// 恶意指纹库（命中即拦截）
			authed.GET("/bots/fingerprints", botHandler.ListFingerprints)
			authed.POST("/bots/fingerprints", botHandler.CreateFingerprint)
			authed.PUT("/bots/fingerprints/:id", botHandler.UpdateFingerprint)
			authed.DELETE("/bots/fingerprints/:id", botHandler.DeleteFingerprint)

			// 爬虫画像库（UA + IP 段验证）
			authed.GET("/bots/profiles", botHandler.ListProfiles)
			authed.POST("/bots/profiles", botHandler.CreateProfile)
			authed.PUT("/bots/profiles/:id", botHandler.UpdateProfile)
			authed.DELETE("/bots/profiles/:id", botHandler.DeleteProfile)

			// 爬虫记录与统计
			authed.GET("/bots/logs", botHandler.ListLogs)
			authed.GET("/bots/logs/:id", botHandler.GetLog)

			// JA4 客户端指纹库与查询识别
			authed.GET("/ja4/profiles", ja4Handler.List)
			authed.POST("/ja4/profiles", ja4Handler.Create)
			authed.PUT("/ja4/profiles/:id", ja4Handler.Update)
			authed.DELETE("/ja4/profiles/:id", ja4Handler.Delete)
			authed.GET("/ja4/lookup", ja4Handler.Lookup)
			authed.GET("/ja4/export", ja4Handler.Export)
			authed.POST("/bots/consume", botHandler.ConsumeLogs)
			authed.POST("/bots/logs/:id/blacklist", botHandler.BlacklistLog)
			authed.GET("/bots/stats", botHandler.Stats)
			authed.GET("/bots/top", botHandler.Top)
			authed.GET("/bots/trend", botHandler.Trend)

			// 人机验证事件
			authed.GET("/challenges", challengeHandler.List)
			authed.POST("/challenges/consume", challengeHandler.Consume)

			// CC 触发事件
			authed.GET("/cc-logs", ccLogHandler.List)
			authed.POST("/cc-logs/consume", ccLogHandler.Consume)

			// 触发规则（host/UA/请求头/IP 等条件筛选）
			authed.GET("/trigger-rules", triggerRuleHandler.List)
			authed.POST("/trigger-rules", triggerRuleHandler.Create)
			authed.PUT("/trigger-rules/:id", triggerRuleHandler.Update)
			authed.DELETE("/trigger-rules/:id", triggerRuleHandler.Delete)
			authed.PATCH("/trigger-rules/:id/enabled", triggerRuleHandler.SetEnabled)
			authed.POST("/trigger-rules/publish", triggerRuleHandler.Publish)

			// 操作审计日志
			authed.GET("/audit-logs", auditHandler.ListAudits)

			// WAF 运行配置
			authed.GET("/config", configHandler.Get)
			authed.PUT("/config", configHandler.Save)
			authed.GET("/config/versions", configHandler.Versions)

			// 数据库备份（在线快照下载）
			authed.GET("/db/backup", backupHandler.Export)
		}
	}

	// 前端静态资源（SPA，从 embed 产物提供）
	r.GET("/", serveFrontend)
	r.GET("/assets/*filepath", serveFrontend)
	r.NoRoute(serveFrontend)

	return r
}

// serveFrontend 提供内嵌前端页面；非 /api 路径统一回退 index.html（SPA）
func serveFrontend(c *gin.Context) {
	p := c.Request.URL.Path
	if p == "/" {
		p = "/index.html"
	}
	if strings.HasPrefix(p, "/api") {
		c.JSON(http.StatusNotFound, gin.H{"error": "接口不存在"})
		return
	}

	data, err := webui.FS.ReadFile("dist" + p)
	if err != nil {
		// SPA fallback：未知路由返回入口页
		data, err = webui.FS.ReadFile("dist/index.html")
		if err != nil {
			c.String(http.StatusNotFound, "not found")
			return
		}
		c.Header("Content-Type", "text/html; charset=utf-8")
	} else if ct := mime.TypeByExtension(filepath.Ext(p)); ct != "" {
		c.Header("Content-Type", ct)
	}
	c.Status(http.StatusOK)
	_, _ = c.Writer.Write(data)
}
