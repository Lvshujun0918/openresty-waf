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

	r.GET("/api/health", func(c *gin.Context) {
		c.JSON(200, gin.H{"status": "ok"})
	})

	api := r.Group("/api")
	{
		api.POST("/auth/login", authHandler.Login)

		// 引导相关（公开：状态/指引/组件下载）
		api.GET("/setup/status", setupHandler.Status)
		api.GET("/setup/guide", setupHandler.Guide)
		api.GET("/setup/waf.tar.gz", setupHandler.DownloadWAF)
		api.GET("/setup/install.sh", setupHandler.InstallScript)

		authed := api.Group("", AuthMiddleware(authSvc))
		authed.Use(CSRFMiddleware())
		authed.Use(AuditMiddleware(auditSvc))
		{
			authed.GET("/auth/me", authHandler.Me)
			authed.POST("/auth/totp/setup", authHandler.TotpSetup)
			authed.POST("/auth/totp/confirm", authHandler.TotpConfirm)
			authed.DELETE("/auth/totp", authHandler.TotpDisable)
			authed.GET("/auth/sessions", authHandler.Sessions)
			authed.DELETE("/auth/sessions/:jti", authHandler.KickSession)

			// 引导配置（登录后）
			authed.POST("/setup/redis", setupHandler.SaveRedis)

			// 规则管理
			authed.GET("/rules", ruleHandler.List)
			authed.POST("/rules", ruleHandler.Create)
			authed.PUT("/rules/:id", ruleHandler.Update)
			authed.DELETE("/rules/:id", ruleHandler.Delete)
			authed.PATCH("/rules/:id/enabled", ruleHandler.SetEnabled)
			authed.POST("/rules/publish", ruleHandler.Publish)
			authed.POST("/rules/test", ruleHandler.Test)
			authed.GET("/rules/publish-history", ruleHandler.PublishHistory)
			authed.POST("/rules/rollback/:id", ruleHandler.Rollback)
			authed.GET("/rules/export", ruleHandler.Export)
			authed.POST("/rules/import", ruleHandler.Import)
			authed.GET("/rules/stats", ruleHandler.HitStats)

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

			// 攻击事件
			authed.GET("/events", eventHandler.List)
			authed.GET("/events/:id", eventHandler.Detail)
			authed.POST("/events/consume", eventHandler.Consume)
			authed.POST("/events/:id/ban", eventHandler.Ban)
			authed.POST("/events/:id/false-positive", eventHandler.MarkFalsePositive)
			authed.POST("/events/:id/exempt", eventHandler.Exempt)

			// 封禁管理（临时/永久封禁 IP）
			authed.GET("/bans", banHandler.List)
			authed.DELETE("/bans", banHandler.Unban)

			// 仪表盘聚合统计
			authed.GET("/dashboard/stats", dashboardHandler.Stats)

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
