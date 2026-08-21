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

	d := newDeps(cfg, db, mgr)

	// API 版本化：/api/v1 为规范前缀；/api 保持旧路径兼容（前端与既有脚本零改造）
	registerAPIRoutes(r.Group("/api"), d)
	registerAPIRoutes(r.Group("/api/v1"), d)

	// 前端静态资源（SPA，从 embed 产物提供）
	r.GET("/", serveFrontend)
	r.GET("/assets/*filepath", serveFrontend)
	r.NoRoute(serveFrontend)

	return r
}

// apiDeps 聚合全部处理器与服务实例（多版本路由组共享同一套实例）。
type apiDeps struct {
	cfg                *config.Config
	db                 *gorm.DB
	authHandler        *AuthHandler
	authSvc            *service.AuthService
	ruleHandler        *RuleHandler
	rulePerfHandler    *RulePerfHandler
	eventHandler       *EventHandler
	setupHandler       *SetupHandler
	configHandler      *ConfigHandler
	ipListHandler      *IpListHandler
	trafficHandler     *TrafficHandler
	dashboardHandler   *DashboardHandler
	challengeHandler   *ChallengeHandler
	ccLogHandler       *CcLogHandler
	triggerRuleHandler *TriggerRuleHandler
	banHandler         *BanHandler
	healthHandler      *HealthHandler
	alertHandler       *AlertHandler
	auditHandler       *AuditHandler
	auditSvc           *service.AuditService
	botHandler         *BotHandler
	ja4Handler         *Ja4Handler
	backupHandler      *BackupHandler
	apiTokenSvc        *service.ApiTokenService
	apiTokenHandler    *ApiTokenHandler
	loginLimiter       *LoginRateLimiter
}

func newDeps(cfg *config.Config, db *gorm.DB, mgr *service.RedisManager) *apiDeps {
	return &apiDeps{
		cfg:                cfg,
		db:                 db,
		authHandler:        NewAuthHandler(db, mgr, cfg),
		authSvc:            service.NewAuthService(db, mgr, cfg),
		ruleHandler:        NewRuleHandler(db, mgr, cfg),
		rulePerfHandler:    NewRulePerfHandler(db, mgr, cfg),
		eventHandler:       NewEventHandler(db, mgr, cfg),
		setupHandler:       NewSetupHandler(db, mgr, cfg),
		configHandler:      NewConfigHandler(db, mgr, cfg),
		ipListHandler:      NewIpListHandler(db, mgr, cfg),
		trafficHandler:     NewTrafficHandler(db, mgr, cfg),
		dashboardHandler:   NewDashboardHandler(db),
		challengeHandler:   NewChallengeHandler(db, mgr, cfg),
		ccLogHandler:       NewCcLogHandler(db, mgr, cfg),
		triggerRuleHandler: NewTriggerRuleHandler(db, mgr, cfg),
		banHandler:         NewBanHandler(db, mgr, cfg),
		healthHandler:      NewHealthHandler(mgr, cfg),
		alertHandler:       NewAlertHandler(db, mgr, cfg),
		auditHandler:       NewAuditHandler(db),
		auditSvc:           service.NewAuditService(db),
		botHandler:         NewBotHandler(db, mgr, cfg),
		ja4Handler:         NewJa4Handler(db, mgr, cfg),
		backupHandler:      NewBackupHandler(db, cfg),
		apiTokenSvc:        service.NewApiTokenService(db),
		apiTokenHandler:    NewApiTokenHandler(db),
		loginLimiter:       NewLoginRateLimiter(),
	}
}

// registerAPIRoutes 向指定前缀的路由组注册全部业务接口（/api 与 /api/v1 复用）。
func registerAPIRoutes(api *gin.RouterGroup, d *apiDeps) {
	{
		// 存活探针（公开）
		api.GET("/health", func(c *gin.Context) {
			c.JSON(200, gin.H{"status": "ok"})
		})

		// 登录接口 IP 维度限流：令牌桶限速 + 失败锁定（与账号维度防爆破互补）
		api.POST("/auth/login", d.loginLimiter.Middleware(), d.authHandler.Login)

		// 引导相关（公开：状态/组件/脚本下载——引擎机安装无需面板凭据；
		// guide 含 Redis 明文密码，必须登录后可见，见下方 authed 组）
		api.GET("/setup/status", d.setupHandler.Status)
		api.GET("/setup/waf.tar.gz", d.setupHandler.DownloadWAF)
		api.GET("/setup/install.sh", d.setupHandler.InstallScript)

		authed := api.Group("", AuthMiddleware(d.authSvc, d.apiTokenSvc))
		authed.Use(CSRFMiddleware())
		authed.Use(AuditMiddleware(d.auditSvc))
		// RBAC：按路径模块校验角色写权限（system 模块读写均限 super）
		authed.Use(RBACMiddleware())
		userHandler := NewUserHandler(d.db)
		{
			// 用户管理（仅 super）
			superOnly := authed.Group("", RequireSuper())
			superOnly.GET("/users", userHandler.List)
			superOnly.POST("/users", userHandler.Create)
			superOnly.PUT("/users/:id", userHandler.Update)
			superOnly.DELETE("/users/:id", userHandler.Delete)

			// API Token 管理（脚本/CI 非交互调用凭证，仅 super）
			superOnly.GET("/tokens", d.apiTokenHandler.List)
			superOnly.POST("/tokens", d.apiTokenHandler.Create)
			superOnly.DELETE("/tokens/:id", d.apiTokenHandler.Revoke)

			authed.GET("/auth/me", d.authHandler.Me)
			authed.POST("/auth/totp/setup", d.authHandler.TotpSetup)
			authed.POST("/auth/totp/confirm", d.authHandler.TotpConfirm)
			authed.DELETE("/auth/totp", d.authHandler.TotpDisable)
			authed.GET("/auth/sessions", d.authHandler.Sessions)
			authed.DELETE("/auth/sessions/:jti", d.authHandler.KickSession)

			// 引导配置（登录后）
			authed.POST("/setup/redis", d.setupHandler.SaveRedis)
			authed.GET("/setup/guide", d.setupHandler.Guide)

			// 规则管理
			authed.GET("/rules", d.ruleHandler.List)
			authed.POST("/rules", d.ruleHandler.Create)
			authed.PUT("/rules/:id", d.ruleHandler.Update)
			authed.DELETE("/rules/:id", d.ruleHandler.Delete)
			authed.PATCH("/rules/:id/enabled", d.ruleHandler.SetEnabled)
			authed.POST("/rules/publish", d.ruleHandler.Publish)
			authed.POST("/rules/test", d.ruleHandler.Test)
			authed.POST("/rules/test-all", d.ruleHandler.TestAll)
			authed.GET("/rules/publish-history", d.ruleHandler.PublishHistory)
			authed.POST("/rules/rollback/:id", d.ruleHandler.Rollback)
			authed.GET("/rules/export", d.ruleHandler.Export)
			authed.POST("/rules/import", d.ruleHandler.Import)
			authed.GET("/rules/stats", d.ruleHandler.HitStats)
			// 规则灰度发布（按百分比/IP 名单下发新规则集）
			authed.POST("/rules/publish/canary", d.ruleHandler.PublishCanary)
			authed.POST("/rules/publish/promote", d.ruleHandler.PromoteCanary)
			authed.DELETE("/rules/publish/canary", d.ruleHandler.AbortCanary)
			authed.GET("/rules/canary/status", d.ruleHandler.CanaryStatus)
			// 规则耗时画像（引擎 rule_perf.lua 上报 → 后台聚合）
			authed.GET("/rules/perf", d.rulePerfHandler.List)
			authed.POST("/rules/perf/consume", d.rulePerfHandler.Consume)
			authed.DELETE("/rules/perf", d.rulePerfHandler.Reset)

			// IP 列表订阅（远程威胁情报 IP 列表）
			authed.GET("/ip-list-subs", d.ipListHandler.List)
			authed.POST("/ip-list-subs", d.ipListHandler.Create)
			authed.PUT("/ip-list-subs/:id", d.ipListHandler.Update)
			authed.DELETE("/ip-list-subs/:id", d.ipListHandler.Delete)
			authed.PATCH("/ip-list-subs/:id/enabled", d.ipListHandler.SetEnabled)
			authed.POST("/ip-list-subs/:id/sync", d.ipListHandler.Sync)

			// 全量流量记录
			authed.GET("/traffic", d.trafficHandler.List)
			authed.POST("/traffic/consume", d.trafficHandler.Consume)
			authed.POST("/traffic/cleanup", d.trafficHandler.Cleanup)
			authed.GET("/traffic/stats", d.trafficHandler.Stats)
			authed.GET("/traffic/trend", d.trafficHandler.Trend)
			authed.GET("/traffic/export", d.trafficHandler.Export)

			// 攻击事件
			authed.GET("/events", d.eventHandler.List)
			authed.GET("/events/:id", d.eventHandler.Detail)
			authed.POST("/events/consume", d.eventHandler.Consume)
			authed.POST("/events/:id/ban", d.eventHandler.Ban)
			authed.POST("/events/:id/false-positive", d.eventHandler.MarkFalsePositive)
			authed.POST("/events/:id/exempt", d.eventHandler.Exempt)
			authed.GET("/events/export", d.eventHandler.Export)

			// 封禁管理（临时/永久封禁 IP，支持 IP+UA 维度）
			authed.GET("/bans", d.banHandler.List)
			authed.POST("/bans", d.banHandler.Create)
			authed.DELETE("/bans", d.banHandler.Unban)

			// 仪表盘聚合统计
			authed.GET("/dashboard/stats", d.dashboardHandler.Stats)
			authed.GET("/dashboard/group-trend", d.dashboardHandler.GroupTrend)
			authed.GET("/dashboard/top-regions", d.dashboardHandler.TopRegions)

			// 引擎健康状态与实时监控
			authed.GET("/health/engines", d.healthHandler.Engines)
			authed.GET("/monitor/realtime", d.healthHandler.Realtime)

			// 告警通知（通道 + 规则）
			authed.GET("/alerts/channels", d.alertHandler.ListChannels)
			authed.POST("/alerts/channels", d.alertHandler.CreateChannel)
			authed.PUT("/alerts/channels/:id", d.alertHandler.UpdateChannel)
			authed.DELETE("/alerts/channels/:id", d.alertHandler.DeleteChannel)
			authed.POST("/alerts/channels/:id/test", d.alertHandler.TestChannel)
			authed.GET("/alerts/rules", d.alertHandler.ListRules)
			authed.POST("/alerts/rules", d.alertHandler.CreateRule)
			authed.PUT("/alerts/rules/:id", d.alertHandler.UpdateRule)
			authed.DELETE("/alerts/rules/:id", d.alertHandler.DeleteRule)
			authed.PATCH("/alerts/rules/:id/enabled", d.alertHandler.SetRuleEnabled)

			// 恶意指纹库（命中即拦截）
			authed.GET("/bots/fingerprints", d.botHandler.ListFingerprints)
			authed.POST("/bots/fingerprints", d.botHandler.CreateFingerprint)
			authed.PUT("/bots/fingerprints/:id", d.botHandler.UpdateFingerprint)
			authed.DELETE("/bots/fingerprints/:id", d.botHandler.DeleteFingerprint)

			// 爬虫画像库（UA + IP 段验证）
			authed.GET("/bots/profiles", d.botHandler.ListProfiles)
			authed.POST("/bots/profiles", d.botHandler.CreateProfile)
			authed.PUT("/bots/profiles/:id", d.botHandler.UpdateProfile)
			authed.DELETE("/bots/profiles/:id", d.botHandler.DeleteProfile)

			// 爬虫记录与统计
			authed.GET("/bots/logs", d.botHandler.ListLogs)
			authed.GET("/bots/logs/:id", d.botHandler.GetLog)

			// JA4 客户端指纹库与查询识别
			authed.GET("/ja4/profiles", d.ja4Handler.List)
			authed.POST("/ja4/profiles", d.ja4Handler.Create)
			authed.PUT("/ja4/profiles/:id", d.ja4Handler.Update)
			authed.DELETE("/ja4/profiles/:id", d.ja4Handler.Delete)
			authed.GET("/ja4/lookup", d.ja4Handler.Lookup)
			authed.GET("/ja4/export", d.ja4Handler.Export)
			authed.POST("/bots/consume", d.botHandler.ConsumeLogs)
			authed.POST("/bots/logs/:id/blacklist", d.botHandler.BlacklistLog)
			authed.GET("/bots/stats", d.botHandler.Stats)
			authed.GET("/bots/top", d.botHandler.Top)
			authed.GET("/bots/trend", d.botHandler.Trend)

			// 人机验证事件
			authed.GET("/challenges", d.challengeHandler.List)
			authed.POST("/challenges/consume", d.challengeHandler.Consume)

			// CC 触发事件
			authed.GET("/cc-logs", d.ccLogHandler.List)
			authed.POST("/cc-logs/consume", d.ccLogHandler.Consume)

			// 触发规则（host/UA/请求头/IP 等条件筛选）
			authed.GET("/trigger-rules", d.triggerRuleHandler.List)
			authed.POST("/trigger-rules", d.triggerRuleHandler.Create)
			authed.PUT("/trigger-rules/:id", d.triggerRuleHandler.Update)
			authed.DELETE("/trigger-rules/:id", d.triggerRuleHandler.Delete)
			authed.PATCH("/trigger-rules/:id/enabled", d.triggerRuleHandler.SetEnabled)
			authed.POST("/trigger-rules/publish", d.triggerRuleHandler.Publish)

			// 操作审计日志
			authed.GET("/audit-logs", d.auditHandler.ListAudits)

			// WAF 运行配置
			authed.GET("/config", d.configHandler.Get)
			authed.PUT("/config", d.configHandler.Save)
			authed.GET("/config/versions", d.configHandler.Versions)

			// 数据库备份（在线快照下载）
			authed.GET("/db/backup", d.backupHandler.Export)
		}
	}
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
