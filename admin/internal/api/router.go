// Package api 路由与 HTTP 处理器。
package api

import (
	"mime"
	"net/http"
	"path/filepath"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/redis/go-redis/v9"
	"gorm.io/gorm"

	"openresty-waf/admin/internal/config"
	"openresty-waf/admin/internal/service"
	"openresty-waf/admin/internal/webui"
)

func NewRouter(cfg *config.Config, db *gorm.DB, rdb *redis.Client) *gin.Engine {
	r := gin.Default()

	authHandler := NewAuthHandler(db, cfg)
	authSvc := service.NewAuthService(db, cfg)
	ruleHandler := NewRuleHandler(db, rdb, cfg)
	eventHandler := NewEventHandler(db, rdb, cfg)

	r.GET("/api/health", func(c *gin.Context) {
		c.JSON(200, gin.H{"status": "ok"})
	})

	api := r.Group("/api")
	{
		api.POST("/auth/login", authHandler.Login)

		authed := api.Group("", AuthMiddleware(authSvc))
		{
			authed.GET("/auth/me", authHandler.Me)

			// 规则管理
			authed.GET("/rules", ruleHandler.List)
			authed.POST("/rules", ruleHandler.Create)
			authed.PUT("/rules/:id", ruleHandler.Update)
			authed.DELETE("/rules/:id", ruleHandler.Delete)
			authed.PATCH("/rules/:id/enabled", ruleHandler.SetEnabled)
			authed.POST("/rules/publish", ruleHandler.Publish)

			// 攻击事件
			authed.GET("/events", eventHandler.List)
			authed.POST("/events/consume", eventHandler.Consume)
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
