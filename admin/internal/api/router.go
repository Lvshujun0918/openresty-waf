// Package api 路由与 HTTP 处理器。
package api

import (
	"github.com/gin-gonic/gin"
	"github.com/redis/go-redis/v9"
	"gorm.io/gorm"

	"openresty-waf/admin/internal/config"
	"openresty-waf/admin/internal/service"
)

func NewRouter(cfg *config.Config, db *gorm.DB, rdb *redis.Client) *gin.Engine {
	r := gin.Default()

	authHandler := NewAuthHandler(db, cfg)
	authSvc := service.NewAuthService(db, cfg)
	ruleHandler := NewRuleHandler(db, rdb, cfg)

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
		}
	}

	return r
}
