// Package api 路由与 HTTP 处理器。
package api

import (
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"

	"openresty-waf/admin/internal/config"
	"openresty-waf/admin/internal/service"
)

func NewRouter(cfg *config.Config, db *gorm.DB) *gin.Engine {
	r := gin.Default()

	authHandler := NewAuthHandler(db, cfg)
	authSvc := service.NewAuthService(db, cfg)

	r.GET("/api/health", func(c *gin.Context) {
		c.JSON(200, gin.H{"status": "ok"})
	})

	api := r.Group("/api")
	{
		api.POST("/auth/login", authHandler.Login)

		authed := api.Group("", AuthMiddleware(authSvc))
		{
			authed.GET("/auth/me", authHandler.Me)
		}
	}

	return r
}
