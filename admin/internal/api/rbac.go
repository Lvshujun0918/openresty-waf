// Package api 路由与 HTTP 处理器。
package api

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"

	"openresty-waf/admin/internal/service"
)

// RBACMiddleware 基于角色的访问控制：
//   - 认证中间件已在上下文注入 role（API Token 等同 super）；
//   - system 模块（用户/Token/备份/Redis 引导）读写均限 super；
//   - 其余模块：GET 查询对所有角色开放，写操作按 CanWrite 判定；
//   - 未映射模块（自助接口/仪表盘等）不设限。
func RBACMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		role, _ := c.Get("role")
		roleStr, _ := role.(string)
		module := service.ModuleForPath(c.Request.URL.Path)
		if module == "" {
			c.Next()
			return
		}
		if c.Request.Method == http.MethodGet || c.Request.Method == http.MethodHead {
			if !service.CanRead(roleStr, module) {
				c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "当前角色无权访问该功能"})
				return
			}
			c.Next()
			return
		}
		if !service.CanWrite(roleStr, module) {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "当前角色无权执行该操作"})
			return
		}
		c.Next()
	}
}

// RequireSuper 强制 super 角色（用户管理等系统接口的显式双重保险）
func RequireSuper() gin.HandlerFunc {
	return func(c *gin.Context) {
		role, _ := c.Get("role")
		if service.NormalizeRole(roleStr(role)) != service.RoleSuper {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "仅超级管理员可操作"})
			return
		}
		c.Next()
	}
}

func roleStr(v interface{}) string {
	s, _ := v.(string)
	return strings.TrimSpace(s)
}
