package api

import (
	"crypto/rand"
	"encoding/hex"
	"net"
	"net/http"

	"github.com/gin-gonic/gin"

	"openresty-waf/admin/internal/config"
)

// ============================================================================
// 面板安全加固中间件：IP 白名单 / 安全响应头 / CSRF 双提交 Cookie
// ============================================================================

// SecurityHeaders 全局安全响应头
func SecurityHeaders() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Header("X-Content-Type-Options", "nosniff")
		c.Header("X-Frame-Options", "SAMEORIGIN")
		c.Header("Referrer-Policy", "strict-origin-when-cross-origin")
		c.Header("X-XSS-Protection", "1; mode=block")
		// CSP 仅作用于 API 路径（前端 SPA 的内联脚本/样式较多，放开 style-src 'unsafe-inline'）
		if len(c.Request.URL.Path) >= 4 && c.Request.URL.Path[:4] == "/api" {
			c.Header("Content-Security-Policy",
				"default-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; frame-ancestors 'none'")
		}
		c.Header("Cache-Control", "no-store")
		c.Next()
	}
}

// AllowedIP 面板访问 IP 白名单：来源 IP 不在列表时拒绝（空列表 = 不限制）。
// 防止管理面板暴露在公网时被扫描/爆破。
func AllowedIP(cfg *config.Config) gin.HandlerFunc {
	var allowed []*net.IPNet
	for _, entry := range cfg.Security.AllowedIPs {
		if ip := net.ParseIP(entry); ip != nil {
			bits := 32
			if ip.To4() == nil {
				bits = 128
			}
			allowed = append(allowed, &net.IPNet{IP: ip, Mask: net.CIDRMask(bits, bits)})
			continue
		}
		if _, n, err := net.ParseCIDR(entry); err == nil {
			allowed = append(allowed, n)
		}
	}
	return func(c *gin.Context) {
		if len(allowed) == 0 {
			c.Next()
			return
		}
		// 用 RemoteAddr（直连地址）而非 c.ClientIP()：后者信任 X-Forwarded-For，
		// 面板前有反代时攻击者可伪造 XFF 绕过白名单
		host, _, err := net.SplitHostPort(c.Request.RemoteAddr)
		if err != nil {
			host = c.Request.RemoteAddr
		}
		ip := net.ParseIP(host)
		if ip == nil {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "访问被拒绝"})
			return
		}
		for _, n := range allowed {
			if n.Contains(ip) {
				c.Next()
				return
			}
		}
		c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "访问被拒绝"})
	}
}

// CSRF 双提交 Cookie：登录时下发非 HttpOnly 的 waf_csrf Cookie，
// 前端所有写请求从 Cookie 读取该值并携带 X-CSRF-Token 头，两者必须一致。
// 攻击者跨站发起请求时无法读取/伪造该 Cookie 值。
const csrfCookieName = "waf_csrf"

func generateCSRFToken() string {
	buf := make([]byte, 24)
	_, _ = rand.Read(buf)
	return hex.EncodeToString(buf)
}

// SetCSRFCookie 登录成功后下发 CSRF Cookie
func SetCSRFCookie(c *gin.Context) {
	c.SetCookie(csrfCookieName, generateCSRFToken(), 7*86400, "/", "", false, false)
}

// CSRFMiddleware 校验写请求的 X-CSRF-Token 与 Cookie 一致（GET/HEAD 放行）。
// API Token 认证的请求（api_token 标记）无浏览器上下文，天然免疫 CSRF，直接放行。
func CSRFMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		if c.Request.Method == http.MethodGet || c.Request.Method == http.MethodHead {
			c.Next()
			return
		}
		if c.GetBool("api_token") {
			c.Next()
			return
		}
		cookie, err := c.Cookie(csrfCookieName)
		if err != nil || cookie == "" {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "CSRF 校验失败：缺少 Cookie"})
			return
		}
		header := c.GetHeader("X-CSRF-Token")
		if header == "" || header != cookie {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "CSRF 校验失败"})
			return
		}
		c.Next()
	}
}
