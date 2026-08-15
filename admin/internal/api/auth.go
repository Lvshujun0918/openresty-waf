package api

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"

	"openresty-waf/admin/internal/config"
	"openresty-waf/admin/internal/service"
)

type AuthHandler struct {
	svc *service.AuthService
}

func NewAuthHandler(db *gorm.DB, cfg *config.Config) *AuthHandler {
	return &AuthHandler{svc: service.NewAuthService(db, cfg)}
}

type loginReq struct {
	Username string `json:"username" binding:"required"`
	Password string `json:"password" binding:"required"`
	TotpCode string `json:"totp_code"` // 可选：启用 TOTP 的账号必填
}

// Login POST /api/auth/login
func (h *AuthHandler) Login(c *gin.Context) {
	var req loginReq
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "参数错误"})
		return
	}
	token, err := h.svc.LoginWithTOTP(req.Username, req.Password, req.TotpCode)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"token": token})
}

// Me GET /api/auth/me
func (h *AuthHandler) Me(c *gin.Context) {
	username, _ := c.Get("username")
	userID, _ := c.Get("user_id")
	totpEnabled := false
	if id, ok := userID.(uint); ok {
		enabled, err := h.svc.TOTPStatus(id)
		if err == nil {
			totpEnabled = enabled
		}
	}
	c.JSON(http.StatusOK, gin.H{
		"id": userID, "username": username, "totp_enabled": totpEnabled,
	})
}

// TotpSetup POST /api/auth/totp/setup  生成新密钥（未确认前不生效）
func (h *AuthHandler) TotpSetup(c *gin.Context) {
	userID, _ := c.Get("user_id")
	id, ok := userID.(uint)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "未登录"})
		return
	}
	secret, url, err := h.svc.SetupTOTP(id)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"secret": secret, "otpauth_url": url})
}

// TotpConfirm POST /api/auth/totp/confirm  body: {"code": "123456"}  校验后启用
func (h *AuthHandler) TotpConfirm(c *gin.Context) {
	var req struct {
		Code string `json:"code" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "参数错误"})
		return
	}
	userID, _ := c.Get("user_id")
	id, ok := userID.(uint)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "未登录"})
		return
	}
	if err := h.svc.ConfirmTOTP(id, req.Code); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}

// TotpDisable DELETE /api/auth/totp  query: ?code=123456  校验后关闭
func (h *AuthHandler) TotpDisable(c *gin.Context) {
	code := c.Query("code")
	if code == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "参数错误"})
		return
	}
	userID, _ := c.Get("user_id")
	id, ok := userID.(uint)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "未登录"})
		return
	}
	if err := h.svc.DisableTOTP(id, code); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}

// AuthMiddleware JWT 鉴权中间件
func AuthMiddleware(svc *service.AuthService) gin.HandlerFunc {
	return func(c *gin.Context) {
		auth := c.GetHeader("Authorization")
		if !strings.HasPrefix(auth, "Bearer ") {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "未登录"})
			return
		}
		claims, err := svc.ParseToken(strings.TrimPrefix(auth, "Bearer "))
		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "登录已失效"})
			return
		}
		c.Set("user_id", claims.UserID)
		c.Set("username", claims.Username)
		c.Next()
	}
}
