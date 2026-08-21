// Package api API Token 管理接口。
package api

import (
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"

	"openresty-waf/admin/internal/service"
)

// ApiTokenHandler 令牌 CRUD。
type ApiTokenHandler struct {
	svc *service.ApiTokenService
}

func NewApiTokenHandler(db *gorm.DB) *ApiTokenHandler {
	return &ApiTokenHandler{svc: service.NewApiTokenService(db)}
}

// List GET /api/tokens
func (h *ApiTokenHandler) List(c *gin.Context) {
	list, err := h.svc.List()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "查询失败"})
		return
	}
	c.JSON(http.StatusOK, list)
}

// Create POST /api/tokens {"name":"ci-deploy"} → 明文 token 仅返回一次
func (h *ApiTokenHandler) Create(c *gin.Context) {
	var req struct {
		Name string `json:"name" binding:"required,max=64"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "参数错误：name 必填（≤64 字符）"})
		return
	}
	t, plain, err := h.svc.Create(req.Name)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "创建失败"})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"id":     t.ID,
		"name":   t.Name,
		"prefix": t.Prefix,
		"token":  plain, // 仅此一次
	})
}

// Revoke DELETE /api/tokens/:id
func (h *ApiTokenHandler) Revoke(c *gin.Context) {
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil || id <= 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "非法 ID"})
		return
	}
	if err := h.svc.Revoke(uint(id)); err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "令牌不存在或已吊销"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"ok": true})
}
