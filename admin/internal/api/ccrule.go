package api

import (
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"

	"openresty-waf/admin/internal/config"
	"openresty-waf/admin/internal/model"
	"openresty-waf/admin/internal/service"
)

// CcRuleHandler CC 防刷规则：按 host + path 精细化配置
type CcRuleHandler struct {
	svc *service.CcRuleService
}

func NewCcRuleHandler(db *gorm.DB, mgr *service.RedisManager, cfg *config.Config) *CcRuleHandler {
	return &CcRuleHandler{svc: service.NewCcRuleService(db, mgr, cfg)}
}

// List GET /api/cc-rules
func (h *CcRuleHandler) List(c *gin.Context) {
	rules, err := h.svc.List()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, rules)
}

// Create POST /api/cc-rules
func (h *CcRuleHandler) Create(c *gin.Context) {
	var r model.CcRule
	if err := c.ShouldBindJSON(&r); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "参数错误: " + err.Error()})
		return
	}
	if err := h.svc.Create(&r); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusCreated, r)
}

// Update PUT /api/cc-rules/:id
func (h *CcRuleHandler) Update(c *gin.Context) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "无效的 id"})
		return
	}
	var r model.CcRule
	if err := c.ShouldBindJSON(&r); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "参数错误"})
		return
	}
	if err := h.svc.Update(uint(id), &r); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}

// Delete DELETE /api/cc-rules/:id
func (h *CcRuleHandler) Delete(c *gin.Context) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "无效的 id"})
		return
	}
	if err := h.svc.Delete(uint(id)); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}

// SetEnabled PATCH /api/cc-rules/:id/enabled
func (h *CcRuleHandler) SetEnabled(c *gin.Context) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "无效的 id"})
		return
	}
	var req struct {
		Enabled bool `json:"enabled"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "参数错误"})
		return
	}
	if err := h.svc.SetEnabled(uint(id), req.Enabled); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}

// Publish POST /api/cc-rules/publish 发布启用规则到 Redis 触发热更新
func (h *CcRuleHandler) Publish(c *gin.Context) {
	rs, err := h.svc.Publish()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "发布失败: " + err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"status": "ok", "version": rs.Version, "rule_count": len(rs.Rules),
	})
}
