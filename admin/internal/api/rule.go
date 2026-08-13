package api

import (
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"

	"openresty-waf/admin/internal/config"
	"openresty-waf/admin/internal/model"
	"openresty-waf/admin/internal/ruletest"
	"openresty-waf/admin/internal/service"
)

type RuleHandler struct {
	svc *service.RuleService
}

func NewRuleHandler(db *gorm.DB, mgr *service.RedisManager, cfg *config.Config) *RuleHandler {
	return &RuleHandler{svc: service.NewRuleService(db, mgr, cfg)}
}

// List GET /api/rules?group=&site_id=&keyword=
func (h *RuleHandler) List(c *gin.Context) {
	rules, err := h.svc.List(c.Query("group"), c.Query("site_id"), c.Query("keyword"))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, rules)
}

// Test POST /api/rules/test  模拟请求测试规则是否命中（保存前验证）
func (h *RuleHandler) Test(c *gin.Context) {
	var req struct {
		RuleID  string                `json:"rule_id" binding:"required"`
		Request ruletest.TestRequest  `json:"request"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "参数错误: " + err.Error()})
		return
	}
	rule, err := h.svc.GetByRuleID(req.RuleID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "规则不存在: " + req.RuleID})
		return
	}
	res := ruletest.Match(*rule, req.Request)
	c.JSON(http.StatusOK, gin.H{
		"matched": res.Matched,
		"note":    res.Note,
		"rule": gin.H{
			"id": rule.RuleID, "name": rule.Name, "group": rule.Group, "msg": rule.Message,
		},
	})
}

// Create POST /api/rules
func (h *RuleHandler) Create(c *gin.Context) {
	var r model.Rule
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

// Update PUT /api/rules/:id
func (h *RuleHandler) Update(c *gin.Context) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "无效的 id"})
		return
	}
	var r model.Rule
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

// Delete DELETE /api/rules/:id
func (h *RuleHandler) Delete(c *gin.Context) {
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

// SetEnabled PATCH /api/rules/:id/enabled  body: {"enabled": true}
func (h *RuleHandler) SetEnabled(c *gin.Context) {
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

// Publish POST /api/rules/publish  将全部启用规则发布到 Redis 触发热更新
func (h *RuleHandler) Publish(c *gin.Context) {
	rs, err := h.svc.Publish()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "发布失败: " + err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"status": "ok", "version": rs.Version, "rule_count": len(rs.Rules),
	})
}
