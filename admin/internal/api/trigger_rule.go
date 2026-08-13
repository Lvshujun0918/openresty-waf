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

// TriggerRuleHandler 触发规则：条件（host/UA/请求头/IP + AND/OR）筛选请求，
// 命中后执行对应动作（人机验证/豁免/CC）
type TriggerRuleHandler struct {
	svc *service.TriggerRuleService
}

func NewTriggerRuleHandler(db *gorm.DB, mgr *service.RedisManager, cfg *config.Config) *TriggerRuleHandler {
	return &TriggerRuleHandler{svc: service.NewTriggerRuleService(db, mgr, cfg)}
}

// List GET /api/trigger-rules?kind=&keyword=
func (h *TriggerRuleHandler) List(c *gin.Context) {
	rules, err := h.svc.List(c.Query("kind"), c.Query("keyword"))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"items": rules})
}

type triggerRuleReq struct {
	Name       string `json:"name" binding:"required"`
	Kind       string `json:"kind" binding:"required"`
	MatchLogic string `json:"match_logic"`
	Enabled    bool   `json:"enabled"`
	SortOrder  int    `json:"sort_order"`
	Conditions string `json:"conditions"`
}

// Create POST /api/trigger-rules
func (h *TriggerRuleHandler) Create(c *gin.Context) {
	var req triggerRuleReq
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "参数错误"})
		return
	}
	if req.MatchLogic == "" {
		req.MatchLogic = "and"
	}
	r := &model.TriggerRule{
		Name: req.Name, Kind: req.Kind, MatchLogic: req.MatchLogic,
		Enabled: req.Enabled, SortOrder: req.SortOrder, Conditions: req.Conditions,
	}
	if err := h.svc.Create(r); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, r)
}

// Update PUT /api/trigger-rules/:id
func (h *TriggerRuleHandler) Update(c *gin.Context) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "非法 ID"})
		return
	}
	var req triggerRuleReq
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "参数错误"})
		return
	}
	r := &model.TriggerRule{
		Name: req.Name, Kind: req.Kind, MatchLogic: req.MatchLogic,
		Enabled: req.Enabled, SortOrder: req.SortOrder, Conditions: req.Conditions,
	}
	if err := h.svc.Update(uint(id), r); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}

// Delete DELETE /api/trigger-rules/:id
func (h *TriggerRuleHandler) Delete(c *gin.Context) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "非法 ID"})
		return
	}
	if err := h.svc.Delete(uint(id)); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}

// SetEnabled PATCH /api/trigger-rules/:id/enabled
func (h *TriggerRuleHandler) SetEnabled(c *gin.Context) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "非法 ID"})
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
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}

// Publish POST /api/trigger-rules/publish 发布启用的规则到引擎
func (h *TriggerRuleHandler) Publish(c *gin.Context) {
	rs, err := h.svc.Publish()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "ok", "version": rs.Version})
}
