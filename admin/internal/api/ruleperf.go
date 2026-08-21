package api

import (
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"

	"openresty-waf/admin/internal/config"
	"openresty-waf/admin/internal/service"
)

// RulePerfHandler 规则耗时画像
type RulePerfHandler struct {
	svc *service.RulePerfService
}

func NewRulePerfHandler(db *gorm.DB, mgr *service.RedisManager, cfg *config.Config) *RulePerfHandler {
	return &RulePerfHandler{svc: service.NewRulePerfService(db, mgr, cfg)}
}

// List GET /api/rules/perf?limit=100 按累计耗时降序
func (h *RulePerfHandler) List(c *gin.Context) {
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "100"))
	rows, err := h.svc.List(limit)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"items": rows})
}

// Consume POST /api/rules/perf/consume 手动触发消费 Redis 队列
func (h *RulePerfHandler) Consume(c *gin.Context) {
	n, err := h.svc.Consume(100)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "ok", "consumed": n})
}

// Reset DELETE /api/rules/perf 清空统计重新累积
func (h *RulePerfHandler) Reset(c *gin.Context) {
	if err := h.svc.Reset(); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}
