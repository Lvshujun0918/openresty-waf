package api

import (
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"

	"openresty-waf/admin/internal/service"
)

// DashboardHandler 仪表盘聚合统计
type DashboardHandler struct {
	svc *service.DashboardService
}

func NewDashboardHandler(db *gorm.DB) *DashboardHandler {
	return &DashboardHandler{svc: service.NewDashboardService(db)}
}

// Stats GET /api/dashboard/stats?days=14 仪表盘一次拉取全部聚合数据
func (h *DashboardHandler) Stats(c *gin.Context) {
	days, _ := strconv.Atoi(c.DefaultQuery("days", "14"))
	stats, err := h.svc.Stats(days)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, stats)
}

// GroupTrend GET /api/dashboard/group-trend?group=sqli&days=14 攻击类型趋势
func (h *DashboardHandler) GroupTrend(c *gin.Context) {
	days, _ := strconv.Atoi(c.DefaultQuery("days", "14"))
	points, err := h.svc.GroupTrend(c.Query("group"), days)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"group": c.Query("group"), "items": points})
}

// TopRegions GET /api/dashboard/top-regions?level=province&limit=10 攻击来源地区排行
func (h *DashboardHandler) TopRegions(c *gin.Context) {
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "10"))
	items, err := h.svc.TopRegions(c.DefaultQuery("level", "province"), limit)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"items": items})
}
