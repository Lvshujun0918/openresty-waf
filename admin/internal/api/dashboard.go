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

// Stats GET /api/dashboard/stats?days=14&host=example.com 仪表盘一次拉取全部聚合数据
// host 非空时仅统计指定站点域名的数据（多站点隔离）
func (h *DashboardHandler) Stats(c *gin.Context) {
	days, _ := strconv.Atoi(c.DefaultQuery("days", "14"))
	host := c.Query("host")
	stats, err := h.svc.Stats(days, host)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, stats)
}
