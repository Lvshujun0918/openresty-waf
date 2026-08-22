package api

import (
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"

	"openresty-waf/admin/internal/service"
)

// StatsHandler 流量统计接口
type StatsHandler struct {
	svc *service.TrafficStatService
}

func NewStatsHandler(db *gorm.DB) *StatsHandler {
	return &StatsHandler{svc: service.NewTrafficStatService(db)}
}

// Traffic GET /api/stats/traffic?hours=24 流量统计报告
func (h *StatsHandler) Traffic(c *gin.Context) {
	hours := 24
	if v := c.Query("hours"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 {
			c.JSON(http.StatusBadRequest, gin.H{"error": "hours 必须为正整数"})
			return
		}
		hours = n
	}
	report, err := h.svc.Stat(hours)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, report)
}
