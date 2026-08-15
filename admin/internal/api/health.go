package api

import (
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"

	"openresty-waf/admin/internal/config"
	"openresty-waf/admin/internal/service"
)

// HealthHandler 引擎健康状态与实时监控接口
type HealthHandler struct {
	svc *service.HealthService
}

func NewHealthHandler(mgr *service.RedisManager, cfg *config.Config) *HealthHandler {
	return &HealthHandler{svc: service.NewHealthService(mgr, cfg)}
}

// Engines GET /api/health/engines 引擎在线状态列表
func (h *HealthHandler) Engines(c *gin.Context) {
	list, err := h.svc.ListEngines()
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"engines": list, "count": len(list)})
}

// Realtime GET /api/monitor/realtime?minutes=10 实时监控秒级曲线
func (h *HealthHandler) Realtime(c *gin.Context) {
	minutes := 10
	if v := c.Query("minutes"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			minutes = n
		}
	}
	points, err := h.svc.Realtime(minutes)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"points": points})
}
