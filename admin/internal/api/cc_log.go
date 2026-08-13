package api

import (
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"

	"openresty-waf/admin/internal/config"
	"openresty-waf/admin/internal/service"
)

// CcLogHandler CC 触发事件
type CcLogHandler struct {
	svc *service.CcLogService
}

func NewCcLogHandler(db *gorm.DB, mgr *service.RedisManager, cfg *config.Config) *CcLogHandler {
	return &CcLogHandler{svc: service.NewCcLogService(db, mgr, cfg)}
}

// List GET /api/cc-logs?page=&page_size=&client_ip=&rule_name=
func (h *CcLogHandler) List(c *gin.Context) {
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	pageSize, _ := strconv.Atoi(c.DefaultQuery("page_size", "20"))
	if page < 1 {
		page = 1
	}
	if pageSize < 1 || pageSize > 100 {
		pageSize = 20
	}
	logs, total, err := h.svc.List(c.Query("client_ip"), c.Query("rule_name"), page, pageSize)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"total": total, "page": page, "page_size": pageSize, "items": logs,
	})
}

// Consume POST /api/cc-logs/consume 手动触发消费 Redis 队列
func (h *CcLogHandler) Consume(c *gin.Context) {
	n, err := h.svc.Consume(100)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "ok", "consumed": n})
}
