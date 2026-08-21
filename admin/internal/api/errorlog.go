package api

import (
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"

	"openresty-waf/admin/internal/config"
	"openresty-waf/admin/internal/service"
)

// ErrorLogHandler 引擎报错汇总
type ErrorLogHandler struct {
	svc *service.ErrorLogService
}

func NewErrorLogHandler(db *gorm.DB, mgr *service.RedisManager, cfg *config.Config) *ErrorLogHandler {
	return &ErrorLogHandler{svc: service.NewErrorLogService(db, mgr, cfg)}
}

// List GET /api/errors?page=&page_size=&level=&source=&keyword=
func (h *ErrorLogHandler) List(c *gin.Context) {
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	pageSize, _ := strconv.Atoi(c.DefaultQuery("page_size", "20"))
	if page < 1 {
		page = 1
	}
	if pageSize < 1 || pageSize > 100 {
		pageSize = 20
	}
	logs, total, err := h.svc.List(c.Query("level"), c.Query("source"), c.Query("keyword"), page, pageSize)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"total": total, "page": page, "page_size": pageSize, "items": logs,
	})
}

// Stats GET /api/errors/stats 近 24 小时按级别统计
func (h *ErrorLogHandler) Stats(c *gin.Context) {
	stats, err := h.svc.Stats()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, stats)
}

// Consume POST /api/errors/consume 手动触发消费 Redis 队列
func (h *ErrorLogHandler) Consume(c *gin.Context) {
	n, err := h.svc.Consume(200)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "ok", "consumed": n})
}

// Clear DELETE /api/errors 清空报错记录
func (h *ErrorLogHandler) Clear(c *gin.Context) {
	if err := h.svc.Clear(); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}
