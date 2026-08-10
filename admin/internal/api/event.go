package api

import (
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
	"github.com/redis/go-redis/v9"
	"gorm.io/gorm"

	"openresty-waf/admin/internal/config"
	"openresty-waf/admin/internal/service"
)

type EventHandler struct {
	svc *service.EventService
}

func NewEventHandler(db *gorm.DB, rdb *redis.Client, cfg *config.Config) *EventHandler {
	return &EventHandler{svc: service.NewEventService(db, rdb, cfg)}
}

// List GET /api/events?page=&page_size=&group=&client_ip=&rule_id=
func (h *EventHandler) List(c *gin.Context) {
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	pageSize, _ := strconv.Atoi(c.DefaultQuery("page_size", "20"))
	if page < 1 {
		page = 1
	}
	if pageSize < 1 || pageSize > 100 {
		pageSize = 20
	}
	events, total, err := h.svc.List(
		c.Query("group"), c.Query("client_ip"), c.Query("rule_id"), page, pageSize)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"total": total, "page": page, "page_size": pageSize, "items": events,
	})
}

// Consume POST /api/events/consume  手动触发消费 Redis 攻击事件队列
func (h *EventHandler) Consume(c *gin.Context) {
	n, err := h.svc.Consume(100)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "ok", "consumed": n})
}
