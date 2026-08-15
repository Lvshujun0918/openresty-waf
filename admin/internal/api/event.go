package api

import (
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"

	"openresty-waf/admin/internal/config"
	"openresty-waf/admin/internal/service"
)

type EventHandler struct {
	svc     *service.EventService
	wafCfg  *service.WafConfigService
}

func NewEventHandler(db *gorm.DB, mgr *service.RedisManager, cfg *config.Config) *EventHandler {
	return &EventHandler{
		svc:    service.NewEventService(db, mgr, cfg),
		wafCfg: service.NewWafConfigService(db, mgr, cfg),
	}
}

// List GET /api/events?page=&page_size=&group=&client_ip=&rule_id=&host=&action=
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
		c.Query("group"), c.Query("client_ip"), c.Query("rule_id"), c.Query("host"), c.Query("action"), page, pageSize)
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

// Detail GET /api/events/:id  事件详情（含命中规则 / 请求头 / 请求体）
func (h *EventHandler) Detail(c *gin.Context) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil || id == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "非法的事件 ID"})
		return
	}
	ev, err := h.svc.Get(uint(id))
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "事件不存在"})
		return
	}
	c.JSON(http.StatusOK, ev)
}

// Ban POST /api/events/:id/ban  body: {"hours": 1}  一键封禁事件来源 IP
// hours<=0 表示永久封禁；封禁写入配置 blacklist.ips 并热更新下发。
func (h *EventHandler) Ban(c *gin.Context) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil || id == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "非法的事件 ID"})
		return
	}
	var req struct {
		Hours int `json:"hours"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "参数错误"})
		return
	}
	ev, err := h.svc.Get(uint(id))
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "事件不存在"})
		return
	}
	if ev.ClientIP == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "事件无客户端 IP"})
		return
	}
	if err := h.wafCfg.BanIP(ev.ClientIP, req.Hours); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "封禁失败: " + err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "ok", "ip": ev.ClientIP})
}
