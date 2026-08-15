package api

import (
	"encoding/csv"
	"net/http"
	"strconv"
	"time"

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

// MarkFalsePositive POST /api/events/:id/false-positive  body: {"flag": true}
// 标记/取消误报（处置闭环：误报数据进入规则命中率统计）
func (h *EventHandler) MarkFalsePositive(c *gin.Context) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil || id == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "非法的事件 ID"})
		return
	}
	var req struct {
		Flag bool `json:"flag"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "参数错误"})
		return
	}
	if err := h.svc.MarkFalsePositive(uint(id), req.Flag); err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}

// Exempt POST /api/events/:id/exempt 一键豁免：生成 exempt 触发规则
// （host + 路径前缀；需在触发规则页发布后生效，返回规则 ID 供提示）
func (h *EventHandler) Exempt(c *gin.Context) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil || id == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "非法的事件 ID"})
		return
	}
	ruleID, err := h.svc.CreateExemptRule(uint(id))
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "ok", "rule_id": ruleID})
}

// Export GET /api/events/export?group=&client_ip=&rule_id=&host=&action=&limit=
// 导出匹配事件为 CSV（合规留档；需带当前列表过滤条件）
func (h *EventHandler) Export(c *gin.Context) {
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "10000"))
	events, err := h.svc.ExportAll(
		c.Query("group"), c.Query("client_ip"), c.Query("rule_id"), c.Query("host"), c.Query("action"), limit)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.Header("Content-Type", "text/csv; charset=utf-8")
	c.Header("Content-Disposition", `attachment; filename="waf-events-`+time.Now().Format("20060102-150405")+`.csv"`)
	w := csv.NewWriter(c.Writer)
	_ = w.Write([]string{"ID", "时间", "来源IP", "国家", "省份", "城市", "方法", "主机", "URI", "命中规则", "规则ID列表", "类型", "级别", "状态码", "误报"})
	for _, ev := range events {
		_ = w.Write([]string{
			strconv.FormatUint(uint64(ev.ID), 10),
			ev.Time.Format("2006-01-02 15:04:05"),
			ev.ClientIP, ev.Country, ev.Province, ev.City,
			ev.Method, ev.Host, ev.URI, ev.RuleID, ev.RuleIDs,
			ev.Group, strconv.Itoa(ev.Severity), strconv.Itoa(ev.Status),
			map[bool]string{true: "是", false: ""}[ev.FalsePositive],
		})
	}
	w.Flush()
}
