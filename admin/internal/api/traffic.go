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

// TrafficHandler 全量流量记录：查询/消费/清理
type TrafficHandler struct {
	svc *service.TrafficService
}

func NewTrafficHandler(db *gorm.DB, mgr *service.RedisManager, cfg *config.Config) *TrafficHandler {
	return &TrafficHandler{svc: service.NewTrafficService(db, mgr, cfg)}
}

// List GET /api/traffic?page=&page_size=&host=&client_ip=&attack=
func (h *TrafficHandler) List(c *gin.Context) {
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	pageSize, _ := strconv.Atoi(c.DefaultQuery("page_size", "20"))
	if page < 1 {
		page = 1
	}
	if pageSize < 1 || pageSize > 100 {
		pageSize = 20
	}
	logs, total, err := h.svc.List(
		c.Query("host"), c.Query("client_ip"), c.Query("attack"), page, pageSize)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"total": total, "page": page, "page_size": pageSize, "items": logs,
	})
}

// Consume POST /api/traffic/consume 手动触发消费 Redis 流量队列
func (h *TrafficHandler) Consume(c *gin.Context) {
	n, err := h.svc.Consume(100)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "ok", "consumed": n})
}

// Cleanup POST /api/traffic/cleanup?days=7 手动清理 N 天前的流量记录
func (h *TrafficHandler) Cleanup(c *gin.Context) {
	days, _ := strconv.Atoi(c.DefaultQuery("days", "7"))
	n, err := h.svc.Cleanup(days)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "ok", "deleted": n})
}

// Stats GET /api/traffic/stats 统计信息
func (h *TrafficHandler) Stats(c *gin.Context) {
	total, attack, err := h.svc.GetStats()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"total": total, "attack": attack})
}

// Trend GET /api/traffic/trend?days=7 按天聚合趋势
func (h *TrafficHandler) Trend(c *gin.Context) {
	days, _ := strconv.Atoi(c.DefaultQuery("days", "7"))
	points, err := h.svc.Trend(days)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"days": days, "items": points})
}

// Export GET /api/traffic/export?host=&client_ip=&attack=&limit= 导出流量记录 CSV
func (h *TrafficHandler) Export(c *gin.Context) {
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "10000"))
	logs, err := h.svc.ExportAll(
		c.Query("host"), c.Query("client_ip"), c.Query("attack"), limit)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.Header("Content-Type", "text/csv; charset=utf-8")
	c.Header("Content-Disposition", `attachment; filename="waf-traffic-`+time.Now().Format("20060102-150405")+`.csv"`)
	w := csv.NewWriter(c.Writer)
	_ = w.Write([]string{"ID", "时间", "来源IP", "方法", "主机", "URI", "状态码", "UA", "命中攻击", "命中规则", "响应耗时(ms)", "国家", "省份", "城市"})
	for _, rec := range logs {
		_ = w.Write([]string{
			strconv.FormatUint(uint64(rec.ID), 10),
			rec.Time.Format("2006-01-02 15:04:05"),
			rec.ClientIP, rec.Method, rec.Host, rec.URI,
			strconv.Itoa(rec.Status), rec.UserAgent,
			map[bool]string{true: "是", false: ""}[rec.Attack],
			rec.RuleIDs, strconv.FormatFloat(rec.ResponseTime, 'f', 2, 64),
			rec.Country, rec.Province, rec.City,
		})
	}
	w.Flush()
}
