package api

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"

	"openresty-waf/admin/internal/config"
	"openresty-waf/admin/internal/service"
)

// BanHandler 封禁管理：临时/永久封禁 IP 的列表与解除。
// 封禁数据存储于 WAF 运行配置 blacklist.ips（条目格式 "ip|unix_ts"），
// 经 Redis 下发后引擎热更新生效（过期条目引擎侧自动跳过）。
type BanHandler struct {
	svc *service.WafConfigService
}

func NewBanHandler(db *gorm.DB, mgr *service.RedisManager, cfg *config.Config) *BanHandler {
	return &BanHandler{svc: service.NewWafConfigService(db, mgr, cfg)}
}

// List GET /api/bans  当前生效的封禁条目
func (h *BanHandler) List(c *gin.Context) {
	list, err := h.svc.ListBans()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, list)
}

// Create POST /api/bans  body: {"ip":"1.2.3.4","ua":"...","hours":1}
// 封禁（hours<=0 永久）；ua 非空时按 IP+UA 维度封禁
func (h *BanHandler) Create(c *gin.Context) {
	var req struct {
		IP    string `json:"ip"`
		UA    string `json:"ua"`
		Hours int    `json:"hours"`
	}
	if err := c.ShouldBindJSON(&req); err != nil || req.IP == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "参数错误"})
		return
	}
	if err := h.svc.Ban(req.IP, req.UA, req.Hours); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}

// Unban DELETE /api/bans?ip=1.2.3.4  解除封禁
func (h *BanHandler) Unban(c *gin.Context) {
	ip := c.Query("ip")
	if ip == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "参数错误"})
		return
	}
	if err := h.svc.UnbanIP(ip); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}
