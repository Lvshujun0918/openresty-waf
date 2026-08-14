package api

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"

	"openresty-waf/admin/internal/config"
	"openresty-waf/admin/internal/service"
)

type ConfigHandler struct {
	svc *service.WafConfigService
}

func NewConfigHandler(db *gorm.DB, mgr *service.RedisManager, cfg *config.Config) *ConfigHandler {
	return &ConfigHandler{svc: service.NewWafConfigService(db, mgr, cfg)}
}

// Get GET /api/config 当前 WAF 运行配置
func (h *ConfigHandler) Get(c *gin.Context) {
	cfg, err := h.svc.Get()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"config": cfg})
}

// Versions GET /api/config/versions 版本健康信息（规则/配置/引擎版本）
func (h *ConfigHandler) Versions(c *gin.Context) {
	v, err := h.svc.Versions()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, v)
}

// Save PUT /api/config 保存并下发 WAF 配置
func (h *ConfigHandler) Save(c *gin.Context) {
	var req struct {
		Config map[string]interface{} `json:"config"`
	}
	if err := c.ShouldBindJSON(&req); err != nil || req.Config == nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "参数错误"})
		return
	}
	if err := h.svc.Save(req.Config); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}
