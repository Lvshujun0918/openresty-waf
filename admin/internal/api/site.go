package api

import (
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"

	"openresty-waf/admin/internal/model"
	"openresty-waf/admin/internal/service"
)

type SiteHandler struct {
	svc *service.SiteService
}

func NewSiteHandler(db *gorm.DB) *SiteHandler {
	return &SiteHandler{svc: service.NewSiteService(db)}
}

// bindSite 解析站点请求体（enabled 缺省 true）
func bindSite(c *gin.Context) (*model.Site, bool) {
	var req struct {
		Name    string `json:"name"`
		Domain  string `json:"domain"`
		Enabled *bool  `json:"enabled"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "参数错误"})
		return nil, false
	}
	site := &model.Site{Name: req.Name, Domain: req.Domain, Enabled: true}
	if req.Enabled != nil {
		site.Enabled = *req.Enabled
	}
	return site, true
}

// List GET /api/sites 站点列表（裸数组，与 /rules、/ip-list-subs 一致）
func (h *SiteHandler) List(c *gin.Context) {
	sites, err := h.svc.List()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, sites)
}

// Create POST /api/sites 新增站点
func (h *SiteHandler) Create(c *gin.Context) {
	site, ok := bindSite(c)
	if !ok {
		return
	}
	if err := h.svc.Create(site); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"site": site})
}

// Update PUT /api/sites/:id 更新站点
func (h *SiteHandler) Update(c *gin.Context) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "站点 ID 非法"})
		return
	}
	site, ok := bindSite(c)
	if !ok {
		return
	}
	if err := h.svc.Update(uint(id), site); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}

// Delete DELETE /api/sites/:id 删除站点
func (h *SiteHandler) Delete(c *gin.Context) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "站点 ID 非法"})
		return
	}
	if err := h.svc.Delete(uint(id)); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}
