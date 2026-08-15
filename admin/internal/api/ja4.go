package api

import (
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"

	"openresty-waf/admin/internal/config"
	"openresty-waf/admin/internal/model"
	"openresty-waf/admin/internal/service"
)

// Ja4Handler JA4 客户端指纹库与查询识别
type Ja4Handler struct {
	svc *service.Ja4Service
}

func NewJa4Handler(db *gorm.DB, mgr *service.RedisManager, cfg *config.Config) *Ja4Handler {
	return &Ja4Handler{svc: service.NewJa4Service(db, mgr, cfg)}
}

// List GET /api/ja4/profiles?category= 客户端库列表
func (h *Ja4Handler) List(c *gin.Context) {
	list, err := h.svc.List(c.Query("category"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, list)
}

func (h *Ja4Handler) Create(c *gin.Context) {
	var p model.Ja4Profile
	if err := c.ShouldBindJSON(&p); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "参数错误"})
		return
	}
	if err := h.svc.Create(&p); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"ok": true, "id": p.ID})
}

func (h *Ja4Handler) Update(c *gin.Context) {
	id, _ := strconv.ParseUint(c.Param("id"), 10, 64)
	var p model.Ja4Profile
	if err := c.ShouldBindJSON(&p); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "参数错误"})
		return
	}
	if err := h.svc.Update(uint(id), &p); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

func (h *Ja4Handler) Delete(c *gin.Context) {
	id, _ := strconv.ParseUint(c.Param("id"), 10, 64)
	if err := h.svc.Delete(uint(id)); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

// Lookup GET /api/ja4/lookup?ja4= 查询识别（精确 → ja4_ac 前缀）
func (h *Ja4Handler) Lookup(c *gin.Context) {
	p, match, err := h.svc.Lookup(c.Query("ja4"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if p == nil {
		c.JSON(http.StatusOK, gin.H{"matched": false})
		return
	}
	c.JSON(http.StatusOK, gin.H{"matched": true, "match": match, "profile": p})
}
