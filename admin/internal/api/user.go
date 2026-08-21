// Package api 路由与 HTTP 处理器。
package api

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"

	"openresty-waf/admin/internal/model"
	"openresty-waf/admin/internal/service"
)

// UserHandler 用户管理（仅 super）：账号 CRUD 与角色分配
type UserHandler struct {
	db *gorm.DB
}

func NewUserHandler(db *gorm.DB) *UserHandler {
	return &UserHandler{db: db}
}

// List GET /api/users
func (h *UserHandler) List(c *gin.Context) {
	var users []model.User
	if err := h.db.Select("id", "username", "role", "totp_enabled", "created_at", "updated_at").
		Order("id").Find(&users).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "查询失败"})
		return
	}
	c.JSON(http.StatusOK, users)
}

type createUserReq struct {
	Username string `json:"username" binding:"required"`
	Password string `json:"password" binding:"required"`
	Role     string `json:"role" binding:"required"`
}

// Create POST /api/users  body: {"username","password","role"}
func (h *UserHandler) Create(c *gin.Context) {
	var req createUserReq
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "参数错误"})
		return
	}
	req.Username = strings.TrimSpace(req.Username)
	if len(req.Username) < 2 || len(req.Username) > 64 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "用户名长度需在 2-64 字符之间"})
		return
	}
	if len(req.Password) < 8 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "密码至少 8 位"})
		return
	}
	req.Role = service.NormalizeRole(strings.TrimSpace(req.Role))
	if !service.ValidRole(req.Role) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "角色不合法（super/ops/viewer）"})
		return
	}
	var count int64
	h.db.Model(&model.User{}).Where("username = ?", req.Username).Count(&count)
	if count > 0 {
		c.JSON(http.StatusConflict, gin.H{"error": "用户名已存在"})
		return
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "内部错误"})
		return
	}
	user := model.User{Username: req.Username, PasswordHash: string(hash), Role: req.Role}
	if err := h.db.Create(&user).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "创建失败"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"id": user.ID, "username": user.Username, "role": user.Role})
}

type updateUserReq struct {
	Role     *string `json:"role"`     // nil=不变更
	Password *string `json:"password"` // nil=不变更（重置密码）
}

// Update PUT /api/users/:id  body: {"role"?,"password"?}
// 约束：不能修改自己的角色；不能降级/移除最后一个 super。
func (h *UserHandler) Update(c *gin.Context) {
	var req updateUserReq
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "参数错误"})
		return
	}
	var user model.User
	if err := h.db.First(&user, c.Param("id")).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "用户不存在"})
		return
	}
	updates := map[string]interface{}{}
	if req.Role != nil {
		newRole := strings.TrimSpace(*req.Role)
		if !service.ValidRole(newRole) {
			c.JSON(http.StatusBadRequest, gin.H{"error": "角色不合法（super/ops/viewer）"})
			return
		}
		selfID, _ := c.Get("user_id")
		if id, ok := selfID.(uint); ok && id == user.ID && newRole != user.Role {
			c.JSON(http.StatusBadRequest, gin.H{"error": "不能修改自己的角色"})
			return
		}
		if user.Role == service.RoleSuper && newRole != service.RoleSuper && !h.hasOtherSuper(user.ID) {
			c.JSON(http.StatusBadRequest, gin.H{"error": "至少保留一个超级管理员账号"})
			return
		}
		updates["role"] = newRole
	}
	if req.Password != nil {
		if len(*req.Password) < 8 {
			c.JSON(http.StatusBadRequest, gin.H{"error": "密码至少 8 位"})
			return
		}
		hash, err := bcrypt.GenerateFromPassword([]byte(*req.Password), bcrypt.DefaultCost)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "内部错误"})
			return
		}
		updates["password_hash"] = string(hash)
	}
	if len(updates) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "无可更新字段"})
		return
	}
	if err := h.db.Model(&model.User{}).Where("id = ?", user.ID).Updates(updates).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "更新失败"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

// Delete DELETE /api/users/:id
// 约束：不能删除自己；不能删除最后一个 super。
func (h *UserHandler) Delete(c *gin.Context) {
	var user model.User
	if err := h.db.First(&user, c.Param("id")).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "用户不存在"})
		return
	}
	selfID, _ := c.Get("user_id")
	if id, ok := selfID.(uint); ok && id == user.ID {
		c.JSON(http.StatusBadRequest, gin.H{"error": "不能删除当前登录账号"})
		return
	}
	if user.Role == service.RoleSuper && !h.hasOtherSuper(user.ID) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "至少保留一个超级管理员账号"})
		return
	}
	if err := h.db.Delete(&model.User{}, user.ID).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "删除失败"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

// hasOtherSuper 除 excludeID 外是否还存在其他 super 账号
func (h *UserHandler) hasOtherSuper(excludeID uint) bool {
	var count int64
	h.db.Model(&model.User{}).
		Where("id <> ? AND role = ?", excludeID, service.RoleSuper).Count(&count)
	return count > 0
}
