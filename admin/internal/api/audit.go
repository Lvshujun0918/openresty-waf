package api

import (
	"bytes"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"

	"openresty-waf/admin/internal/service"
)

// auditActionOf 由 HTTP 方法与路径推断操作类型
func auditActionOf(method, path string) string {
	switch {
	case strings.HasSuffix(path, "/publish"):
		return "publish"
	case strings.HasSuffix(path, "/rollback/"):
		return "rollback"
	case strings.HasSuffix(path, "/test"):
		return "other"
	case method == http.MethodPost:
		return "create"
	case method == http.MethodPut || method == http.MethodPatch:
		return "update"
	case method == http.MethodDelete:
		return "delete"
	}
	return "other"
}

// detailOf 请求体摘要（前 200 字符，敏感字段打码）
func detailOf(c *gin.Context) string {
	if c.Request.Body == nil {
		return ""
	}
	// 读取前 2048 字节做摘要（不破坏原始流：剩余部分仍在原 Body 中，
	// 与已读字节拼接回 Body，保证后续 handler 能读到完整请求体）
	body, _ := io.ReadAll(io.LimitReader(c.Request.Body, 2048))
	c.Request.Body = io.NopCloser(io.MultiReader(bytes.NewReader(body), c.Request.Body))
	// 敏感字段打码
	text := string(body)
	for _, f := range []string{"password", "passwd", "secret", "smtp_pass", "totp_secret", "cookie_secret"} {
		text = strings.ReplaceAll(text, f+"\"", f+"\":\"***\"")
	}
	if len(text) > 200 {
		text = text[:200] + "..."
	}
	return text
}

// AuditMiddleware 审计中间件：记录 authed 组的写操作
func AuditMiddleware(svc *service.AuditService) gin.HandlerFunc {
	return func(c *gin.Context) {
		if c.Request.Method == http.MethodGet || c.Request.Method == http.MethodHead {
			c.Next()
			return
		}
		username, _ := c.Get("username")
		uname, _ := username.(string)
		if uname == "" {
			uname = "-"
		}
		detail := detailOf(c)
		action := auditActionOf(c.Request.Method, c.Request.URL.Path)
		c.Next()
		svc.Record(uname, action, c.Request.Method,
			c.Request.URL.Path, detail, c.ClientIP(), c.Writer.Status() < 400)
	}
}

// AuditHandler 操作审计日志查询
type AuditHandler struct {
	svc *service.AuditService
}

func NewAuditHandler(db *gorm.DB) *AuditHandler {
	return &AuditHandler{svc: service.NewAuditService(db)}
}

// ListAudits GET /api/audit-logs?page=&page_size=&username=&action=
func (h *AuditHandler) ListAudits(c *gin.Context) {
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	pageSize, _ := strconv.Atoi(c.DefaultQuery("page_size", "20"))
	if page < 1 {
		page = 1
	}
	if pageSize < 1 || pageSize > 100 {
		pageSize = 20
	}
	list, total, err := h.svc.List(c.Query("username"), c.Query("action"), page, pageSize)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"items": list, "total": total})
}
