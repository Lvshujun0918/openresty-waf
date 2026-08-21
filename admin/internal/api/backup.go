package api

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"

	"openresty-waf/admin/internal/config"
	"openresty-waf/admin/internal/service"
)

// BackupHandler 数据库备份下载。
type BackupHandler struct {
	svc *service.BackupService
}

func NewBackupHandler(db *gorm.DB, cfg *config.Config) *BackupHandler {
	return &BackupHandler{svc: service.NewBackupService(db, cfg.DB.Type)}
}

// Export 生成在线快照并以附件形式返回（GET /api/db/backup）。
// 快照写入临时文件，响应完成后即删除，不在服务器留存副本。
func (h *BackupHandler) Export(c *gin.Context) {
	tmp := filepath.Join(os.TempDir(), fmt.Sprintf("waf-backup-%d-%d.db", os.Getpid(), time.Now().UnixNano()))
	if err := h.svc.Create(tmp); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	defer func() {
		if err := os.Remove(tmp); err != nil {
			log.Printf("清理备份临时文件失败: %v", err)
		}
	}()

	name := "waf-backup-" + time.Now().Format("20060102150405") + ".db"
	c.Header("Content-Disposition", `attachment; filename="`+name+`"`)
	c.Header("Content-Type", "application/octet-stream")
	c.File(tmp)
}
