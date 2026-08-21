package service

import (
	"errors"
	"strings"

	"gorm.io/gorm"
)

// BackupService 数据库备份。
// SQLite 使用 VACUUM INTO 在线生成一致性快照（不锁库、不停服），
// WAL 模式下与消费 goroutine / API 查询互不阻塞；MySQL 暂不支持（需 mysqldump）。
type BackupService struct {
	db     *gorm.DB
	dbType string
}

func NewBackupService(db *gorm.DB, dbType string) *BackupService {
	return &BackupService{db: db, dbType: dbType}
}

// Create 将当前数据库快照写入 dst 文件路径，返回错误或 nil。
func (s *BackupService) Create(dst string) error {
	if strings.ToLower(s.dbType) != "sqlite" {
		return errors.New("仅支持 SQLite 数据库在线备份")
	}
	if dst == "" {
		return errors.New("备份目标路径不能为空")
	}
	if err := s.db.Exec("VACUUM INTO ?", dst).Error; err != nil {
		return errors.New("生成数据库快照失败: " + err.Error())
	}
	return nil
}
