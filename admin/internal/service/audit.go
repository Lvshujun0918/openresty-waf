package service

import (
	"log"
	"time"

	"gorm.io/gorm"

	"openresty-waf/admin/internal/model"
)

// AuditService 操作审计：记录后台写操作与安全事件，支持分页查询。
type AuditService struct {
	db *gorm.DB
}

func NewAuditService(db *gorm.DB) *AuditService {
	return &AuditService{db: db}
}

// Cleanup 清理 retentionDays 天前的审计日志，返回删除条数（定时轮转防表膨胀）
func (s *AuditService) Cleanup(retentionDays int) (int64, error) {
	if retentionDays < 1 {
		retentionDays = 90
	}
	cutoff := time.Now().Add(-time.Duration(retentionDays) * 24 * time.Hour)
	res := s.db.Where("created_at < ?", cutoff).Delete(&model.AuditLog{})
	return res.RowsAffected, res.Error
}

// Record 记录一条审计日志（异步不阻塞业务；失败仅告警，不影响主流程）
func (s *AuditService) Record(username, action, method, path, detail, clientIP string, success bool) {
	entry := model.AuditLog{
		Username: username, Action: action, Method: method, Path: path,
		Detail: detail, ClientIP: clientIP, Success: success,
	}
	if err := s.db.Create(&entry).Error; err != nil {
		// 审计失败不阻断业务，仅降级（写文件日志兜底）
		log.Printf("[audit] 记录失败: %v", err)
	}
}

// List 分页查询，支持 username / action 过滤
func (s *AuditService) List(username, action string, page, pageSize int) ([]model.AuditLog, int64, error) {
	q := s.db.Model(&model.AuditLog{})
	if username != "" {
		q = q.Where("username = ?", username)
	}
	if action != "" {
		q = q.Where("action = ?", action)
	}
	var total int64
	if err := q.Count(&total).Error; err != nil {
		return nil, 0, err
	}
	var list []model.AuditLog
	if err := q.Order("id desc").Offset((page - 1) * pageSize).Limit(pageSize).Find(&list).Error; err != nil {
		return nil, 0, err
	}
	return list, total, nil
}
