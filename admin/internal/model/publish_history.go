package model

import "time"

// PublishHistory 规则发布历史（每次发布保存完整规则集快照，支持一键回滚）。
// Content 仅在回滚时读取，列表接口不返回（json:"-"）。
type PublishHistory struct {
	ID        uint      `gorm:"primaryKey" json:"id"`
	Kind      string    `gorm:"size:16;index" json:"kind"` // 类型："rules"
	Version   string    `gorm:"size:32" json:"version"`    // Redis 规则版本号（数字）
	RuleCount int       `json:"rule_count"`                // 规则条数
	Content   string    `gorm:"type:text" json:"-"`        // 完整规则集 JSON
	CreatedAt time.Time `json:"created_at"`
}
