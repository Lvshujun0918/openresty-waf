package model

import "time"

// RuleSubscription 远程规则订阅源：定时拉取 URL 中的规则集（JSON 数组，
// 与 GET /api/rules/export 导出格式一致），重建为本订阅产生的规则。
// 同步入库后默认不自动发布，需在规则页手动发布（外部源可能被污染，
// 自动全量发布存在误拦风险；可在订阅上开启 auto_publish 跳过人工审查）。
type RuleSubscription struct {
	ID          uint       `gorm:"primaryKey" json:"id"`
	Name        string     `gorm:"size:128" json:"name"`
	URL         string     `gorm:"type:text" json:"url"`
	AutoPublish bool       `gorm:"default:false" json:"auto_publish"` // 同步后自动发布规则集
	IntervalMin int        `gorm:"default:1440" json:"interval_min"`  // 同步周期（分钟）
	Enabled     bool       `gorm:"default:true" json:"enabled"`
	LastSyncAt  *time.Time `json:"last_sync_at"`
	LastStatus  string     `gorm:"size:255" json:"last_status"`
	LastCount   int        `json:"last_count"`
	CreatedAt   time.Time  `json:"created_at"`
	UpdatedAt   time.Time  `json:"updated_at"`
}
