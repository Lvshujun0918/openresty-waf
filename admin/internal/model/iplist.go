package model

import "time"

// IpListSubscription 远程 IP 列表订阅源：定时拉取 URL 中的 IP/CIDR，
// 合并到白名单/黑名单并下发引擎（用于威胁情报 IP 列表、云厂商封禁列表等）。
type IpListSubscription struct {
	ID          uint       `gorm:"primaryKey" json:"id"`
	Name        string     `gorm:"size:128" json:"name"`
	URL         string     `gorm:"type:text" json:"url"`
	Type        string     `gorm:"size:16" json:"type"` // whitelist | blacklist
	IntervalMin int        `gorm:"default:60" json:"interval_min"` // 同步周期（分钟）
	Enabled     bool       `gorm:"default:true" json:"enabled"`
	LastSyncAt  *time.Time `json:"last_sync_at"`
	LastStatus  string     `gorm:"size:255" json:"last_status"`
	LastCount   int        `json:"last_count"`
	CreatedAt   time.Time  `json:"created_at"`
	UpdatedAt   time.Time  `json:"updated_at"`
}
