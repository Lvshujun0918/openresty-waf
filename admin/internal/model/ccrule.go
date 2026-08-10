package model

import "time"

// CcRule CC 防刷精细化规则：按 host + path 匹配，可配置不同的频率阈值与封禁时长。
// 匹配优先级（引擎侧）：host+path 都命中 > 仅 host > 仅 path > 全局（host/path 均空）。
type CcRule struct {
	ID          uint      `gorm:"primaryKey" json:"id"`
	Name        string    `gorm:"size:128" json:"name"`
	Host        string    `gorm:"size:255;index" json:"host"` // 空/`*` = 所有域名；支持 `*.example.com` 子域通配
	Path        string    `gorm:"size:512" json:"path"`       // 空 = 所有路径；前缀匹配
	Rate        string    `gorm:"size:32" json:"rate"`        // 频率 "count/seconds"，如 100/60
	BanDuration int       `gorm:"default:300" json:"ban_duration"`
	Enabled     bool      `gorm:"default:true" json:"enabled"`
	SortOrder   int       `gorm:"default:0" json:"sort_order"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}
