package model

import "time"

// IpListSubscription 远程订阅源：定时拉取 URL 中的威胁情报并同步到对应库。
// Target: ip（恶意/信任 IP 库，合并到黑白名单下发）|
//         fingerprint（恶意指纹库，同步为 BotFingerprint）|
//         bot_profile（爬虫画像库，同步为 BotProfile）。
type IpListSubscription struct {
	ID          uint       `gorm:"primaryKey" json:"id"`
	Name        string     `gorm:"size:128" json:"name"`
	URL         string     `gorm:"type:text" json:"url"`
	Data        string     `gorm:"type:text" json:"data"` // 手动输入的 IP/CIDR 列表（每行一个），与 URL 二选一
	Type        string     `gorm:"size:16" json:"type"` // 仅 target=ip 时使用：whitelist | blacklist
	Target      string     `gorm:"size:16;default:ip" json:"target"` // ip | fingerprint | bot_profile
	IntervalMin int        `gorm:"default:60" json:"interval_min"`   // 同步周期（分钟）
	Enabled     bool       `gorm:"default:true" json:"enabled"`
	LastSyncAt  *time.Time `json:"last_sync_at"`
	LastStatus  string     `gorm:"size:255" json:"last_status"`
	LastCount   int        `json:"last_count"`
	CreatedAt   time.Time  `json:"created_at"`
	UpdatedAt   time.Time  `json:"updated_at"`
}
