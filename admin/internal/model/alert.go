package model

import "time"

// AlertChannel 告警通知通道。
// Type: webhook（通用 JSON POST）| dingtalk | wecom | feishu | email（SMTP）。
type AlertChannel struct {
	ID         uint      `gorm:"primaryKey" json:"id"`
	Name       string    `gorm:"size:64" json:"name"`
	Type       string    `gorm:"size:16" json:"type"`
	WebhookURL string    `gorm:"size:512" json:"webhook_url"` // webhook 类通道的 URL
	Secret     string    `gorm:"size:256" json:"-"`           // 签名密钥/钉钉等 access_token（不回显）
	SMTPHost   string    `gorm:"size:128" json:"smtp_host"`   // email 通道
	SMTPPort   int       `json:"smtp_port"`
	SMTPUser   string    `gorm:"size:128" json:"smtp_user"`
	SMTPPass   string    `gorm:"size:128" json:"-"`
	SMTPFrom   string    `gorm:"size:128" json:"smtp_from"`
	Enabled    bool      `json:"enabled"`
	CreatedAt  time.Time `json:"created_at"`
	UpdatedAt  time.Time `json:"updated_at"`
}

// AlertRule 告警规则。
// Type: event_surge（窗口内攻击事件数超阈值）| engine_offline（全部引擎离线）。
// Action: notify（仅通知）| rollback_rules（通知并自动回滚最近一次规则发布）。
type AlertRule struct {
	ID              uint       `gorm:"primaryKey" json:"id"`
	Name            string     `gorm:"size:64" json:"name"`
	Type            string     `gorm:"size:32" json:"type"`
	WindowSec       int        `json:"window_sec"` // 统计窗口（秒）
	Threshold       int        `json:"threshold"`  // 触发阈值
	Action          string     `gorm:"size:16" json:"action"` // notify | rollback_rules
	ChannelID       uint       `json:"channel_id"`
	CooldownSec     int        `json:"cooldown_sec"` // 防抖：触发后冷却时间
	Enabled         bool       `json:"enabled"`
	LastTriggeredAt *time.Time `json:"last_triggered_at"`
	CreatedAt       time.Time  `json:"created_at"`
	UpdatedAt       time.Time  `json:"updated_at"`
}
