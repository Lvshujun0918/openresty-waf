package model

import "time"

// Event 攻击事件（由 WAF 日志落库）
type Event struct {
	ID        uint      `gorm:"primaryKey" json:"id"`
	Time      time.Time `gorm:"index" json:"time"`   // 攻击时间
	ClientIP  string    `gorm:"size:64;index" json:"client_ip"`
	Method    string    `gorm:"size:16" json:"method"`
	Host      string    `gorm:"size:255" json:"host"`
	URI       string    `gorm:"type:text" json:"uri"`
	RuleID    string    `gorm:"size:32;index" json:"rule_id"`
	Group     string    `gorm:"size:32;index" json:"group"`
	Message   string    `gorm:"size:255" json:"msg"` // 与 WAF 日志字段 msg 一致
	Severity  int       `json:"severity"`
	Status    int       `json:"status"`
	CreatedAt time.Time `json:"created_at"`
}
