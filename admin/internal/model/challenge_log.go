package model

import "time"

// ChallengeLog 人机验证事件（下发 / 通过 / 失败）
type ChallengeLog struct {
	ID        uint      `gorm:"primaryKey" json:"id"`
	Time      time.Time `gorm:"index" json:"time"`
	ReqID     string    `gorm:"size:64;index" json:"req_id"`
	ClientIP  string    `gorm:"size:64;index" json:"client_ip"`
	Country   string    `gorm:"size:64" json:"country"`
	Province  string    `gorm:"size:64" json:"province"`
	City      string    `gorm:"size:64" json:"city"`
	Action    string    `gorm:"size:16;index" json:"action"` // issue / pass / fail
	Method    string    `gorm:"size:16" json:"method"`
	Host      string    `gorm:"size:255" json:"host"`
	URI       string    `gorm:"size:255" json:"uri"`
	RuleName  string    `gorm:"size:128" json:"rule_name"` // 触发的触发规则名称
	Ja4       string    `gorm:"size:64" json:"ja4"`
	Ja4H      string    `gorm:"size:64" json:"ja4h"`                 // JA4H HTTP 客户端指纹        // JA4 TLS 指纹
	Headers   string    `gorm:"type:text" json:"headers"`   // 请求头 JSON（name/value 数组）
	Body      string    `gorm:"type:text" json:"body"`      // 请求体（最多 8KB）
	CreatedAt time.Time `json:"created_at"`
}
