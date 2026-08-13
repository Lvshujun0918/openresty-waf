package model

import "time"

// CcLog CC 触发事件（频率超限触发封禁）
type CcLog struct {
	ID        uint      `gorm:"primaryKey" json:"id"`
	Time      time.Time `gorm:"index" json:"time"`
	ReqID     string    `gorm:"size:64;index" json:"req_id"`
	ClientIP  string    `gorm:"size:64;index" json:"client_ip"`
	Country   string    `gorm:"size:64" json:"country"`
	Province  string    `gorm:"size:64" json:"province"`
	City      string    `gorm:"size:64" json:"city"`
	Method    string    `gorm:"size:16" json:"method"`
	Host      string    `gorm:"size:255" json:"host"`
	URI       string    `gorm:"type:text" json:"uri"`
	RuleName  string    `gorm:"size:128" json:"rule_name"` // 触发的触发规则名称
	Headers   string    `gorm:"type:text" json:"headers"`  // 请求头 JSON（name/value 数组）
	Body      string    `gorm:"type:text" json:"body"`     // 请求体（最多 8KB）
	Status    int       `json:"status"`                    // 拦截时返回的状态码
	CreatedAt time.Time `json:"created_at"`
}
