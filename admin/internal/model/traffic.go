package model

import "time"

// TrafficLog 全量流量记录：开启全量记录模式后，引擎将每个请求上报一条记录。
// 与攻击事件分离，可配置保留天数由后台定时清理。
type TrafficLog struct {
	ID           uint      `gorm:"primaryKey" json:"id"`
	Time         time.Time `gorm:"index" json:"time"`       // 请求时间（RFC3339 UTC）
	ClientIP     string    `gorm:"size:64;index" json:"client_ip"`
	Method       string    `gorm:"size:16" json:"method"`
	Host         string    `gorm:"size:255;index" json:"host"`
	URI          string    `gorm:"type:text" json:"uri"`
	Status       int       `json:"status"`
	UserAgent    string    `gorm:"size:512" json:"user_agent"`
	Attack       bool      `gorm:"index" json:"attack"`          // 是否命中攻击规则
	RuleIDs      string    `gorm:"size:255" json:"rule_ids"`     // 命中的规则 id（逗号分隔）
	ResponseTime float64   `json:"response_time"`                // 响应耗时（毫秒）
	CreatedAt    time.Time `json:"created_at"`
}
