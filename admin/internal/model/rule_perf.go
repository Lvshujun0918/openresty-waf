package model

import "time"

// RulePerf 规则耗时画像：引擎按规则聚合评估次数/耗时（µs）定时上报，
// 后台消费累计合并（hits/total_us 累加，max_us 取历史最大）。
type RulePerf struct {
	ID        uint      `gorm:"primaryKey" json:"id"`
	RuleID    string    `gorm:"size:32;uniqueIndex" json:"rule_id"`
	Hits      int64     `json:"hits"`     // 累计评估次数
	TotalUS   int64     `json:"total_us"` // 累计耗时（微秒）
	MaxUS     int64     `json:"max_us"`   // 单次最大耗时（微秒）
	UpdatedAt time.Time `json:"updated_at"`
}
