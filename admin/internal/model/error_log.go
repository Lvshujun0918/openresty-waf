package model

import "time"

// ErrorLog 引擎运行时报错（ERR/WARN 级），由引擎 errlog.lua 异步推送 Redis 队列，
// 后台消费落库后在「报错汇总」页统一展示，免翻各处 nginx error.log。
type ErrorLog struct {
	ID            uint      `gorm:"primaryKey" json:"id"`
	Time          time.Time `gorm:"index" json:"time"`
	Level         string    `gorm:"size:8;index" json:"level"`   // error / warn
	Source        string    `gorm:"size:32;index" json:"source"` // 来源模块：access/init/engine/operators/cc/challenge/upload/ja4/log...
	Message       string    `gorm:"type:text" json:"message"`
	ReqID         string    `gorm:"size:64;index" json:"req_id"`
	ClientIP      string    `gorm:"size:64;index" json:"client_ip"`
	Host          string    `gorm:"size:255" json:"host"`
	URI           string    `gorm:"type:text" json:"uri"`
	EngineVersion string    `gorm:"size:16" json:"engine_version"`
	CreatedAt     time.Time `json:"created_at"`
}
