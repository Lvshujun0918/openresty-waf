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
	URI       string    `gorm:"size:255" json:"uri"`
	CreatedAt time.Time `json:"created_at"`
}
