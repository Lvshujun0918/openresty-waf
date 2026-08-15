package model

import "time"

// User 管理后台管理员账号
type User struct {
	ID           uint      `gorm:"primaryKey" json:"id"`
	Username     string    `gorm:"uniqueIndex;size:64;not null" json:"username"`
	PasswordHash string    `gorm:"size:128;not null" json:"-"`
	TotpSecret   string    `gorm:"size:64" json:"-"`      // TOTP 密钥（base32，确认后启用）
	TotpEnabled  bool      `gorm:"default:false" json:"totp_enabled"`
	FailedLogins int       `gorm:"default:0" json:"-"`    // 连续失败次数（防爆破）
	LockedUntil  *time.Time `json:"-"`                    // 锁定截止时间（防爆破）
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}
