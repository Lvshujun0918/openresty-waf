// Package model API Token：供脚本/CI 等非交互调用方访问管理 API。
package model

import "time"

// ApiToken 访问令牌。明文仅在创建时返回一次，库中只存 SHA-256。
type ApiToken struct {
	ID         uint       `gorm:"primaryKey" json:"id"`
	Name       string     `gorm:"size:64;not null" json:"name"`      // 用途备注
	Prefix     string     `gorm:"size:16;index" json:"prefix"`       // 明文前缀（识别用）
	TokenHash  string     `gorm:"size:64;uniqueIndex" json:"-"`      // SHA-256 hex
	LastUsedAt *time.Time `json:"last_used_at"`
	RevokedAt  *time.Time `json:"revoked_at"`
	CreatedAt  time.Time  `json:"created_at"`
}
