package model

import "time"

// Ja4Profile JA4 客户端指纹库：已知客户端/工具/恶意软件的 JA4 指纹映射。
// Category: browser（浏览器）| tool（工具/库）| malware（恶意软件）| other。
// 恶意条目（malware）seed 时自动联动写入 BotFingerprint（引擎拦截）。
type Ja4Profile struct {
	ID          uint      `gorm:"primaryKey" json:"id"`
	Ja4         string    `gorm:"size:64;index" json:"ja4"`     // 完整 JA4
	AcPrefix    string    `gorm:"size:24;index" json:"ac_prefix"` // a段_+c段前6（JA4_ac，抗 cipher 轮换）
	Name        string    `gorm:"size:64" json:"name"`          // 客户端名称（如 Chromium / Sliver Agent）
	Category    string    `gorm:"size:16;index" json:"category"` // browser | tool | malware | other
	Description string    `gorm:"size:255" json:"description"`
	Enabled     bool      `json:"enabled"`
	Source      string    `gorm:"size:16" json:"source"` // seed | manual
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}
