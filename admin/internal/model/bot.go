package model

import "time"

// BotProfile 爬虫画像：UA 正则 + 可选 IP 段（搜索引擎类验证真实性）。
// Engine=true 时校验来源 IP 是否在 Ips 网段内（不在 = 虚假爬虫）。
// Source: ""（手动）| subscription（订阅同步）；SubID 关联订阅源。
type BotProfile struct {
	ID        uint      `gorm:"primaryKey" json:"id"`
	Name      string    `gorm:"size:64;index" json:"name"`
	UA        string    `gorm:"size:512" json:"ua"`      // PCRE 正则（可含 | 交替）
	Ips       string    `gorm:"size:1024" json:"ips"`    // CIDR 数组 JSON（engine 类必填）
	Engine    bool      `json:"engine"`                  // 是否为搜索引擎类（需 IP 段验证）
	Enabled   bool      `json:"enabled"`
	SortOrder int       `json:"sort_order"`
	Source    string    `gorm:"size:16;index" json:"source"` // "" | subscription
	SubID     uint      `gorm:"index" json:"sub_id"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// BotFingerprint 恶意指纹库：HTTP 客户端指纹（组合头哈希）。
// Match: exact（精确）| regex（正则）。
// Source: ""（手动）| subscription（订阅同步）；SubID 关联订阅源。
type BotFingerprint struct {
	ID          uint      `gorm:"primaryKey" json:"id"`
	Name        string    `gorm:"size:64" json:"name"`
	Value       string    `gorm:"size:128" json:"value"`
	Match       string    `gorm:"size:8" json:"match"` // exact | regex
	Description string    `gorm:"size:255" json:"description"`
	Enabled     bool      `json:"enabled"`
	Source      string    `gorm:"size:16;index" json:"source"` // "" | subscription
	SubID       uint      `gorm:"index" json:"sub_id"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// BotLog 爬虫访问记录（引擎识别为爬虫时上报，含虚假判定与恶意标记）
type BotLog struct {
	ID           uint      `gorm:"primaryKey" json:"id"`
	Time         time.Time `gorm:"index" json:"time"`
	ReqID        string    `gorm:"size:64" json:"req_id"`
	ClientIP     string    `gorm:"size:64;index" json:"client_ip"`
	Country      string    `gorm:"size:64" json:"country"`
	Province     string    `gorm:"size:64" json:"province"`
	City         string    `gorm:"size:64" json:"city"`
	Method       string    `gorm:"size:16" json:"method"`
	Host         string    `gorm:"size:255" json:"host"`
	URI          string    `gorm:"type:text" json:"uri"`
	UA           string    `gorm:"size:512" json:"ua"`
	Fingerprint  string    `gorm:"size:64;index" json:"fingerprint"` // HTTP 组合指纹（兜底/统计）
	Ja4          string    `gorm:"size:64;index" json:"ja4"`         // JA4 TLS 指纹（TLS 连接）
	Profile      string    `gorm:"size:64;index" json:"profile"`     // 命中的爬虫画像
	Engine       bool      `json:"engine"`                           // 搜索引擎类
	Fake         bool      `gorm:"index" json:"fake"`                // 虚假爬虫（UA 声称搜索引擎但 IP 不匹配）
	MaliciousIP  bool      `json:"malicious_ip"`                     // 来源命中恶意 IP 库
	MaliciousFP  string    `gorm:"size:64" json:"malicious_fp"`      // 指纹命中恶意指纹库名称（空=未命中）
	FpSource     string    `gorm:"size:8" json:"fp_source"`          // 命中指纹来源（ja4 | http）
	Status       int       `json:"status"`
	CreatedAt    time.Time `json:"created_at"`
}
