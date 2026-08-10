package model

import "time"

// Rule 拦截规则，字段与 Lua 规则引擎 DSL 一一对应，可序列化后经 Redis 下发。
type Rule struct {
	ID         uint      `gorm:"primaryKey" json:"id"`
	RuleID     string    `gorm:"size:32;index" json:"rule_id"` // 如 20001
	Name       string    `gorm:"size:128" json:"name"`
	Group      string    `gorm:"size:32;index" json:"group"`   // sqli/xss/rce/lfi/ssrf/protocol/leak/scanner/custom
	Phase      string    `gorm:"size:32;default:access" json:"phase"`
	Severity   int       `gorm:"default:2" json:"severity"`
	Enabled    bool      `gorm:"default:true" json:"enabled"`
	Operator   string    `gorm:"size:32" json:"operator"` // REGEX/CIDR/PM/EQUALS/CONTAINS...
	Pattern    string    `gorm:"type:text" json:"pattern"`
	Transforms string    `gorm:"type:text" json:"transforms"` // JSON 数组，如 ["url_decode","to_lowercase"]
	Vars       string    `gorm:"type:text" json:"vars"`       // JSON 数组，如 [{"type":"URI_ARGS"}]
	Actions    string    `gorm:"type:text" json:"actions"`    // JSON 对象，如 {"disrupt":"BLOCK","status":403}
	Status     int       `gorm:"default:403" json:"status"`   // 便捷字段，Actions 中的状态码
	Message    string    `gorm:"size:255" json:"message"`     // 便捷字段，Actions 中的提示
	SiteID     uint      `gorm:"index;default:0" json:"site_id"` // 0 表示全局规则
	SortOrder  int       `gorm:"default:0" json:"sort_order"`
	CreatedAt  time.Time `json:"created_at"`
	UpdatedAt  time.Time `json:"updated_at"`
}
