package model

import (
	"strconv"
	"time"
)

// RuleParanoiaLevel 返回 CRS 规则所属偏执级别（1-4）。
// 非 CRS / 用户自定义规则返回 1（始终在最低档位参与检测）。
// 高档位规则：SQL 注入启发式（认证绕过探测 / classic probings / 特殊字符异常）、
// XSS 混淆/编码类——误报高，仅在用户调高档位时启用。
func RuleParanoiaLevel(ruleID string) int {
	id, err := strconv.Atoi(ruleID)
	if err != nil {
		return 1
	}
	switch {
	case (id >= 942340 && id <= 942349) ||
		(id >= 942370 && id <= 942379) ||
		(id >= 942420 && id <= 942439) ||
		(id >= 942490 && id <= 942499):
		return 2
	case id >= 941350 && id <= 941399:
		return 2
	default:
		return 1
	}
}

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
	SortOrder  int       `gorm:"default:0" json:"sort_order"`
	IsSeed     bool      `gorm:"default:false" json:"is_seed"` // 内置种子标记（升级时自动替换）
	CreatedAt  time.Time `json:"created_at"`
	UpdatedAt  time.Time `json:"updated_at"`
}
