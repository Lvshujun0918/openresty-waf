package model

import "time"

// TriggerCondition 触发条件：对请求参数进行筛选。
// Field: host（域名）| path（路径）| ua（User-Agent）| ip（客户端IP）| method（方法）| header（请求头）| args（Query 参数）
// Operator: equals（等于）| prefix（前缀）| contains（包含）| regex（正则）| cidr（IP段，仅 ip）| in（枚举，逗号分隔）
type TriggerCondition struct {
	Field    string `json:"field"`
	Operator string `json:"operator"`
	Value    string `json:"value"`
	Header   string `json:"header,omitempty"` // field=header 时指定请求头名
	Negate   bool   `json:"negate"`           // 取反
}

// TriggerRule 触发规则：条件（AND/OR 组合）命中后执行对应动作。
// Kind: challenge（触发人机验证）| exempt（豁免规则检测）| cc（触发 CC 限流）
// Config: 动作配置 JSON，kind=cc -> {"rate":"100/60","ban_duration":300}；
//         kind=challenge -> {"mode":"basic"}；kind=exempt 可为空。
type TriggerRule struct {
	ID         uint      `gorm:"primaryKey" json:"id"`
	Name       string    `gorm:"size:64" json:"name"`
	Kind       string    `gorm:"size:16;index" json:"kind"`
	MatchLogic string    `gorm:"size:8" json:"match_logic"` // and | or
	Enabled    bool      `gorm:"index" json:"enabled"`
	SortOrder  int       `gorm:"default:0" json:"sort_order"`
	Conditions string    `gorm:"type:text" json:"conditions"` // TriggerCondition JSON 数组
	Config     string    `gorm:"type:text" json:"config"`     // 动作配置 JSON
	CreatedAt  time.Time `json:"created_at"`
	UpdatedAt  time.Time `json:"updated_at"`
}
