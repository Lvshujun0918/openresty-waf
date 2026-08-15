package model

import "time"

// AuditLog 操作审计日志：记录管理后台的写操作与关键安全事件
// （谁在什么时间做了什么操作），等保审计项，日志不可删除。
type AuditLog struct {
	ID        uint      `gorm:"primaryKey" json:"id"`
	Username  string    `gorm:"size:64;index" json:"username"` // 操作人（未登录如登录失败为 "-"）
	Action    string    `gorm:"size:16" json:"action"`         // login / logout / create / update / delete / publish / rollback / ban / unban / other
	Method    string    `gorm:"size:8" json:"method"`          // HTTP 方法
	Path      string    `gorm:"size:255" json:"path"`          // 请求路径
	Detail    string    `gorm:"size:512" json:"detail"`        // 简要描述（body 摘要）
	ClientIP  string    `gorm:"size:64" json:"client_ip"`
	Success   bool      `json:"success"`                       // 操作是否成功
	CreatedAt time.Time `gorm:"index" json:"created_at"`
}
