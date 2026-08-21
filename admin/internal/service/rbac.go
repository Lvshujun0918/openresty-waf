// Package service 业务逻辑层。
package service

import "strings"

// RBAC 角色（轻量三档，见 README「访问控制」）：
//   - super：超级管理员，全部权限（含用户/API Token/备份等系统操作）
//   - ops：安全运营，业务防护写操作（规则/名单/封禁/事件处置/告警/配置），
//     无系统管理权限
//   - viewer：只读审计，仅查询类接口 + 自身账号安全设置
const (
	RoleSuper  = "super"
	RoleOps    = "ops"
	RoleViewer = "viewer"
)

// 权限模块（写操作按模块授权；GET 查询对所有登录角色开放，system 除外）
const (
	PermRules      = "rules"      // 规则/触发规则管理与发布
	PermProtection = "protection" // 名单/封禁/事件处置/Bot/JA4 指纹库
	PermAlerts     = "alerts"     // 告警通道与规则
	PermConfig     = "config"     // WAF 运行配置
	PermMonitor    = "monitor"    // 流量/挑战/CC 记录消费与清理
	PermSystem     = "system"     // 用户/API Token/Redis 引导/数据库备份（仅 super）
)

// opsWritePerms ops 角色可写的模块集合（super 恒全量，viewer 无写权限）
var opsWritePerms = map[string]bool{
	PermRules:      true,
	PermProtection: true,
	PermAlerts:     true,
	PermConfig:     true,
	PermMonitor:    true,
}

// ValidRole 角色是否合法
func ValidRole(role string) bool {
	switch role {
	case RoleSuper, RoleOps, RoleViewer:
		return true
	}
	return false
}

// NormalizeRole 空角色回退 super（兼容历史账号/旧令牌）
func NormalizeRole(role string) string {
	if role == "" {
		return RoleSuper
	}
	return role
}

// CanWrite 判断角色对模块的写权限：
//   - super：全部放行
//   - system 模块：仅 super
//   - ops：业务模块放行
//   - viewer：只读，一律拒绝
func CanWrite(role, module string) bool {
	role = NormalizeRole(role)
	if role == RoleSuper {
		return true
	}
	if module == PermSystem {
		return false
	}
	if role == RoleOps {
		return opsWritePerms[module]
	}
	return false
}

// CanRead 判断角色对模块的读权限（system 模块仅 super 可读，
// 避免低权角色枚举用户/Token 或下载备份）
func CanRead(role, module string) bool {
	if module == PermSystem {
		return NormalizeRole(role) == RoleSuper
	}
	return true
}

// ModuleForPath 按路径前缀映射权限模块。
// 未匹配到的路径返回空串（无模块约束，如 /auth/* 自助接口、仪表盘查询）。
func ModuleForPath(path string) string {
	path = strings.TrimPrefix(path, "/api/")
	path = strings.TrimPrefix(path, "/api")
	switch {
	// 系统管理（读写均限 super）
	case path == "tokens" || strings.HasPrefix(path, "tokens/"),
		path == "users" || strings.HasPrefix(path, "users/"),
		path == "db/backup",
		path == "setup/redis":
		return PermSystem
	// 规则与触发规则
	case strings.HasPrefix(path, "rules"), strings.HasPrefix(path, "trigger-rules"):
		return PermRules
	// 名单/封禁/事件处置/Bot/JA4
	case strings.HasPrefix(path, "ip-list-subs"), strings.HasPrefix(path, "bans"),
		strings.HasPrefix(path, "events"), strings.HasPrefix(path, "bots"),
		strings.HasPrefix(path, "ja4"):
		return PermProtection
	// 告警
	case strings.HasPrefix(path, "alerts"):
		return PermAlerts
	// 运行配置
	case path == "config" || strings.HasPrefix(path, "config/"):
		return PermConfig
	// 数据管道维护（流量/人机验证/CC 记录消费与清理、实时监控）
	case strings.HasPrefix(path, "traffic"), strings.HasPrefix(path, "challenges"),
		strings.HasPrefix(path, "cc-logs"), strings.HasPrefix(path, "monitor"):
		return PermMonitor
	}
	return ""
}
