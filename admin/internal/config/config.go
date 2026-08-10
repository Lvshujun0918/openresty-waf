// Package config 管理后台配置（环境变量加载，带默认值）。
package config

import (
	"os"
	"strconv"
)

type Config struct {
	Server    Server
	DB        DB
	JWT       JWT
	Rule      Rule
	WAF       WAF
	WAFConfig WAFConfig
}

type Server struct {
	Addr string // 监听地址，如 :8081
}

type DB struct {
	Type string // sqlite | mysql
	DSN  string // sqlite 文件路径 或 mysql DSN
}

type JWT struct {
	Secret string
	Expire int // 过期时间（小时）
}

// WAF WAF 组件分发相关
type WAF struct {
	DistDir string // WAF Lua 组件打包目录（Docker 镜像内置 /opt/waf-dist）
}

// WAFConfig WAF 运行配置下发相关键（与 waf/config.lua 的 rule_refresh 约定一致）
type WAFConfig struct {
	DataKey    string // Redis 配置数据键（JSON）
	VersionKey string // Redis 配置版本键，自增触发 Lua 引擎热更新
}

// Rule Redis 规则下发相关键（与 waf/config.lua 的 rule_refresh 约定保持一致）
type Rule struct {
	VersionKey string // 版本号键，自增触发 Lua 引擎热更新
	RulesetKey string // 完整规则集 JSON 键
	EventKey   string // 攻击事件队列键（WAF log.lua redis 后端 LPUSH）
}

func Load() *Config {
	return &Config{
		Server: Server{Addr: getEnv("ADMIN_ADDR", ":8081")},
		DB: DB{
			Type: getEnv("ADMIN_DB_TYPE", "sqlite"),
			DSN:  getEnv("ADMIN_DB_DSN", "waf.db"),
		},
		JWT: JWT{
			Secret: getEnv("ADMIN_JWT_SECRET", "openresty-waf-change-me"),
			Expire: getEnvInt("ADMIN_JWT_EXPIRE_HOURS", 24),
		},
		Rule: Rule{
			VersionKey: getEnv("WAF_RULE_VERSION_KEY", "waf:rule:version"),
			RulesetKey: getEnv("WAF_RULE_RULESET_KEY", "waf:rule:ruleset"),
			EventKey:   getEnv("WAF_EVENT_KEY", "waf:event:list"),
		},
		WAF: WAF{
			DistDir: getEnv("WAF_DIST_DIR", "/opt/waf-dist"),
		},
		WAFConfig: WAFConfig{
			DataKey:    getEnv("WAF_CONFIG_DATA_KEY", "waf:config:data"),
			VersionKey: getEnv("WAF_CONFIG_VERSION_KEY", "waf:config:version"),
		},
	}
}

func getEnv(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func getEnvInt(key string, def int) int {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return def
}
