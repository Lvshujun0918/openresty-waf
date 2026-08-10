// Package config 管理后台配置（环境变量加载，带默认值）。
package config

import (
	"os"
	"strconv"
)

type Config struct {
	Server Server
	DB     DB
	Redis  Redis
	JWT    JWT
}

type Server struct {
	Addr string // 监听地址，如 :8081
}

type DB struct {
	Type string // sqlite | mysql
	DSN  string // sqlite 文件路径 或 mysql DSN
}

type Redis struct {
	Addr     string
	Password string
	DB       int
}

type JWT struct {
	Secret string
	Expire int // 过期时间（小时）
}

func Load() *Config {
	return &Config{
		Server: Server{Addr: getEnv("ADMIN_ADDR", ":8081")},
		DB: DB{
			Type: getEnv("ADMIN_DB_TYPE", "sqlite"),
			DSN:  getEnv("ADMIN_DB_DSN", "waf.db"),
		},
		Redis: Redis{
			Addr:     getEnv("REDIS_ADDR", "127.0.0.1:6379"),
			Password: getEnv("REDIS_PASSWORD", ""),
			DB:       getEnvInt("REDIS_DB", 0),
		},
		JWT: JWT{
			Secret: getEnv("ADMIN_JWT_SECRET", "openresty-waf-change-me"),
			Expire: getEnvInt("ADMIN_JWT_EXPIRE_HOURS", 24),
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
