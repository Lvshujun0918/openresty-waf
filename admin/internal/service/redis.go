package service

import (
	"context"
	"log"

	"github.com/redis/go-redis/v9"

	"openresty-waf/admin/internal/config"
)

// InitRedis 初始化 Redis 客户端并做连接探测。
// 规则热下发、攻击事件缓冲均依赖 Redis。
func InitRedis(cfg *config.Config) *redis.Client {
	rdb := redis.NewClient(&redis.Options{
		Addr:     cfg.Redis.Addr,
		Password: cfg.Redis.Password,
		DB:       cfg.Redis.DB,
	})
	if err := rdb.Ping(context.Background()).Err(); err != nil {
		log.Printf("警告: Redis 连接失败(%s): %v", cfg.Redis.Addr, err)
	}
	return rdb
}
