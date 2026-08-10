package service

import (
	"sync"

	"github.com/redis/go-redis/v9"
)

// RedisManager 动态 Redis 客户端管理器。
// 单容器部署下后台启动时无需 Redis；首次引导页保存连接信息后
// 调用 Replace 重建客户端，后续规则下发 / 事件消费均通过它获取连接。
type RedisManager struct {
	mu  sync.RWMutex
	rdb *redis.Client
}

func NewRedisManager() *RedisManager {
	return &RedisManager{}
}

// Replace 重建客户端（保存 Redis 配置后调用；配置变更时旧连接自动关闭）
func (m *RedisManager) Replace(cfg *RedisConfig) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.rdb != nil {
		_ = m.rdb.Close()
	}
	m.rdb = redis.NewClient(&redis.Options{
		Addr:     cfg.Addr,
		Password: cfg.Password,
		DB:       cfg.DB,
	})
}

// GetClient 返回当前客户端；未配置返回 nil
func (m *RedisManager) GetClient() *redis.Client {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.rdb
}

// LoadFromSetup 启动时按 DB 中已保存的配置初始化（已完成引导的场景）
func (m *RedisManager) LoadFromSetup(s *SetupService) {
	if cfg, ok := s.GetRedisConfig(); ok {
		m.Replace(cfg)
	}
}
