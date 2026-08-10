package service

import (
	"context"
	"errors"
	"strconv"
	"time"

	"github.com/redis/go-redis/v9"
	"gorm.io/gorm"

	"openresty-waf/admin/internal/model"
)

// Setup 配置键
const (
	SetupKeyRedisAddr = "redis_addr"
	SetupKeyRedisPass = "redis_password"
	SetupKeyRedisDB   = "redis_db"
	SetupKeyDone      = "setup_done"
)

// RedisConfig Redis 连接配置
type RedisConfig struct {
	Addr     string `json:"addr"`
	Password string `json:"password"`
	DB       int    `json:"db"`
}

// SetupService 引导配置：首次启动引导页写入 Redis 连接信息并做连通性测试
type SetupService struct {
	db  *gorm.DB
	mgr *RedisManager
}

func NewSetupService(db *gorm.DB, mgr *RedisManager) *SetupService {
	return &SetupService{db: db, mgr: mgr}
}

func (s *SetupService) get(key string) (string, bool) {
	var row model.Setup
	if err := s.db.Where("key = ?", key).First(&row).Error; err != nil {
		return "", false
	}
	return row.Value, true
}

func (s *SetupService) getOr(key, def string) string {
	if v, ok := s.get(key); ok && v != "" {
		return v
	}
	return def
}

func (s *SetupService) set(key, value string) error {
	var row model.Setup
	err := s.db.Where("key = ?", key).First(&row).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return s.db.Create(&model.Setup{Key: key, Value: value}).Error
	}
	if err != nil {
		return err
	}
	return s.db.Model(&row).Update("value", value).Error
}

// GetRedisConfig 从 DB 读取 Redis 配置
func (s *SetupService) GetRedisConfig() (*RedisConfig, bool) {
	addr, ok := s.get(SetupKeyRedisAddr)
	if !ok || addr == "" {
		return nil, false
	}
	db, _ := strconv.Atoi(s.getOr(SetupKeyRedisDB, "0"))
	return &RedisConfig{
		Addr:     addr,
		Password: s.getOr(SetupKeyRedisPass, ""),
		DB:       db,
	}, true
}

// IsDone 引导是否完成
func (s *SetupService) IsDone() bool {
	v, ok := s.get(SetupKeyDone)
	return ok && v == "1"
}

// SaveRedisConfig 测试并保存 Redis 配置，重建连接
func (s *SetupService) SaveRedisConfig(addr, password string, db int) error {
	if addr == "" {
		return errors.New("Redis 地址不能为空")
	}
	cfg := &RedisConfig{Addr: addr, Password: password, DB: db}
	if err := testRedis(cfg); err != nil {
		return err
	}
	_ = s.set(SetupKeyRedisAddr, addr)
	_ = s.set(SetupKeyRedisPass, password)
	_ = s.set(SetupKeyRedisDB, strconv.Itoa(db))
	_ = s.set(SetupKeyDone, "1")
	s.mgr.Replace(cfg)
	return nil
}

// testRedis 连通性测试
func testRedis(cfg *RedisConfig) error {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	rdb := redis.NewClient(&redis.Options{
		Addr:     cfg.Addr,
		Password: cfg.Password,
		DB:       cfg.DB,
	})
	defer rdb.Close()
	if err := rdb.Ping(ctx).Err(); err != nil {
		return errors.New("Redis 连接失败: " + err.Error())
	}
	return nil
}
