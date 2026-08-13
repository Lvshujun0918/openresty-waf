package service

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/redis/go-redis/v9"
	"gorm.io/gorm"

	"openresty-waf/admin/internal/config"
	"openresty-waf/admin/internal/model"
)

// ChallengeKey 引擎推送人机验证事件的 Redis 队列 key（与 waf/detectors/challenge.lua 一致）
const ChallengeKey = "waf:challenge:list"

// ChallengeService 人机验证事件：消费 Redis 队列落库 + 分页查询。
type ChallengeService struct {
	db  *gorm.DB
	mgr *RedisManager
	cfg *config.Config
	ctx context.Context
}

func NewChallengeService(db *gorm.DB, mgr *RedisManager, cfg *config.Config) *ChallengeService {
	return &ChallengeService{db: db, mgr: mgr, cfg: cfg, ctx: context.Background()}
}

// Consume 从 Redis 队列消费人机验证事件并写入 DB，返回本次消费条数
func (s *ChallengeService) Consume(limit int) (int, error) {
	rdb := s.mgr.GetClient()
	if rdb == nil {
		return 0, errors.New("Redis 未配置")
	}
	count := 0
	for i := 0; i < limit; i++ {
		raw, err := rdb.RPop(s.ctx, ChallengeKey).Result()
		if err == redis.Nil {
			break
		}
		if err != nil {
			return count, err
		}
		var rec model.ChallengeLog
		if err := json.Unmarshal([]byte(raw), &rec); err != nil {
			continue // 跳过坏数据
		}
		if rec.Time.IsZero() {
			rec.Time = time.Now()
		}
		if err := s.db.Create(&rec).Error; err != nil {
			return count, err
		}
		count++
	}
	return count, nil
}

// List 分页查询人机验证事件，支持 client_ip / action 过滤
func (s *ChallengeService) List(clientIP, action string, page, pageSize int) ([]model.ChallengeLog, int64, error) {
	q := s.db.Model(&model.ChallengeLog{})
	if clientIP != "" {
		q = q.Where("client_ip LIKE ?", "%"+clientIP+"%")
	}
	if action != "" {
		q = q.Where("action = ?", action)
	}
	var total int64
	if err := q.Count(&total).Error; err != nil {
		return nil, 0, err
	}
	var logs []model.ChallengeLog
	if err := q.Order("id desc").Offset((page - 1) * pageSize).Limit(pageSize).Find(&logs).Error; err != nil {
		return nil, 0, err
	}
	return logs, total, nil
}
