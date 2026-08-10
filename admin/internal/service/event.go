package service

import (
	"context"
	"encoding/json"
	"time"

	"github.com/redis/go-redis/v9"
	"gorm.io/gorm"

	"openresty-waf/admin/internal/config"
	"openresty-waf/admin/internal/model"
)

// EventService 攻击事件：消费 Redis 队列落库 + 分页查询。
// WAF 侧 log.lua 以 redis 后端将事件 LPUSH 到队列，后台消费写入 DB。
type EventService struct {
	db  *gorm.DB
	rdb *redis.Client
	cfg *config.Config
	ctx context.Context
}

func NewEventService(db *gorm.DB, rdb *redis.Client, cfg *config.Config) *EventService {
	return &EventService{db: db, rdb: rdb, cfg: cfg, ctx: context.Background()}
}

// Consume 从 Redis 队列消费事件并写入 DB，返回本次消费条数。
// 使用 RPop 逐条消费，坏数据跳过，单个失败不中断。
func (s *EventService) Consume(limit int) (int, error) {
	key := s.cfg.Rule.EventKey
	count := 0
	for i := 0; i < limit; i++ {
		raw, err := s.rdb.RPop(s.ctx, key).Result()
		if err == redis.Nil {
			break // 队列已空
		}
		if err != nil {
			return count, err
		}
		var ev model.Event
		if err := json.Unmarshal([]byte(raw), &ev); err != nil {
			continue // 跳过无法解析的数据
		}
		if ev.Time.IsZero() {
			ev.Time = time.Now()
		}
		if err := s.db.Create(&ev).Error; err != nil {
			return count, err
		}
		count++
	}
	return count, nil
}

// List 分页查询攻击事件，支持 group / client_ip / rule_id 过滤
func (s *EventService) List(group, clientIP, ruleID string, page, pageSize int) ([]model.Event, int64, error) {
	q := s.db.Model(&model.Event{})
	if group != "" {
		q = q.Where("`group` = ?", group)
	}
	if clientIP != "" {
		q = q.Where("client_ip LIKE ?", "%"+clientIP+"%")
	}
	if ruleID != "" {
		q = q.Where("rule_id = ?", ruleID)
	}
	var total int64
	if err := q.Count(&total).Error; err != nil {
		return nil, 0, err
	}
	var events []model.Event
	if err := q.Order("id desc").Offset((page - 1) * pageSize).Limit(pageSize).Find(&events).Error; err != nil {
		return nil, 0, err
	}
	return events, total, nil
}
