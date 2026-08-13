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

// EventService 攻击事件：消费 Redis 队列落库 + 分页查询。
// WAF 侧 log.lua 以 redis 后端将事件 LPUSH 到队列，后台消费写入 DB。
type EventService struct {
	db  *gorm.DB
	mgr *RedisManager
	cfg *config.Config
	ctx context.Context
}

func NewEventService(db *gorm.DB, mgr *RedisManager, cfg *config.Config) *EventService {
	return &EventService{db: db, mgr: mgr, cfg: cfg, ctx: context.Background()}
}

// Consume 从 Redis 队列消费事件并写入 DB，返回本次消费条数。
// 使用 RPop 逐条消费，坏数据跳过，单个失败不中断。
func (s *EventService) Consume(limit int) (int, error) {
	rdb := s.mgr.GetClient()
	if rdb == nil {
		return 0, errors.New("Redis 未配置，请先在引导页完成 Redis 配置")
	}
	key := s.cfg.Rule.EventKey
	count := 0
	for i := 0; i < limit; i++ {
		raw, err := rdb.RPop(s.ctx, key).Result()
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

// List 分页查询攻击事件，支持 group / client_ip / rule_id / host / action 过滤
// action: "block"=status>=400（拦截），"record"=status<400（仅记录）
func (s *EventService) List(group, clientIP, ruleID, host, action string, page, pageSize int) ([]model.Event, int64, error) {
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
	if host != "" {
		q = q.Where("host LIKE ?", "%"+host+"%")
	}
	if action == "block" {
		q = q.Where("status >= ?", 400)
	} else if action == "record" {
		q = q.Where("status < ?", 400)
	}
	var total int64
	if err := q.Count(&total).Error; err != nil {
		return nil, 0, err
	}
	// 列表不返回大字段（命中规则详情/请求头/请求体），详情接口单独获取
	var events []model.Event
	if err := q.Select("id", "time", "req_id", "client_ip", "country", "province", "city",
		"method", "host", "uri", "rule_id", "rule_ids", "`group`", "message",
		"severity", "status", "created_at").
		Order("id desc").Offset((page - 1) * pageSize).Limit(pageSize).Find(&events).Error; err != nil {
		return nil, 0, err
	}
	return events, total, nil
}

// Get 按 ID 获取事件完整信息（含命中规则详情 / 请求头 / 请求体）
func (s *EventService) Get(id uint) (*model.Event, error) {
	var ev model.Event
	if err := s.db.First(&ev, id).Error; err != nil {
		return nil, err
	}
	return &ev, nil
}
