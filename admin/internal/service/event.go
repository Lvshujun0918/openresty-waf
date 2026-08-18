package service

import (
	"context"
	"encoding/json"
	"errors"
	"strconv"
	"strings"
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

// Consume 从 Redis 队列批量消费事件并写入 DB，返回本次消费条数。
// 批量 RPop + 批量插入（CreateInBatches），攻击风暴下避免逐条往返与逐条写库；
// 坏数据跳过，单个失败不中断。
func (s *EventService) Consume(limit int) (int, error) {
	rdb := s.mgr.GetClient()
	if rdb == nil {
		return 0, errors.New("Redis 未配置，请先在引导页完成 Redis 配置")
	}
	key := s.cfg.Rule.EventKey
	raws, err := rdb.RPopCount(s.ctx, key, limit).Result()
	if err == redis.Nil {
		return 0, nil // 队列已空
	}
	if err != nil {
		return 0, err
	}
	events := make([]model.Event, 0, len(raws))
	for _, raw := range raws {
		var ev model.Event
		if err := json.Unmarshal([]byte(raw), &ev); err != nil {
			continue // 跳过无法解析的数据
		}
		if ev.Time.IsZero() {
			ev.Time = time.Now()
		}
		// 爬虫命中不算攻击：丢弃 crawler 组事件（引擎新版本已不上报，
		// 此处防御旧引擎/历史队列残留数据）
		if ev.Group == "crawler" {
			continue
		}
		events = append(events, ev)
	}
	if len(events) > 0 {
		if err := s.db.CreateInBatches(events, 100).Error; err != nil {
			return 0, err
		}
	}
	return len(events), nil
}

// List 分页查询攻击事件，支持 group / client_ip / rule_id / host / action 过滤
// action: "block"=status>=400（拦截），"record"=status<400（仅记录）
func (s *EventService) List(group, clientIP, ruleID, host, action string, page, pageSize int) ([]model.Event, int64, error) {
	q := s.buildListQuery(group, clientIP, ruleID, host, action)
	var total int64
	if err := q.Count(&total).Error; err != nil {
		return nil, 0, err
	}
	// 列表不返回大字段（命中规则详情/请求头/请求体），详情接口单独获取
	var events []model.Event
	if err := q.Select("id", "time", "req_id", "client_ip", "country", "province", "city",
		"method", "host", "uri", "rule_id", "rule_ids", "`group`", "message",
		"severity", "status", "blocked", "created_at", "false_positive").
		Order("id desc").Offset((page - 1) * pageSize).Limit(pageSize).Find(&events).Error; err != nil {
		return nil, 0, err
	}
	return events, total, nil
}

// buildListQuery 列表查询条件（List / Export 共用）
func (s *EventService) buildListQuery(group, clientIP, ruleID, host, action string) *gorm.DB {
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
		q = q.Where("blocked = ?", true) // 仅 WAF 真正拦截（404 等后端状态码不算）
	} else if action == "record" {
		q = q.Where("blocked = ?", false)
	}
	return q
}

// ExportAll 导出全部匹配记录（不分页，限制上限防拉爆；返回记录切片供 CSV 序列化）
func (s *EventService) ExportAll(group, clientIP, ruleID, host, action string, limit int) ([]model.Event, error) {
	if limit <= 0 || limit > 10000 {
		limit = 10000
	}
	var events []model.Event
	if err := s.buildListQuery(group, clientIP, ruleID, host, action).
		Order("id desc").Limit(limit).Find(&events).Error; err != nil {
		return nil, err
	}
	return events, nil
}

// Get 按 ID 获取事件完整信息（含命中规则详情 / 请求头 / 请求体）
func (s *EventService) Get(id uint) (*model.Event, error) {
	var ev model.Event
	if err := s.db.First(&ev, id).Error; err != nil {
		return nil, err
	}
	return &ev, nil
}

// MarkFalsePositive 标记/取消误报（事件处置闭环：误报标记计入规则命中率统计）
func (s *EventService) MarkFalsePositive(id uint, flag bool) error {
	res := s.db.Model(&model.Event{}).Where("id = ?", id).
		Update("false_positive", flag)
	if res.RowsAffected == 0 {
		return errors.New("事件不存在")
	}
	return res.Error
}

// CreateExemptRule 一键豁免：基于事件 host + 路径前缀生成一条 exempt 触发规则
// （命中即跳过规则检测；需在触发规则页发布后生效，返回生成的规则 ID）
func (s *EventService) CreateExemptRule(id uint) (uint, error) {
	ev, err := s.Get(id)
	if err != nil {
		return 0, err
	}
	path := ev.URI
	if idx := strings.IndexByte(path, '?'); idx >= 0 {
		path = path[:idx]
	}
	if path == "" {
		path = "/"
	}
	conds := []model.TriggerCondition{
		{Field: "host", Operator: "equals", Value: ev.Host},
		{Field: "path", Operator: "prefix", Value: path},
	}
	body, err := json.Marshal(conds)
	if err != nil {
		return 0, err
	}
	rule := model.TriggerRule{
		Name:       "事件豁免-" + strconv.FormatUint(uint64(ev.ID), 10) + "-" + ev.RuleID,
		Kind:       "exempt",
		MatchLogic: "and",
		Enabled:    true,
		Conditions: string(body),
	}
	if err := s.db.Create(&rule).Error; err != nil {
		return 0, err
	}
	return rule.ID, nil
}
