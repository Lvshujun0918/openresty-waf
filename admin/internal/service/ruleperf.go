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

// RulePerfKey 引擎推送规则耗时画像的 Redis 队列 key（与 waf/rule_perf.lua 一致）
const RulePerfKey = "waf:ruleperf:list"

// RulePerfService 规则耗时画像：消费 Redis 队列累计落库 + 聚合查询 + 重置。
type RulePerfService struct {
	db  *gorm.DB
	mgr *RedisManager
	cfg *config.Config
	ctx context.Context
}

func NewRulePerfService(db *gorm.DB, mgr *RedisManager, cfg *config.Config) *RulePerfService {
	return &RulePerfService{db: db, mgr: mgr, cfg: cfg, ctx: context.Background()}
}

// rulePerfSample 引擎上报的单条规则样本（waf/rule_perf.lua flush 数组元素）
type rulePerfSample struct {
	ID      string `json:"id"`
	N       int64  `json:"n"`
	TotalUS int64  `json:"total_us"`
	MaxUS   int64  `json:"max_us"`
	Time    int64  `json:"time"`
}

// Consume 从 Redis 队列批量消费画像快照并累计合并入 DB，返回本次消费条数。
// 引擎每次 flush 推送一条 JSON 数组（整 worker 快照），此处逐数组展开合并。
func (s *RulePerfService) Consume(limit int) (int, error) {
	rdb := s.mgr.GetClient()
	if rdb == nil {
		return 0, errors.New("Redis 未配置")
	}
	raws, err := rdb.RPopCount(s.ctx, RulePerfKey, limit).Result()
	if err == redis.Nil {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}

	// 跨快照按规则聚合，减少写库往返
	type acc struct{ hits, totalUS, maxUS int64 }
	merged := map[string]*acc{}
	for _, raw := range raws {
		var arr []rulePerfSample
		if err := json.Unmarshal([]byte(raw), &arr); err != nil {
			continue // 跳过坏数据
		}
		for _, sm := range arr {
			if sm.ID == "" || sm.N <= 0 {
				continue
			}
			a := merged[sm.ID]
			if a == nil {
				a = &acc{}
				merged[sm.ID] = a
			}
			a.hits += sm.N
			a.totalUS += sm.TotalUS
			if sm.MaxUS > a.maxUS {
				a.maxUS = sm.MaxUS
			}
		}
	}
	if len(merged) == 0 {
		return len(raws), nil
	}

	now := time.Now()
	for id, a := range merged {
		var rp model.RulePerf
		err := s.db.Where("rule_id = ?", id).First(&rp).Error
		if errors.Is(err, gorm.ErrRecordNotFound) {
			rp = model.RulePerf{RuleID: id, Hits: a.hits, TotalUS: a.totalUS, MaxUS: a.maxUS, UpdatedAt: now}
			if err := s.db.Create(&rp).Error; err != nil {
				return 0, err
			}
			continue
		}
		if err != nil {
			return 0, err
		}
		rp.Hits += a.hits
		rp.TotalUS += a.totalUS
		if a.maxUS > rp.MaxUS {
			rp.MaxUS = a.maxUS
		}
		rp.UpdatedAt = now
		if err := s.db.Save(&rp).Error; err != nil {
			return 0, err
		}
	}
	return len(raws), nil
}

// RulePerfRow 聚合查询行：画像数据 + 规则元信息联查
type RulePerfRow struct {
	RuleID    string    `json:"rule_id"`
	Name      string    `json:"name"`
	Group     string    `json:"group"`
	Message   string    `json:"message"`
	Enabled   bool      `json:"enabled"`
	Hits      int64     `json:"hits"`
	AvgUS     float64   `json:"avg_us"`
	MaxUS     int64     `json:"max_us"`
	TotalUS   int64     `json:"total_us"`
	UpdatedAt time.Time `json:"updated_at"`
}

// List 按累计耗时降序返回规则耗时画像（联查规则名称/分组/启停）
func (s *RulePerfService) List(limit int) ([]RulePerfRow, error) {
	if limit < 1 || limit > 500 {
		limit = 100
	}
	var perfs []model.RulePerf
	if err := s.db.Order("total_us desc").Limit(limit).Find(&perfs).Error; err != nil {
		return nil, err
	}

	// 批量取规则元信息（rule_id 可能已随规则删除/重种消失，缺失时留空）
	ids := make([]string, 0, len(perfs))
	for _, p := range perfs {
		ids = append(ids, p.RuleID)
	}
	meta := map[string]*model.Rule{}
	if len(ids) > 0 {
		var rules []model.Rule
		if err := s.db.Where("rule_id IN ?", ids).Find(&rules).Error; err == nil {
			for i := range rules {
				if _, ok := meta[rules[i].RuleID]; !ok {
					meta[rules[i].RuleID] = &rules[i]
				}
			}
		}
	}

	rows := make([]RulePerfRow, 0, len(perfs))
	for _, p := range perfs {
		row := RulePerfRow{
			RuleID:    p.RuleID,
			Hits:      p.Hits,
			AvgUS:     0,
			MaxUS:     p.MaxUS,
			TotalUS:   p.TotalUS,
			UpdatedAt: p.UpdatedAt,
		}
		if p.Hits > 0 {
			row.AvgUS = float64(p.TotalUS) / float64(p.Hits)
		}
		if r := meta[p.RuleID]; r != nil {
			row.Name = r.Name
			row.Group = r.Group
			row.Message = r.Message
			row.Enabled = r.Enabled
		}
		rows = append(rows, row)
	}
	return rows, nil
}

// Reset 清空画像统计（重新累积）
func (s *RulePerfService) Reset() error {
	return s.db.Where("1 = 1").Delete(&model.RulePerf{}).Error
}
