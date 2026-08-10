package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"gorm.io/gorm"

	"openresty-waf/admin/internal/config"
	"openresty-waf/admin/internal/model"
)

// CcRuleset 下发到 Lua 引擎的 CC 规则集结构
type CcRuleset struct {
	Version string           `json:"version"`
	Rules   []model.CcRule   `json:"rules"`
}

// CcRuleService CC 防刷规则：按 host + path 精细化配置频率阈值与封禁时长。
// 下发机制与规则集一致：写入 Redis + 版本自增，Lua 引擎轮询热更新。
type CcRuleService struct {
	db  *gorm.DB
	mgr *RedisManager
	cfg *config.Config
	ctx context.Context
}

func NewCcRuleService(db *gorm.DB, mgr *RedisManager, cfg *config.Config) *CcRuleService {
	return &CcRuleService{db: db, mgr: mgr, cfg: cfg, ctx: context.Background()}
}

// List 全部 CC 规则（按排序）
func (s *CcRuleService) List() ([]model.CcRule, error) {
	var rules []model.CcRule
	if err := s.db.Order("sort_order asc, id asc").Find(&rules).Error; err != nil {
		return nil, err
	}
	return rules, nil
}

func (s *CcRuleService) Create(r *model.CcRule) error {
	if r.Rate == "" {
		return errors.New("频率不能为空（格式 count/seconds，如 100/60）")
	}
	if r.BanDuration <= 0 {
		r.BanDuration = 300
	}
	return s.db.Create(r).Error
}

func (s *CcRuleService) Update(id uint, r *model.CcRule) error {
	var existing model.CcRule
	if err := s.db.First(&existing, id).Error; err != nil {
		return errors.New("规则不存在")
	}
	return s.db.Model(&existing).Updates(r).Error
}

func (s *CcRuleService) Delete(id uint) error {
	return s.db.Delete(&model.CcRule{}, id).Error
}

func (s *CcRuleService) SetEnabled(id uint, enabled bool) error {
	return s.db.Model(&model.CcRule{}).Where("id = ?", id).Update("enabled", enabled).Error
}

// Publish 发布启用的 CC 规则集到 Redis，自增版本号触发 Lua 引擎热更新
func (s *CcRuleService) Publish() (*CcRuleset, error) {
	rdb := s.mgr.GetClient()
	if rdb == nil {
		return nil, errors.New("Redis 未配置，请先在引导页完成 Redis 配置")
	}
	var rules []model.CcRule
	if err := s.db.Where("enabled = ?", true).
		Order("sort_order asc, id asc").Find(&rules).Error; err != nil {
		return nil, err
	}
	rs := &CcRuleset{
		Version: fmt.Sprintf("v%d", time.Now().UnixNano()),
		Rules:   rules,
	}
	body, err := json.Marshal(rs)
	if err != nil {
		return nil, err
	}
	pipe := rdb.TxPipeline()
	pipe.Set(s.ctx, s.cfg.Rule.CcRulesKey, string(body), 0)
	pipe.Incr(s.ctx, s.cfg.Rule.CcVersionKey)
	if _, err := pipe.Exec(s.ctx); err != nil {
		return nil, err
	}
	return rs, nil
}
