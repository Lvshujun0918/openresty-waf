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

// TriggerRuleset 发布到 Redis 的触发规则集（引擎轮询热更新）
type TriggerRuleset struct {
	Version string                `json:"version"`
	Rules   []model.TriggerRule   `json:"rules"`
}

// TriggerRuleService 触发规则：按条件（host/UA/请求头/IP 等 + AND/OR 组合）筛选请求，
// 命中后执行对应动作（人机验证/豁免/CC）。下发机制与规则集一致：写 Redis + 版本自增。
type TriggerRuleService struct {
	db  *gorm.DB
	mgr *RedisManager
	cfg *config.Config
	ctx context.Context
}

func NewTriggerRuleService(db *gorm.DB, mgr *RedisManager, cfg *config.Config) *TriggerRuleService {
	return &TriggerRuleService{db: db, mgr: mgr, cfg: cfg, ctx: context.Background()}
}

// List 查询全部触发规则（按用途/关键字过滤）
func (s *TriggerRuleService) List(kind, keyword string) ([]model.TriggerRule, error) {
	q := s.db.Model(&model.TriggerRule{})
	if kind != "" {
		q = q.Where("kind = ?", kind)
	}
	if keyword != "" {
		q = q.Where("name LIKE ?", "%"+keyword+"%")
	}
	var rules []model.TriggerRule
	if err := q.Order("sort_order asc, id asc").Find(&rules).Error; err != nil {
		return nil, err
	}
	return rules, nil
}

// validateTriggerConditions 校验触发规则条件 JSON：
// regex 运算符的 pattern 拒绝明显灾难性回溯（与规则引擎 ReDoS 护栏一致）
func validateTriggerConditions(conds string) error {
	if conds == "" {
		return nil
	}
	var list []model.TriggerCondition
	if err := json.Unmarshal([]byte(conds), &list); err != nil {
		return nil // JSON 格式错误交给入库层处理，这里只做正则安全检查
	}
	for _, c := range list {
		if c.Operator == "regex" && hasCatastrophicBacktracking(c.Value) {
			return fmt.Errorf("字段 %q 的正则疑似灾难性回溯（组内量词与组后量词嵌套，如 (a+)+），请简化", c.Field)
		}
	}
	return nil
}

// Create 新建触发规则
func (s *TriggerRuleService) Create(r *model.TriggerRule) error {
	if err := validateTriggerConditions(r.Conditions); err != nil {
		return err
	}
	return s.db.Create(r).Error
}

// Update 更新触发规则
func (s *TriggerRuleService) Update(id uint, r *model.TriggerRule) error {
	if err := validateTriggerConditions(r.Conditions); err != nil {
		return err
	}
	return s.db.Model(&model.TriggerRule{}).Where("id = ?", id).Updates(map[string]interface{}{
		"name": r.Name, "kind": r.Kind, "match_logic": r.MatchLogic,
		"enabled": r.Enabled, "sort_order": r.SortOrder, "conditions": r.Conditions,
		"config": r.Config, "updated_at": time.Now(),
	}).Error
}

// Delete 删除触发规则
func (s *TriggerRuleService) Delete(id uint) error {
	return s.db.Delete(&model.TriggerRule{}, id).Error
}

// SetEnabled 启用/禁用
func (s *TriggerRuleService) SetEnabled(id uint, enabled bool) error {
	return s.db.Model(&model.TriggerRule{}).Where("id = ?", id).
		Updates(map[string]interface{}{"enabled": enabled, "updated_at": time.Now()}).Error
}

// Publish 发布启用的触发规则到 Redis，触发引擎热更新
func (s *TriggerRuleService) Publish() (*TriggerRuleset, error) {
	rdb := s.mgr.GetClient()
	if rdb == nil {
		return nil, errors.New("Redis 未配置，请先完成 Redis 配置")
	}
	var rules []model.TriggerRule
	if err := s.db.Where("enabled = ?", true).
		Order("sort_order asc, id asc").Find(&rules).Error; err != nil {
		return nil, err
	}
	// 条件序列化：把每条规则的 Conditions JSON 字符串解析为数组，供引擎直接使用
	type outRule struct {
		ID         uint                     `json:"id"`
		Name       string                   `json:"name"`
		Kind       string                   `json:"kind"`
		MatchLogic string                   `json:"match_logic"`
		Enabled    bool                     `json:"enabled"`
		Conditions []model.TriggerCondition `json:"conditions"`
		Config     map[string]interface{}   `json:"config"`
	}
	out := make([]outRule, 0, len(rules))
	for _, r := range rules {
		var conds []model.TriggerCondition
		if r.Conditions != "" {
			_ = json.Unmarshal([]byte(r.Conditions), &conds)
		}
		var cfg map[string]interface{}
		if r.Config != "" {
			_ = json.Unmarshal([]byte(r.Config), &cfg)
		}
		out = append(out, outRule{
			ID: r.ID, Name: r.Name, Kind: r.Kind, MatchLogic: r.MatchLogic,
			Enabled: r.Enabled, Conditions: conds, Config: cfg,
		})
	}
	rs := &TriggerRuleset{Version: fmt.Sprintf("v%d", time.Now().UnixNano()), Rules: nil}
	body, err := json.Marshal(map[string]interface{}{"version": rs.Version, "rules": out})
	if err != nil {
		return nil, err
	}
	pipe := rdb.TxPipeline()
	pipe.Set(s.ctx, s.cfg.Rule.TriggerRulesKey, string(body), 0)
	pipe.Incr(s.ctx, s.cfg.Rule.TriggerVersionKey)
	if _, err := pipe.Exec(s.ctx); err != nil {
		return nil, err
	}
	return rs, nil
}
