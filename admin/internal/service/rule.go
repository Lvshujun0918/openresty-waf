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

// Ruleset 下发给 Lua 引擎的规则集结构（与 waf/rule_engine 的 DSL 约定一致）
type Ruleset struct {
	Version string                   `json:"version"`
	Rules   []map[string]interface{} `json:"rules"`
}

type RuleService struct {
	db  *gorm.DB
	mgr *RedisManager
	cfg *config.Config
	ctx context.Context
}

func NewRuleService(db *gorm.DB, mgr *RedisManager, cfg *config.Config) *RuleService {
	return &RuleService{db: db, mgr: mgr, cfg: cfg, ctx: context.Background()}
}

// toEngineRule 将 DB 规则转换为 Lua 引擎 DSL 对象
func (s *RuleService) toEngineRule(r model.Rule) map[string]interface{} {
	var vars, transforms []interface{}
	var actions map[string]interface{}
	_ = json.Unmarshal([]byte(r.Vars), &vars)
	_ = json.Unmarshal([]byte(r.Transforms), &transforms)
	_ = json.Unmarshal([]byte(r.Actions), &actions)
	if actions == nil {
		actions = map[string]interface{}{
			"disrupt": "BLOCK",
			"status":  r.Status,
			"msg":     r.Message,
		}
	}
	return map[string]interface{}{
		"id":         r.RuleID,
		"group":      r.Group,
		"phase":      r.Phase,
		"severity":   r.Severity,
		"enabled":    r.Enabled,
		"vars":       vars,
		"operator":   r.Operator,
		"pattern":    r.Pattern,
		"transforms": transforms,
		"actions":    actions,
	}
}

// BuildRuleset 从数据库构建待下发规则集（仅启用的规则，按站点与排序）
// 按 CRS 偏执级别过滤：仅下发 paranoia_level <= 当前配置档位的规则
func (s *RuleService) BuildRuleset() (*Ruleset, error) {
	var rules []model.Rule
	if err := s.db.Where("enabled = ?", true).
		Order("site_id asc, sort_order asc, id asc").Find(&rules).Error; err != nil {
		return nil, err
	}
	level := s.currentParanoiaLevel()
	rs := &Ruleset{
		Version: fmt.Sprintf("v%d", time.Now().UnixNano()),
		Rules:   make([]map[string]interface{}, 0, len(rules)),
	}
	for _, r := range rules {
		if model.RuleParanoiaLevel(r.RuleID) > level {
			continue // 高档位规则，当前档位不参与检测
		}
		rs.Rules = append(rs.Rules, s.toEngineRule(r))
	}
	return rs, nil
}

// currentParanoiaLevel 读取后台运行配置中的 CRS 偏执级别（1-4，缺省 1）
func (s *RuleService) currentParanoiaLevel() int {
	var row struct{ Value string }
	if err := s.db.Model(&model.Setup{}).Select("value").
		Where("key = ?", SetupKeyWafConfig).Scan(&row).Error; err != nil || row.Value == "" {
		return 1
	}
	var cfg map[string]interface{}
	if err := json.Unmarshal([]byte(row.Value), &cfg); err != nil {
		return 1
	}
	if det, ok := cfg["detection"].(map[string]interface{}); ok {
		if v, ok := det["paranoia_level"].(float64); ok && v >= 1 && v <= 4 {
			return int(v)
		}
	}
	return 1
}

// Publish 发布规则集到 Redis，并自增版本号触发 Lua 引擎热更新。
// 与 waf/config.lua 的 rule_refresh 键约定保持一致。
func (s *RuleService) Publish() (*Ruleset, error) {
	rdb := s.mgr.GetClient()
	if rdb == nil {
		return nil, errors.New("Redis 未配置，请先在引导页完成 Redis 配置")
	}
	rs, err := s.BuildRuleset()
	if err != nil {
		return nil, err
	}
	body, err := json.Marshal(rs)
	if err != nil {
		return nil, err
	}
	pipe := rdb.TxPipeline()
	pipe.Set(s.ctx, s.cfg.Rule.RulesetKey, string(body), 0)
	pipe.Incr(s.ctx, s.cfg.Rule.VersionKey)
	if _, err := pipe.Exec(s.ctx); err != nil {
		return nil, err
	}
	return rs, nil
}

// List 规则列表（支持 group / site_id / keyword 过滤）
func (s *RuleService) List(group, siteID, keyword string) ([]model.Rule, error) {
	q := s.db
	if group != "" {
		q = q.Where("`group` = ?", group)
	}
	if siteID != "" {
		q = q.Where("site_id = ?", siteID)
	}
	if keyword != "" {
		like := "%" + keyword + "%"
		q = q.Where("rule_id LIKE ? OR name LIKE ? OR pattern LIKE ?", like, like, like)
	}
	var rules []model.Rule
	if err := q.Order("site_id asc, sort_order asc, id asc").Find(&rules).Error; err != nil {
		return nil, err
	}
	return rules, nil
}

func (s *RuleService) Create(r *model.Rule) error {
	if r.RuleID == "" || r.Operator == "" || r.Pattern == "" {
		return errors.New("rule_id / operator / pattern 不能为空")
	}
	return s.db.Create(r).Error
}

func (s *RuleService) Update(id uint, r *model.Rule) error {
	var existing model.Rule
	if err := s.db.First(&existing, id).Error; err != nil {
		return errors.New("规则不存在")
	}
	return s.db.Model(&existing).Updates(r).Error
}

func (s *RuleService) Delete(id uint) error {
	return s.db.Delete(&model.Rule{}, id).Error
}

func (s *RuleService) SetEnabled(id uint, enabled bool) error {
	res := s.db.Model(&model.Rule{}).Where("id = ?", id).Update("enabled", enabled)
	if res.RowsAffected == 0 {
		return errors.New("规则不存在")
	}
	return res.Error
}
