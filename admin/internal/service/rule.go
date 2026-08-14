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
	// 仲裁优先级：用户自定义规则（salience 100）可覆盖内置/CRS 规则（salience 10），
	// 使「放行/豁免规则」能压过内置拦截
	salience := 10
	if !r.IsSeed {
		salience = 100
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
		"salience":   salience,
	}
}

// BuildRuleset 从数据库构建待下发规则集（仅启用的规则，按站点与排序）
// 按 CRS 偏执级别过滤：仅下发 paranoia_level <= 当前配置档位的规则。
// 站点规则（SiteID != 0）写入 site 域名字段，Lua 引擎按请求 Host 过滤子集。
func (s *RuleService) BuildRuleset() (*Ruleset, error) {
	var rules []model.Rule
	if err := s.db.Where("enabled = ?", true).
		Order("site_id asc, sort_order asc, id asc").Find(&rules).Error; err != nil {
		return nil, err
	}
	level := s.currentParanoiaLevel()
	meta := s.siteMeta(rules)
	rs := &Ruleset{
		Version: fmt.Sprintf("v%d", time.Now().UnixNano()),
		Rules:   make([]map[string]interface{}, 0, len(rules)),
	}
	for _, r := range rules {
		if model.RuleParanoiaLevel(r.RuleID) > level {
			continue // 高档位规则，当前档位不参与检测
		}
		if m, ok := meta[r.SiteID]; ok {
			if !m.Enabled {
				continue // 站点已停用：专属规则不下发
			}
			if m.Domain != "" {
				er := s.toEngineRule(r)
				er["site"] = m.Domain
				rs.Rules = append(rs.Rules, er)
				continue
			}
		}
		rs.Rules = append(rs.Rules, s.toEngineRule(r))
	}
	return rs, nil
}

// siteMeta 规则集涉及的站点 ID → {域名, 启用} 映射
func (s *RuleService) siteMeta(rules []model.Rule) map[uint]struct {
	Domain  string
	Enabled bool
} {
	ids := []uint{}
	for _, r := range rules {
		if r.SiteID != 0 {
			ids = append(ids, r.SiteID)
		}
	}
	return NewSiteService(s.db).SiteMeta(ids)
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

// publishScript 原子下发规则集并自增版本号：
//   KEYS[1]=规则集键，KEYS[2]=版本键，ARGV[1]=规则集 JSON
// 先 SET 规则集再 INCR 版本，保证引擎读到新版本时规则集已就绪；
// 返回新版本号（数字，Lua 引擎侧做单调校验）。
const publishScript = `redis.call('SET', KEYS[1], ARGV[1]) return redis.call('INCR', KEYS[2])`

// historyKeep 每类发布历史保留条数
const historyKeep = 10

// Publish 发布规则集到 Redis：原子 SET+INCR 版本，触发 Lua 引擎热更新。
// 发布前保存历史快照（保留最近 10 条，供一键回滚）。
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
	v, err := rdb.Eval(s.ctx, publishScript,
		[]string{s.cfg.Rule.RulesetKey, s.cfg.Rule.VersionKey}, string(body)).Int64()
	if err != nil {
		return nil, err
	}
	rs.Version = fmt.Sprintf("%d", v)
	s.saveHistory("rules", rs.Version, string(body), len(rs.Rules))
	return rs, nil
}

// saveHistory 保存发布历史并裁剪到最近 historyKeep 条（裁剪失败不影响发布）
func (s *RuleService) saveHistory(kind, version, content string, ruleCount int) {
	h := model.PublishHistory{
		Kind: kind, Version: version, Content: content, RuleCount: ruleCount,
	}
	if err := s.db.Create(&h).Error; err != nil {
		return
	}
	var ids []uint
	_ = s.db.Model(&model.PublishHistory{}).Where("kind = ?", kind).
		Order("id desc").Offset(historyKeep).Limit(1000).Pluck("id", &ids).Error
	if len(ids) > 0 {
		_ = s.db.Where("id IN ?", ids).Delete(&model.PublishHistory{}).Error
	}
}

// ListPublishHistory 发布历史列表（新→旧，最近 historyKeep 条；不含完整内容）
func (s *RuleService) ListPublishHistory() ([]model.PublishHistory, error) {
	var list []model.PublishHistory
	err := s.db.Where("kind = ?", "rules").Order("id desc").Limit(historyKeep).Find(&list).Error
	return list, err
}

// Rollback 回滚到指定历史快照：重新下发该版本规则集并自增版本号
// （版本单调递增，引擎按新版本加载旧内容，回滚本身也记录历史）。
func (s *RuleService) Rollback(id uint) error {
	rdb := s.mgr.GetClient()
	if rdb == nil {
		return errors.New("Redis 未配置，请先在引导页完成 Redis 配置")
	}
	var h model.PublishHistory
	if err := s.db.Where("id = ? AND kind = ?", id, "rules").First(&h).Error; err != nil {
		return errors.New("发布记录不存在")
	}
	v, err := rdb.Eval(s.ctx, publishScript,
		[]string{s.cfg.Rule.RulesetKey, s.cfg.Rule.VersionKey}, h.Content).Int64()
	if err != nil {
		return err
	}
	s.saveHistory("rules", fmt.Sprintf("%d", v), h.Content, h.RuleCount)
	return nil
}

// GetByRuleID 按规则 ID 查询单条规则（规则测试用）
func (s *RuleService) GetByRuleID(ruleID string) (*model.Rule, error) {
	var r model.Rule
	if err := s.db.Where("rule_id = ?", ruleID).First(&r).Error; err != nil {
		return nil, err
	}
	return &r, nil
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
