package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"time"

	"gorm.io/gorm"

	"github.com/redis/go-redis/v9"

	"openresty-waf/admin/internal/config"
	"openresty-waf/admin/internal/model"
	"openresty-waf/admin/internal/ruletest"
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

// BuildRuleset 从数据库构建待下发规则集（仅启用的规则，按排序）
// 按 CRS 偏执级别过滤：仅下发 paranoia_level <= 当前配置档位的规则。
func (s *RuleService) BuildRuleset() (*Ruleset, error) {
	var rules []model.Rule
	if err := s.db.Where("enabled = ?", true).
		Order("sort_order asc, id asc").Find(&rules).Error; err != nil {
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

// publishScript 原子下发规则集并自增版本号：
//
//	KEYS[1]=规则集键，KEYS[2]=版本键，ARGV[1]=规则集 JSON
//
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

// canaryPublishScript 原子下发灰度规则集+配置并自增灰度版本号：
//
//	KEYS[1]=灰度规则集键，KEYS[2]=灰度配置键，KEYS[3]=灰度版本键
//	ARGV[1]=规则集 JSON，ARGV[2]=配置 JSON（percent/ips）
const canaryPublishScript = `
redis.call('SET', KEYS[1], ARGV[1])
redis.call('SET', KEYS[2], ARGV[2])
return redis.call('INCR', KEYS[3])`

// CanaryCfg 灰度发布配置：percent 为按 IP 哈希分桶的灰度百分比（0-100），
// ips 为强制进入灰度的 IP 名单（优先于百分比判定）。
type CanaryCfg struct {
	Percent int      `json:"percent"`
	IPs     []string `json:"ips"`
}

// PublishCanary 发布灰度规则集：与稳定集内容相同（当前启用规则快照），
// 但写入独立键并由引擎按 percent/IP 名单选择性加载。
func (s *RuleService) PublishCanary(percent int, ips []string) (*Ruleset, error) {
	if percent < 0 || percent > 100 {
		return nil, errors.New("灰度比例必须在 0-100 之间")
	}
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
	cfgBody, err := json.Marshal(CanaryCfg{Percent: percent, IPs: ips})
	if err != nil {
		return nil, err
	}
	v, err := rdb.Eval(s.ctx, canaryPublishScript,
		[]string{s.cfg.Rule.CanaryRulesetKey, s.cfg.Rule.CanaryCfgKey, s.cfg.Rule.CanaryVersionKey},
		string(body), string(cfgBody)).Int64()
	if err != nil {
		return nil, err
	}
	rs.Version = fmt.Sprintf("%d", v)
	s.saveHistory("canary", rs.Version, string(body), len(rs.Rules))
	return rs, nil
}

// PromoteCanary 全量发布：将最新灰度历史内容发到稳定键，并清除全部灰度键。
func (s *RuleService) PromoteCanary() error {
	rdb := s.mgr.GetClient()
	if rdb == nil {
		return errors.New("Redis 未配置，请先在引导页完成 Redis 配置")
	}
	var h model.PublishHistory
	if err := s.db.Where("kind = ?", "canary").Order("id desc").First(&h).Error; err != nil {
		return errors.New("没有可晋升的灰度发布记录")
	}
	v, err := rdb.Eval(s.ctx, publishScript,
		[]string{s.cfg.Rule.RulesetKey, s.cfg.Rule.VersionKey}, h.Content).Int64()
	if err != nil {
		return err
	}
	if err := s.clearCanaryKeys(rdb); err != nil {
		return err
	}
	s.saveHistory("rules", fmt.Sprintf("%d", v), h.Content, h.RuleCount)
	return nil
}

// AbortCanary 终止灰度：清除灰度键，全部流量回退稳定规则集。
func (s *RuleService) AbortCanary() error {
	rdb := s.mgr.GetClient()
	if rdb == nil {
		return errors.New("Redis 未配置，请先在引导页完成 Redis 配置")
	}
	return s.clearCanaryKeys(rdb)
}

// clearCanaryKeys 删除灰度三键（引擎轮询发现版本键消失即自动清理本地灰度态）
func (s *RuleService) clearCanaryKeys(rdb redis.UniversalClient) error {
	return rdb.Del(s.ctx,
		s.cfg.Rule.CanaryRulesetKey, s.cfg.Rule.CanaryCfgKey, s.cfg.Rule.CanaryVersionKey).Err()
}

// CanaryStatus 查询灰度状态（active=灰度版本键存在）
func (s *RuleService) CanaryStatus() (map[string]interface{}, error) {
	res := map[string]interface{}{"active": false}
	rdb := s.mgr.GetClient()
	if rdb == nil {
		return res, nil
	}
	v, err := rdb.Get(s.ctx, s.cfg.Rule.CanaryVersionKey).Result()
	if err != nil {
		return res, nil // 键不存在或 Redis 异常均视为未开启灰度
	}
	res["active"] = true
	res["version"] = v
	if cfgBody, err := rdb.Get(s.ctx, s.cfg.Rule.CanaryCfgKey).Bytes(); err == nil {
		var cfg CanaryCfg
		if json.Unmarshal(cfgBody, &cfg) == nil {
			res["percent"] = cfg.Percent
			res["ips"] = cfg.IPs
		}
	}
	return res, nil
}

// GetByRuleID 按规则 ID 查询单条规则（规则测试用）
func (s *RuleService) GetByRuleID(ruleID string) (*model.Rule, error) {
	var r model.Rule
	if err := s.db.Where("rule_id = ?", ruleID).First(&r).Error; err != nil {
		return nil, err
	}
	return &r, nil
}

// ExportRules 导出全部规则（清除内部 ID/时间戳/种子标记，可直接导入其他实例）
func (s *RuleService) ExportRules() ([]model.Rule, error) {
	var rules []model.Rule
	if err := s.db.Order("sort_order asc, id asc").Find(&rules).Error; err != nil {
		return nil, err
	}
	for i := range rules {
		rules[i].ID = 0
		rules[i].IsSeed = false
		rules[i].Source = "local"
		rules[i].SubID = 0
		rules[i].CreatedAt = time.Time{}
		rules[i].UpdatedAt = time.Time{}
	}
	return rules, nil
}

// ImportRules 导入规则：逐条静态校验，rule_id 已存在的跳过；
// 返回导入成功与跳过条数。
func (s *RuleService) ImportRules(rules []model.Rule) (imported, skipped int, err error) {
	for _, r := range rules {
		r.ID = 0
		r.IsSeed = false
		r.Source = "local"
		r.SubID = 0
		r.CreatedAt = time.Time{}
		r.UpdatedAt = time.Time{}
		if r.RuleID == "" {
			r.RuleID = fmt.Sprintf("c%d", time.Now().UnixNano())
		}
		if err := s.validateRule(&r); err != nil {
			skipped++
			continue
		}
		var count int64
		_ = s.db.Model(&model.Rule{}).Where("rule_id = ?", r.RuleID).Count(&count).Error
		if count > 0 {
			skipped++ // 已存在：跳过避免覆盖
			continue
		}
		if err := s.db.Create(&r).Error; err != nil {
			skipped++
			continue
		}
		imported++
	}
	return imported, skipped, nil
}

// List 规则列表（支持 group / keyword 过滤）
func (s *RuleService) List(group, keyword string) ([]model.Rule, error) {
	q := s.db
	if group != "" {
		q = q.Where("`group` = ?", group)
	}
	if keyword != "" {
		like := "%" + keyword + "%"
		q = q.Where("rule_id LIKE ? OR name LIKE ? OR pattern LIKE ?", like, like, like)
	}
	var rules []model.Rule
	if err := q.Order("sort_order asc, id asc").Find(&rules).Error; err != nil {
		return nil, err
	}
	return rules, nil
}

// validOperators 引擎支持的运算符白名单（与 waf/rule_engine/operators.lua 保持一致）
var validOperators = map[string]bool{
	"REGEX": true, "PM": true, "EQUALS": true, "CONTAINS": true, "CIDR": true,
	"STARTS_WITH": true, "ENDS_WITH": true, "EXISTS": true,
	"LIBINJECTION_SQLI": true, "LIBINJECTION_XSS": true,
	"SEMANTIC_ANOMALY": true,
}

// maxPatternLen 规则 pattern 长度上限（字节）：容纳长 CRS 正则（可达 10KB+），
// 同时防止异常巨型 pattern 拖慢引擎编译与执行。
const maxPatternLen = 32768

// catastrophicRe 明显灾难性回溯特征：组内以量词结尾且组后紧跟量词，
// 如 (a+)+ / (a*)* / (ab*)+ / (a{2,3})*。这类模式在 PCRE 下对恶意输入
// 可能指数级回溯，烧满 worker CPU（引擎侧无 match_limit 兜底）。
// 仅做启发式拦截（Go regexp 扫描），不保证覆盖全部 ReDoS 变体，
// 不含嵌套量词的常规正则（如 (foo|bar)+、[\s'\"]*union...）不受影响。
var catastrophicRe = regexp.MustCompile(`\([^()]*[*+?{][^()]*\)\s*[*+?{]`)

func hasCatastrophicBacktracking(pattern string) bool {
	return catastrophicRe.MatchString(pattern)
}

// validateRule 规则静态校验：运算符白名单 + pattern 长度护栏 + ReDoS 启发式
func (s *RuleService) validateRule(r *model.Rule) error {
	if r.RuleID == "" || r.Operator == "" || r.Pattern == "" {
		return errors.New("rule_id / operator / pattern 不能为空")
	}
	if !validOperators[r.Operator] {
		return errors.New("不支持的运算符: " + r.Operator)
	}
	if len(r.Pattern) > maxPatternLen {
		return errors.New("pattern 过长（上限 32KB），请拆分规则或精简正则")
	}
	if r.Operator == "REGEX" && hasCatastrophicBacktracking(r.Pattern) {
		return errors.New("pattern 疑似灾难性回溯（组内量词与组后量词嵌套，如 (a+)+），请简化正则")
	}
	return nil
}

func (s *RuleService) Create(r *model.Rule) error {
	if err := s.validateRule(r); err != nil {
		return err
	}
	return s.db.Create(r).Error
}

func (s *RuleService) Update(id uint, r *model.Rule) error {
	var existing model.Rule
	if err := s.db.First(&existing, id).Error; err != nil {
		return errors.New("规则不存在")
	}
	// 部分更新：仅校验本次提供的字段（空字段保持原值不参与校验）
	if r.Operator != "" && !validOperators[r.Operator] {
		return errors.New("不支持的运算符: " + r.Operator)
	}
	if len(r.Pattern) > maxPatternLen {
		return errors.New("pattern 过长（上限 32KB），请拆分规则或精简正则")
	}
	if r.Pattern != "" && r.Operator == "REGEX" && hasCatastrophicBacktracking(r.Pattern) {
		return errors.New("pattern 疑似灾难性回溯（组内量词与组后量词嵌套，如 (a+)+），请简化正则")
	}
	return s.db.Model(&existing).Updates(r).Error
}

// ReplayHit 全规则重放命中项
type ReplayHit struct {
	RuleID   string `json:"rule_id"`
	Name     string `json:"name"`
	Group    string `json:"group"`
	Msg      string `json:"msg"`
	Severity int    `json:"severity"`
}

// TestAll 用请求描述跑全部启用规则，返回命中列表（攻击重放）
func (s *RuleService) TestAll(req ruletest.TestRequest) ([]ReplayHit, error) {
	var rules []model.Rule
	if err := s.db.Where("enabled = ?", true).Find(&rules).Error; err != nil {
		return nil, err
	}
	var hits []ReplayHit
	for _, r := range rules {
		res := ruletest.Match(r, req)
		if res.Matched {
			hits = append(hits, ReplayHit{
				RuleID: r.RuleID, Name: r.Name, Group: r.Group,
				Msg: r.Message, Severity: r.Severity,
			})
		}
	}
	return hits, nil
}

func (s *RuleService) Delete(id uint) error {
	return s.db.Delete(&model.Rule{}, id).Error
}

// RuleHitStat 规则命中统计（事件按主命中 rule_id 聚合）
type RuleHitStat struct {
	RuleID string  `json:"rule_id"`
	Hits   int64   `json:"hits"`    // 总命中次数
	Blocks int64   `json:"blocks"`  // 拦截次数（status >= 400）
	FPs    int64   `json:"fps"`     // 人工标记误报次数
	FpRate float64 `json:"fp_rate"` // 误报率（百分比，fps/hits）
}

// HitStats 按事件聚合规则命中排行（Top limit），支持按 group 过滤；
// 支持「误报率」分析以指导规则治理（僵尸规则/高误报规则）
func (s *RuleService) HitStats(group string, limit int) ([]RuleHitStat, error) {
	if limit <= 0 || limit > 100 {
		limit = 20
	}
	q := `SELECT rule_id,
		COUNT(*) AS hits,
		COALESCE(SUM(CASE WHEN status >= 400 THEN 1 ELSE 0 END), 0) AS blocks,
		COALESCE(SUM(CASE WHEN false_positive THEN 1 ELSE 0 END), 0) AS fps
		FROM events`
	var args []interface{}
	if group != "" {
		q += ` WHERE ` + "`group`" + ` = ?`
		args = append(args, group)
	}
	q += ` GROUP BY rule_id ORDER BY hits DESC LIMIT ?`
	args = append(args, limit)
	var out []RuleHitStat
	if err := s.db.Raw(q, args...).Scan(&out).Error; err != nil {
		return nil, err
	}
	// 误报率计算（供高误报规则提醒）
	for i := range out {
		if out[i].Hits > 0 {
			out[i].FpRate = float64(out[i].FPs) / float64(out[i].Hits) * 100
		}
	}
	return out, nil
}

func (s *RuleService) SetEnabled(id uint, enabled bool) error {
	res := s.db.Model(&model.Rule{}).Where("id = ?", id).Update("enabled", enabled)
	if res.RowsAffected == 0 {
		return errors.New("规则不存在")
	}
	return res.Error
}
