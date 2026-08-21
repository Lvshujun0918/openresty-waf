package service

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"gorm.io/gorm"

	"openresty-waf/admin/internal/config"
	"openresty-waf/admin/internal/model"
)

// RuleSubService 远程规则订阅源：定时拉取 URL 中的规则集（JSON 数组，
// 与 GET /api/rules/export 导出格式一致），重建为本订阅产生的规则
// （rules.source=subscription 且 sub_id=订阅ID）。
type RuleSubService struct {
	db      *gorm.DB
	mgr     *RedisManager
	cfg     *config.Config
	ruleSvc *RuleService
}

func NewRuleSubService(db *gorm.DB, mgr *RedisManager, cfg *config.Config) *RuleSubService {
	return &RuleSubService{
		db: db, mgr: mgr, cfg: cfg,
		ruleSvc: NewRuleService(db, mgr, cfg),
	}
}

func (s *RuleSubService) List() ([]model.RuleSubscription, error) {
	var subs []model.RuleSubscription
	if err := s.db.Order("id asc").Find(&subs).Error; err != nil {
		return nil, err
	}
	return subs, nil
}

func (s *RuleSubService) Create(sub *model.RuleSubscription) error {
	if err := validateRuleSub(sub); err != nil {
		return err
	}
	return s.db.Create(sub).Error
}

func (s *RuleSubService) Update(id uint, sub *model.RuleSubscription) error {
	var existing model.RuleSubscription
	if err := s.db.First(&existing, id).Error; err != nil {
		return errors.New("订阅不存在")
	}
	if err := validateRuleSub(sub); err != nil {
		return err
	}
	return s.db.Model(&existing).Updates(map[string]interface{}{
		"name":         sub.Name,
		"url":          sub.URL,
		"auto_publish": sub.AutoPublish,
		"interval_min": sub.IntervalMin,
		"enabled":      sub.Enabled,
	}).Error
}

func (s *RuleSubService) Delete(id uint) error {
	var sub model.RuleSubscription
	if err := s.db.First(&sub, id).Error; err != nil {
		return errors.New("订阅不存在")
	}
	if err := s.db.Delete(&model.RuleSubscription{}, id).Error; err != nil {
		return err
	}
	// 清理该订阅同步产生的规则并重新发布（引擎不再加载这些规则）
	s.db.Where("source = ? AND sub_id = ?", "subscription", sub.ID).Delete(&model.Rule{})
	_, _ = s.ruleSvc.Publish()
	return nil
}

func (s *RuleSubService) SetEnabled(id uint, enabled bool) error {
	return s.db.Model(&model.RuleSubscription{}).Where("id = ?", id).Update("enabled", enabled).Error
}

func validateRuleSub(sub *model.RuleSubscription) error {
	if strings.TrimSpace(sub.Name) == "" {
		return errors.New("名称不能为空")
	}
	if !strings.HasPrefix(sub.URL, "http://") && !strings.HasPrefix(sub.URL, "https://") {
		return errors.New("URL 必须以 http:// 或 https:// 开头")
	}
	if sub.IntervalMin < 1 {
		sub.IntervalMin = 1440
	}
	return nil
}

// Sync 立即同步单个订阅，返回本次入库的规则数
func (s *RuleSubService) Sync(id uint) (int, error) {
	var sub model.RuleSubscription
	if err := s.db.First(&sub, id).Error; err != nil {
		return 0, err
	}
	return s.syncSub(&sub)
}

func (s *RuleSubService) syncSub(sub *model.RuleSubscription) (int, error) {
	raw, err := s.fetchRaw(sub.URL)
	if err != nil {
		s.markSync(sub.ID, "失败: "+err.Error(), 0)
		return 0, err
	}
	count, syncErr := s.applyRules(sub, raw)
	if syncErr != nil {
		s.markSync(sub.ID, "同步失败: "+syncErr.Error(), 0)
		return 0, syncErr
	}
	status := "ok"
	if !sub.AutoPublish {
		status = "ok（已入库，待手动发布）"
	}
	s.markSync(sub.ID, status, count)
	return count, nil
}

// looseRule 宽松解析中间结构：Transforms/Vars/Actions 兼容
// 转义字符串（ExportRules 导出格式）与自然 JSON 对象/数组两种写法。
type looseRule struct {
	RuleID     string          `json:"rule_id"`
	Name       string          `json:"name"`
	Group      string          `json:"group"`
	Phase      string          `json:"phase"`
	Severity   int             `json:"severity"`
	Enabled    *bool           `json:"enabled"`
	Operator   string          `json:"operator"`
	Pattern    string          `json:"pattern"`
	Transforms json.RawMessage `json:"transforms"`
	Vars       json.RawMessage `json:"vars"`
	Actions    json.RawMessage `json:"actions"`
	Status     int             `json:"status"`
	Message    string          `json:"message"`
	SortOrder  int             `json:"sort_order"`
}

// rawToString 将 RawMessage 归一化为存储用字符串：
// JSON 字符串直接取值；对象/数组压缩后原样保留。
func rawToString(raw json.RawMessage) (string, bool) {
	s := strings.TrimSpace(string(raw))
	if s == "" {
		return "", false
	}
	if strings.HasPrefix(s, "\"") {
		var out string
		if err := json.Unmarshal(raw, &out); err != nil {
			return "", false
		}
		return out, true
	}
	return s, true
}

// parseRemoteRules 解析远程规则集为 model.Rule 切片
func parseRemoteRules(body string) ([]model.Rule, error) {
	var loose []looseRule
	if err := json.Unmarshal([]byte(body), &loose); err != nil {
		return nil, errors.New("规则 JSON 解析失败: " + err.Error())
	}
	out := make([]model.Rule, 0, len(loose))
	for _, l := range loose {
		r := model.Rule{
			RuleID: l.RuleID, Name: l.Name, Group: l.Group,
			Phase: l.Phase, Severity: l.Severity,
			Enabled: l.Enabled == nil || *l.Enabled,
			Operator: l.Operator, Pattern: l.Pattern,
			Status: l.Status, Message: l.Message, SortOrder: l.SortOrder,
		}
		if v, ok := rawToString(l.Transforms); ok {
			r.Transforms = v
		}
		if v, ok := rawToString(l.Vars); ok {
			r.Vars = v
		}
		if v, ok := rawToString(l.Actions); ok {
			r.Actions = v
		}
		out = append(out, r)
	}
	return out, nil
}

// applyRules 解析远程规则集并重建本订阅产生的规则。
// 每条经静态校验，全部无效时报错不落库（避免清空旧规则后无新规则可用）。
func (s *RuleSubService) applyRules(sub *model.RuleSubscription, raw string) (int, error) {
	body := strings.TrimSpace(raw)
	if !strings.HasPrefix(body, "[") {
		return 0, errors.New("订阅内容必须是规则 JSON 数组（与 /api/rules/export 导出格式一致）")
	}
	parsed, err := parseRemoteRules(body)
	if err != nil {
		return 0, err
	}
	now := time.Now()
	valid := make([]model.Rule, 0, len(parsed))
	for _, r := range parsed {
		r.ID = 0
		r.IsSeed = false
		r.Source = "subscription"
		r.SubID = sub.ID
		r.CreatedAt = now
		r.UpdatedAt = now
		if r.RuleID == "" {
			continue
		}
		if err := s.ruleSvc.validateRule(&r); err != nil {
			continue // 单条无效跳过，不阻断整批
		}
		valid = append(valid, r)
	}
	if len(valid) == 0 {
		return 0, errors.New("未解析到有效规则")
	}
	// 重建：先删本订阅旧规则再写入，保证远端删除的规则本地同步移除
	if err := s.db.Where("source = ? AND sub_id = ?", "subscription", sub.ID).
		Delete(&model.Rule{}).Error; err != nil {
		return 0, err
	}
	for i := range valid {
		if err := s.db.Create(&valid[i]).Error; err != nil {
			return len(valid), err
		}
	}
	if sub.AutoPublish {
		if _, err := s.ruleSvc.Publish(); err != nil {
			return len(valid), fmt.Errorf("同步成功但自动发布失败: %w", err)
		}
	}
	return len(valid), nil
}

func (s *RuleSubService) markSync(id uint, status string, count int) {
	_ = s.db.Model(&model.RuleSubscription{}).Where("id = ?", id).Updates(map[string]interface{}{
		"last_status":  status,
		"last_sync_at": time.Now(),
		"last_count":   count,
	}).Error
}

// fetchRaw 拉取订阅源原始内容（上限 5MB）
func (s *RuleSubService) fetchRaw(rawURL string) (string, error) {
	client := &http.Client{Timeout: 20 * time.Second}
	resp, err := client.Get(rawURL)
	if err != nil {
		return "", errors.New("拉取失败: " + err.Error())
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 5<<20))
	if err != nil {
		return "", errors.New("读取响应失败: " + err.Error())
	}
	return string(body), nil
}

// SyncAll 同步所有已启用且到期的订阅（后台定时任务调用）
func (s *RuleSubService) SyncAll() {
	subs, err := s.List()
	if err != nil {
		return
	}
	for i := range subs {
		sub := subs[i]
		if !sub.Enabled {
			continue
		}
		if sub.LastSyncAt != nil &&
			time.Since(*sub.LastSyncAt) < time.Duration(sub.IntervalMin)*time.Minute {
			continue // 未到同步周期
		}
		_, _ = s.syncSub(&sub)
	}
}
