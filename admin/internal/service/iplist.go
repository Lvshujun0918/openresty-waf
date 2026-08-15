package service

import (
	"context"
	"errors"
	"fmt"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"time"

	"gorm.io/gorm"

	"openresty-waf/admin/internal/config"
	"openresty-waf/admin/internal/model"
)

// IpListService 远程 IP 列表订阅：定时拉取 URL 中的 IP/CIDR，
// 合并到白/黑名单并下发引擎热更新。
type IpListService struct {
	db     *gorm.DB
	mgr    *RedisManager
	wafCfg *WafConfigService
	cfg    *config.Config
	ctx    context.Context
}

func NewIpListService(db *gorm.DB, mgr *RedisManager, cfg *config.Config) *IpListService {
	return &IpListService{db: db, mgr: mgr, wafCfg: NewWafConfigService(db, mgr, cfg), cfg: cfg, ctx: context.Background()}
}

func (s *IpListService) List() ([]model.IpListSubscription, error) {
	var subs []model.IpListSubscription
	if err := s.db.Order("id asc").Find(&subs).Error; err != nil {
		return nil, err
	}
	return subs, nil
}

func (s *IpListService) Create(sub *model.IpListSubscription) error {
	if err := validateSub(sub); err != nil {
		return err
	}
	return s.db.Create(sub).Error
}

func (s *IpListService) Update(id uint, sub *model.IpListSubscription) error {
	var existing model.IpListSubscription
	if err := s.db.First(&existing, id).Error; err != nil {
		return errors.New("订阅不存在")
	}
	if err := validateSub(sub); err != nil {
		return err
	}
	return s.db.Model(&existing).Updates(sub).Error
}

func (s *IpListService) Delete(id uint) error {
	var sub model.IpListSubscription
	if err := s.db.First(&sub, id).Error; err != nil {
		return errors.New("订阅不存在")
	}
	if err := s.db.Delete(&model.IpListSubscription{}, id).Error; err != nil {
		return err
	}
	// 清理该订阅同步产生的指纹/画像条目并重新下发
	bot := NewBotService(s.db, s.mgr, s.cfg)
	removed := int64(0)
	if sub.Target == "fingerprint" {
		res := s.db.Where("source = ? AND sub_id = ?", "subscription", sub.ID).
			Delete(&model.BotFingerprint{})
		removed = res.RowsAffected
		_ = bot.publishFingerprints()
	} else if sub.Target == "bot_profile" {
		res := s.db.Where("source = ? AND sub_id = ?", "subscription", sub.ID).
			Delete(&model.BotProfile{})
		removed = res.RowsAffected
		_ = bot.publishProfiles()
	} else if sub.Target == "ja4_profile" {
		res := s.db.Where("source = ? AND sub_id = ?", "subscription", sub.ID).
			Delete(&model.Ja4Profile{})
		removed = res.RowsAffected
		_ = NewJa4Service(s.db, s.mgr, s.cfg).PublishMalware()
	}
	_ = s.db.Model(&model.IpListSubscription{}).Where("id = ?", id).
		Update("last_status", fmt.Sprintf("已删除，清理同步条目 %d 条", removed)).Error
	return nil
}

func (s *IpListService) SetEnabled(id uint, enabled bool) error {
	return s.db.Model(&model.IpListSubscription{}).Where("id = ?", id).Update("enabled", enabled).Error
}

func validateSub(sub *model.IpListSubscription) error {
	if sub.Name == "" {
		return errors.New("名称不能为空")
	}
	if !strings.HasPrefix(sub.URL, "http://") && !strings.HasPrefix(sub.URL, "https://") {
		return errors.New("URL 必须以 http:// 或 https:// 开头")
	}
	if sub.Target == "" {
		sub.Target = "ip"
	}
	switch sub.Target {
	case "ip":
		if sub.Type != "whitelist" && sub.Type != "blacklist" {
			return errors.New("IP 订阅的类型必须是 whitelist 或 blacklist")
		}
	case "fingerprint", "bot_profile", "ja4_profile":
		// 指纹/画像/客户端库订阅无名单方向
		sub.Type = ""
	default:
		return errors.New("订阅目标必须是 ip / fingerprint / bot_profile")
	}
	if sub.IntervalMin < 1 {
		sub.IntervalMin = 60
	}
	return nil
}

// Sync 同步单个订阅并返回本次并入的 IP 数量
func (s *IpListService) Sync(id uint) (int, error) {
	var sub model.IpListSubscription
	if err := s.db.First(&sub, id).Error; err != nil {
		return 0, err
	}
	return s.syncSub(&sub)
}

func (s *IpListService) syncSub(sub *model.IpListSubscription) (int, error) {
	raw, err := s.fetchRaw(sub.URL)
	now := time.Now()
	if err != nil {
		_ = s.db.Model(&model.IpListSubscription{}).Where("id = ?", sub.ID).Updates(map[string]interface{}{
			"last_status":  "失败: " + err.Error(),
			"last_sync_at": now,
		}).Error
		return 0, err
	}

	var count int
	var syncErr error
	switch sub.Target {
	case "fingerprint":
		count, syncErr = s.syncFingerprints(sub, raw)
	case "bot_profile":
		count, syncErr = s.syncBotProfiles(sub, raw)
	case "ja4_profile":
		count, syncErr = s.syncJa4Profiles(sub, raw)
	default:
		count, syncErr = s.syncIPEntries(sub, raw)
	}
	if syncErr != nil {
		_ = s.db.Model(&model.IpListSubscription{}).Where("id = ?", sub.ID).Updates(map[string]interface{}{
			"last_status":  "同步失败: " + syncErr.Error(),
			"last_sync_at": now,
		}).Error
		return 0, syncErr
	}
	_ = s.db.Model(&model.IpListSubscription{}).Where("id = ?", sub.ID).Updates(map[string]interface{}{
		"last_status":  "ok",
		"last_sync_at": now,
		"last_count":   count,
	}).Error
	return count, nil
}

// fetchRaw 拉取订阅源原始内容（上限 5MB）
func (s *IpListService) fetchRaw(rawURL string) (string, error) {
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

// syncIPEntries 合并 IP/CIDR 到白/黑名单并下发（原有逻辑）
func (s *IpListService) syncIPEntries(sub *model.IpListSubscription, raw string) (int, error) {
	fetched := s.parseIPLines(raw)
	cfg, err := s.wafCfg.Get()
	if err != nil {
		return 0, err
	}
	// 合并到对应名单（whitelist/blacklist 的 ips 数组），去重
	listMap, _ := cfg[sub.Type].(map[string]interface{})
	if listMap == nil {
		listMap = map[string]interface{}{}
	}
	var existing []string
	if v, ok := listMap["ips"]; ok {
		if arr, ok2 := v.([]interface{}); ok2 {
			for _, x := range arr {
				existing = append(existing, fmt.Sprint(x))
			}
		}
	}
	seen := map[string]bool{}
	var merged []string
	for _, ip := range append(existing, fetched...) {
		ip = strings.TrimSpace(ip)
		if ip == "" || seen[ip] {
			continue
		}
		seen[ip] = true
		merged = append(merged, ip)
	}
	listMap["ips"] = merged
	cfg[sub.Type] = listMap

	if err := s.wafCfg.Save(cfg); err != nil {
		return 0, err
	}
	return len(fetched), nil
}

// syncJa4Profiles 同步 JA4 客户端指纹库：CSV 每行 "名称,ja4[,category]"，重建该订阅条目。
func (s *IpListService) syncJa4Profiles(sub *model.IpListSubscription, raw string) (int, error) {
	ja4svc := NewJa4Service(s.db, s.mgr, s.cfg)
	items, err := parseJa4ProfileCSV(raw)
	if err != nil {
		return 0, err
	}
	if len(items) == 0 {
		return 0, errors.New("未解析到有效 JA4 条目（CSV：名称,ja4[,category]）")
	}
	if err := s.db.Where("source = ? AND sub_id = ?", "subscription", sub.ID).
		Delete(&model.Ja4Profile{}).Error; err != nil {
		return 0, err
	}
	now := time.Now()
	for _, it := range items {
		p := model.Ja4Profile{
			Ja4: it.Ja4, AcPrefix: AcPrefix(it.Ja4), Name: it.Name,
			Category: it.Category, Description: "订阅: " + sub.Name,
			Enabled: true, Source: "subscription", SubID: sub.ID,
			CreatedAt: now, UpdatedAt: now,
		}
		if err := s.db.Create(&p).Error; err != nil {
			return 0, err
		}
	}
	_ = ja4svc.PublishMalware()
	return len(items), nil
}

// ja4ProfileItem CSV 解析条目
type ja4ProfileItem struct {
	Name     string
	Ja4      string
	Category string
}

// parseJa4ProfileCSV 解析 "名称,ja4[,category]" 每行（跳过 # 注释与空行，支持逗号/引号）
func parseJa4ProfileCSV(body string) ([]ja4ProfileItem, error) {
	var out []ja4ProfileItem
	seen := map[string]bool{}
	for _, line := range strings.Split(body, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.Split(line, ",")
		if len(parts) < 2 {
			continue
		}
		name := strings.Trim(strings.TrimSpace(parts[0]), `"`)
		ja4 := strings.Trim(strings.TrimSpace(parts[1]), `"`)
		if name == "" || ja4 == "" || seen[ja4] {
			continue
		}
		cat := "other"
		if len(parts) >= 3 {
			switch strings.TrimSpace(parts[2]) {
			case "malware", "browser", "tool":
				cat = strings.TrimSpace(parts[2])
			}
		}
		seen[ja4] = true
		out = append(out, ja4ProfileItem{Name: name, Ja4: ja4, Category: cat})
	}
	return out, nil
}

// parseIPLines 按行解析 IP/CIDR（跳过注释与空行，支持逗号分隔）。
// 注释支持 # 与 ;（Spamhaus drop.txt 等使用 "CIDR ; 描述" 格式）
func (s *IpListService) parseIPLines(body string) []string {
	var out []string
	seen := map[string]bool{}
	for _, line := range strings.Split(body, "\n") {
		line = strings.TrimSpace(line)
		// 截断注释部分
		if idx := strings.IndexAny(line, "#;"); idx >= 0 {
			line = strings.TrimSpace(line[:idx])
		}
		if line == "" {
			continue
		}
		for _, part := range strings.FieldsFunc(line, func(r rune) bool {
			return r == ',' || r == ' ' || r == '\t'
		}) {
			part = strings.TrimSpace(part)
			if part == "" || seen[part] {
				continue
			}
			seen[part] = true
			out = append(out, part)
		}
	}
	return out
}

// syncFingerprints 同步恶意指纹库：JSON 数组或每行 "名称|指纹值[|exact|regex]" 格式。
// 重建该订阅产生的条目（source=subscription + sub_id），并下发引擎。
func (s *IpListService) syncFingerprints(sub *model.IpListSubscription, raw string) (int, error) {
	items := parseFingerprintFeed(raw)
	if len(items) == 0 {
		return 0, errors.New("未解析到有效指纹（支持 JSON 数组或每行 名称|值[|match]）")
	}
	if err := s.db.Where("source = ? AND sub_id = ?", "subscription", sub.ID).
		Delete(&model.BotFingerprint{}).Error; err != nil {
		return 0, err
	}
	now := time.Now()
	for _, it := range items {
		f := model.BotFingerprint{
			Name: it.Name, Value: it.Value, Match: it.Match,
			Description: "订阅: " + sub.Name, Enabled: true,
			Source: "subscription", SubID: sub.ID,
			CreatedAt: now, UpdatedAt: now,
		}
		if err := s.db.Create(&f).Error; err != nil {
			return 0, err
		}
	}
	return len(items), NewBotService(s.db, s.mgr, s.cfg).publishFingerprints()
}

// fingerprintItem 解析出的指纹条目
type fingerprintItem struct {
	Name  string
	Value string
	Match string
}

// parseFingerprintFeed 解析指纹订阅内容（JSON 数组或行格式）
func parseFingerprintFeed(body string) []fingerprintItem {
	body = strings.TrimSpace(body)
	var out []fingerprintItem
	if strings.HasPrefix(body, "[") {
		var list []struct {
			Name  string `json:"name"`
			Value string `json:"value"`
			Match string `json:"match"`
		}
		if err := json.Unmarshal([]byte(body), &list); err == nil {
			for _, it := range list {
				name := strings.TrimSpace(it.Name)
				value := strings.TrimSpace(it.Value)
				if name == "" || value == "" {
					continue
				}
				match := "exact"
				if it.Match == "regex" {
					match = "regex"
				}
				out = append(out, fingerprintItem{Name: name, Value: value, Match: match})
			}
			return out
		}
	}
	// 行格式：名称|指纹值[|match]
	for _, line := range strings.Split(body, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.Split(line, "|")
		if len(parts) < 2 {
			continue
		}
		name := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])
		if name == "" || value == "" {
			continue
		}
		match := "exact"
		if len(parts) >= 3 && strings.TrimSpace(parts[2]) == "regex" {
			match = "regex"
		}
		out = append(out, fingerprintItem{Name: name, Value: value, Match: match})
	}
	return out
}

// syncBotProfiles 同步爬虫画像库：JSON 数组 [{"name","ua","ips":[],"engine":true}]，
// 重建该订阅产生的画像并发布引擎。
func (s *IpListService) syncBotProfiles(sub *model.IpListSubscription, raw string) (int, error) {
	var list []struct {
		Name   string   `json:"name"`
		UA     string   `json:"ua"`
		Ips    []string `json:"ips"`
		Engine bool     `json:"engine"`
	}
	body := strings.TrimSpace(raw)
	if !strings.HasPrefix(body, "[") {
		return 0, errors.New("画像订阅内容必须是 JSON 数组格式")
	}
	if err := json.Unmarshal([]byte(body), &list); err != nil {
		return 0, errors.New("画像 JSON 解析失败: " + err.Error())
	}
	if len(list) == 0 {
		return 0, errors.New("未解析到有效画像")
	}
	if err := s.db.Where("source = ? AND sub_id = ?", "subscription", sub.ID).
		Delete(&model.BotProfile{}).Error; err != nil {
		return 0, err
	}
	now := time.Now()
	order := 1000
	for _, it := range list {
		name := strings.TrimSpace(it.Name)
		ua := strings.TrimSpace(it.UA)
		if name == "" || ua == "" {
			continue
		}
		ips, _ := json.Marshal(it.Ips)
		p := model.BotProfile{
			Name: name, UA: ua, Ips: string(ips), Engine: it.Engine,
			Enabled: true, SortOrder: order, Source: "subscription", SubID: sub.ID,
			CreatedAt: now, UpdatedAt: now,
		}
		if err := s.db.Create(&p).Error; err != nil {
			return 0, err
		}
		order++
	}
	return len(list), NewBotService(s.db, s.mgr, s.cfg).publishProfiles()
}

// SyncAll 同步所有已启用且到期的订阅（后台定时任务调用）
func (s *IpListService) SyncAll() {
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
