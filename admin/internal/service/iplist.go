package service

import (
	"context"
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

// IpListService 远程 IP 列表订阅：定时拉取 URL 中的 IP/CIDR，
// 合并到白/黑名单并下发引擎热更新。
type IpListService struct {
	db     *gorm.DB
	wafCfg *WafConfigService
	cfg    *config.Config
	ctx    context.Context
}

func NewIpListService(db *gorm.DB, mgr *RedisManager, cfg *config.Config) *IpListService {
	return &IpListService{db: db, wafCfg: NewWafConfigService(db, mgr, cfg), cfg: cfg, ctx: context.Background()}
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
	return s.db.Delete(&model.IpListSubscription{}, id).Error
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
	if sub.Type != "whitelist" && sub.Type != "blacklist" {
		return errors.New("类型必须是 whitelist 或 blacklist")
	}
	if sub.IntervalMin < 1 {
		sub.IntervalMin = 60
	}
	return nil
}

// fetchURL 拉取远程列表并解析出 IP/CIDR 行（支持换行/逗号分隔，跳过 # 注释与空行）
func (s *IpListService) fetchURL(rawURL string) ([]string, error) {
	client := &http.Client{Timeout: 20 * time.Second}
	resp, err := client.Get(rawURL)
	if err != nil {
		return nil, errors.New("拉取失败: " + err.Error())
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 5<<20)) // 上限 5MB
	if err != nil {
		return nil, errors.New("读取响应失败: " + err.Error())
	}

	var out []string
	seen := map[string]bool{}
	// 按行解析：跳过空行与 # 注释，行内支持逗号/空格分隔多个 IP
	for _, line := range strings.Split(string(body), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
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
	return out, nil
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
	fetched, err := s.fetchURL(sub.URL)
	now := time.Now()
	if err != nil {
		_ = s.db.Model(&model.IpListSubscription{}).Where("id = ?", sub.ID).Updates(map[string]interface{}{
			"last_status":  "失败: " + err.Error(),
			"last_sync_at": now,
		}).Error
		return 0, err
	}

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
		_ = s.db.Model(&model.IpListSubscription{}).Where("id = ?", sub.ID).Updates(map[string]interface{}{
			"last_status":  "下发失败: " + err.Error(),
			"last_sync_at": now,
		}).Error
		return 0, err
	}

	_ = s.db.Model(&model.IpListSubscription{}).Where("id = ?", sub.ID).Updates(map[string]interface{}{
		"last_status":  "ok",
		"last_sync_at": now,
		"last_count":   len(fetched),
	}).Error
	return len(fetched), nil
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
