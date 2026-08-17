package service

import (
	"context"
	"errors"
	"strings"
	"time"

	"gorm.io/gorm"

	"openresty-waf/admin/internal/config"
	"openresty-waf/admin/internal/model"
)

// Ja4Service JA4 客户端指纹库：已知客户端/工具/恶意软件映射 + 查询识别。
type Ja4Service struct {
	db  *gorm.DB
	mgr *RedisManager
	cfg *config.Config
	ctx context.Context
}

func NewJa4Service(db *gorm.DB, mgr *RedisManager, cfg *config.Config) *Ja4Service {
	return &Ja4Service{db: db, mgr: mgr, cfg: cfg, ctx: context.Background()}
}

// AcPrefix 计算 JA4_ac（a段 + "_" + c段前6）：抗 cipher 轮换的追踪标识
func AcPrefix(ja4 string) string {
	parts := strings.Split(ja4, "_")
	if len(parts) < 3 {
		return ""
	}
	c := parts[2]
	if len(c) > 6 {
		c = c[:6]
	}
	return parts[0] + "_" + c
}

// PublishMalware 把启用中的 malware 类 Ja4Profile 同步到恶意指纹库（JA4- 前缀）并下发引擎。
// 引擎对同 TLS 栈请求精确 403 拦截；订阅/删除时同样调用保持同步。
func (s *Ja4Service) PublishMalware() error {
	_ = s.db.Where("name LIKE ?", "JA4-%").Delete(&model.BotFingerprint{}).Error
	var list []model.Ja4Profile
	if err := s.db.Where("category = ? AND enabled = ?", "malware", true).Find(&list).Error; err != nil {
		return err
	}
	now := time.Now()
	for _, p := range list {
		_ = s.db.Create(&model.BotFingerprint{
			Name: "JA4-" + p.Name, Value: p.Ja4, Match: "exact",
			Description: "JA4 客户端库恶意指纹", Enabled: true,
			CreatedAt: now, UpdatedAt: now,
		}).Error
	}
	return NewBotService(s.db, s.mgr, s.cfg).publishFingerprints()
}

// List 客户端库列表（category 过滤）
func (s *Ja4Service) List(category string) ([]model.Ja4Profile, error) {
	q := s.db.Model(&model.Ja4Profile{})
	if category != "" {
		q = q.Where("category = ?", category)
	}
	var list []model.Ja4Profile
	if err := q.Order("category asc, name asc, id asc").Find(&list).Error; err != nil {
		return nil, err
	}
	return list, nil
}

// Create 手工新增客户端指纹
func (s *Ja4Service) Create(p *model.Ja4Profile) error {
	if p.Ja4 == "" || p.Name == "" {
		return errors.New("JA4 与名称不能为空")
	}
	switch p.Category {
	case "browser", "tool", "malware", "other":
	default:
		return errors.New("分类必须是 browser / tool / malware / other")
	}
	p.AcPrefix = AcPrefix(p.Ja4)
	p.Source = "manual"
	return s.db.Create(p).Error
}

// Update 更新客户端指纹
func (s *Ja4Service) Update(id uint, p *model.Ja4Profile) error {
	var existing model.Ja4Profile
	if err := s.db.First(&existing, id).Error; err != nil {
		return errors.New("条目不存在")
	}
	p.AcPrefix = AcPrefix(p.Ja4)
	return s.db.Model(&existing).Updates(map[string]interface{}{
		"ja4": p.Ja4, "ac_prefix": p.AcPrefix, "name": p.Name,
		"category": p.Category, "description": p.Description,
		"enabled": p.Enabled, "updated_at": time.Now(),
	}).Error
}

func (s *Ja4Service) Delete(id uint) error {
	return s.db.Delete(&model.Ja4Profile{}, id).Error
}

// ExportMalwareCSV 导出恶意 JA4（订阅格式：名称,ja4,category），供多机共享情报源
func (s *Ja4Service) ExportMalwareCSV() (string, error) {
	var list []model.Ja4Profile
	if err := s.db.Where("category = ? AND enabled = ?", "malware", true).
		Order("name asc").Find(&list).Error; err != nil {
		return "", err
	}
	var b strings.Builder
	b.WriteString("# FoxIO JA4 恶意指纹导出\n# 名称,ja4,category\n")
	for _, p := range list {
		b.WriteString(p.Name + "," + p.Ja4 + ",malware\n")
	}
	return b.String(), nil
}

// Lookup 查询识别：精确匹配 → JA4_ac 前缀匹配（抗 cipher 轮换）
func (s *Ja4Service) Lookup(ja4 string) (*model.Ja4Profile, string, error) {
	if ja4 == "" {
		return nil, "", errors.New("缺少 ja4")
	}
	var p model.Ja4Profile
	if err := s.db.Where("ja4 = ? AND enabled = ?", ja4, true).First(&p).Error; err == nil {
		return &p, "exact", nil
	}
	ac := AcPrefix(ja4)
	if ac != "" {
		var list []model.Ja4Profile
		if err := s.db.Where("ac_prefix = ? AND enabled = ?", ac, true).
			Order("id asc").Limit(1).Find(&list).Error; err == nil && len(list) > 0 {
			return &list[0], "ja4_ac", nil
		}
	}
	return nil, "", nil
}
