package service

import (
	"errors"

	"gorm.io/gorm"

	"openresty-waf/admin/internal/model"
)

// SiteService 受保护站点管理（多站点规则隔离）。
// 规则通过 Rule.SiteID 归属站点（0 = 全局规则，对所有域名生效）；
// Publish 时把站点域名写入规则 site 字段，Lua 引擎按请求 Host 过滤规则子集。
type SiteService struct {
	db *gorm.DB
}

func NewSiteService(db *gorm.DB) *SiteService {
	return &SiteService{db: db}
}

// List 站点列表（按创建顺序）
func (s *SiteService) List() ([]model.Site, error) {
	var sites []model.Site
	if err := s.db.Order("id asc").Find(&sites).Error; err != nil {
		return nil, err
	}
	return sites, nil
}

// Create 新增站点（域名唯一）
func (s *SiteService) Create(site *model.Site) error {
	site.ID = 0
	if site.Name == "" || site.Domain == "" {
		return errors.New("站点名称与域名不能为空")
	}
	var cnt int64
	if err := s.db.Model(&model.Site{}).Where("domain = ?", site.Domain).Count(&cnt).Error; err != nil {
		return err
	}
	if cnt > 0 {
		return errors.New("域名已存在")
	}
	return s.db.Create(site).Error
}

// Update 更新站点（名称/域名/启停）
func (s *SiteService) Update(id uint, site *model.Site) error {
	var old model.Site
	if err := s.db.First(&old, id).Error; err != nil {
		return err
	}
	if site.Name == "" || site.Domain == "" {
		return errors.New("站点名称与域名不能为空")
	}
	if site.Domain != old.Domain {
		var cnt int64
		if err := s.db.Model(&model.Site{}).Where("domain = ? AND id <> ?",
			site.Domain, id).Count(&cnt).Error; err != nil {
			return err
		}
		if cnt > 0 {
			return errors.New("域名已存在")
		}
	}
	old.Name = site.Name
	old.Domain = site.Domain
	old.Enabled = site.Enabled
	return s.db.Save(&old).Error
}

// Delete 删除站点：归属规则重置为全局规则（避免悬空引用）
func (s *SiteService) Delete(id uint) error {
	if err := s.db.Model(&model.Rule{}).Where("site_id = ?", id).
		Update("site_id", 0).Error; err != nil {
		return err
	}
	return s.db.Delete(&model.Site{}, id).Error
}

// SiteMeta 批量查询站点元信息（ID → 域名 + 启用状态），BuildRuleset 下发时使用：
// 停用站点的专属规则不下发。
func (s *SiteService) SiteMeta(ids []uint) map[uint]struct {
	Domain  string
	Enabled bool
} {
	out := map[uint]struct {
		Domain  string
		Enabled bool
	}{}
	if len(ids) == 0 {
		return out
	}
	var sites []model.Site
	if err := s.db.Where("id IN ?", ids).Find(&sites).Error; err != nil {
		return out
	}
	for _, st := range sites {
		out[st.ID] = struct {
			Domain  string
			Enabled bool
		}{st.Domain, st.Enabled}
	}
	return out
}
