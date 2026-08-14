package service

import (
	"testing"

	"openresty-waf/admin/internal/model"
)

func TestSite_CreateAndList(t *testing.T) {
	db := newTestDB(t)
	svc := NewSiteService(db)

	if err := svc.Create(&model.Site{Name: "主站", Domain: "cszj.wang", Enabled: true}); err != nil {
		t.Fatalf("create: %v", err)
	}
	if err := svc.Create(&model.Site{Name: "阅读站", Domain: "reader.example.com"}); err != nil {
		t.Fatalf("create2: %v", err)
	}

	sites, err := svc.List()
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(sites) != 2 {
		t.Fatalf("sites = %d", len(sites))
	}
	if sites[0].Domain != "cszj.wang" {
		t.Errorf("order: %s", sites[0].Domain)
	}
}

func TestSite_CreateDuplicateDomain(t *testing.T) {
	db := newTestDB(t)
	svc := NewSiteService(db)
	if err := svc.Create(&model.Site{Name: "a", Domain: "x.com"}); err != nil {
		t.Fatalf("create: %v", err)
	}
	if err := svc.Create(&model.Site{Name: "b", Domain: "x.com"}); err == nil {
		t.Fatal("duplicate domain should fail")
	}
}

func TestSite_UpdateAndDelete(t *testing.T) {
	db := newTestDB(t)
	svc := NewSiteService(db)
	if err := svc.Create(&model.Site{Name: "a", Domain: "a.com"}); err != nil {
		t.Fatalf("create: %v", err)
	}
	var s model.Site
	db.First(&s)

	if err := svc.Update(s.ID, &model.Site{Name: "b", Domain: "b.com", Enabled: false}); err != nil {
		t.Fatalf("update: %v", err)
	}
	var s2 model.Site
	db.First(&s2, s.ID)
	if s2.Domain != "b.com" || s2.Enabled {
		t.Errorf("after update: %+v", s2)
	}

	// 删除后规则归属重置为全局
	db.Create(&model.Rule{RuleID: "t1", Name: "x", SiteID: s.ID})
	if err := svc.Delete(s.ID); err != nil {
		t.Fatalf("delete: %v", err)
	}
	var r model.Rule
	db.Where("rule_id = ?", "t1").First(&r)
	if r.SiteID != 0 {
		t.Errorf("rule site_id = %d, want 0", r.SiteID)
	}
	var cnt int64
	db.Model(&model.Site{}).Count(&cnt)
	if cnt != 0 {
		t.Errorf("site not deleted")
	}
}

func TestSite_SiteMeta(t *testing.T) {
	db := newTestDB(t)
	svc := NewSiteService(db)
	svc.Create(&model.Site{Name: "a", Domain: "a.com"})
	svc.Create(&model.Site{Name: "b", Domain: "b.com", Enabled: false})
	var s1, s2 model.Site
	db.Where("domain = ?", "a.com").First(&s1)
	db.Where("domain = ?", "b.com").First(&s2)

	m := svc.SiteMeta([]uint{s1.ID, s2.ID, 999})
	if m[s1.ID].Domain != "a.com" || !m[s1.ID].Enabled {
		t.Errorf("meta a: %+v", m[s1.ID])
	}
	if m[s2.ID].Domain != "b.com" || m[s2.ID].Enabled {
		t.Errorf("meta b: %+v", m[s2.ID])
	}
	if len(m) != 2 {
		t.Errorf("len = %d", len(m))
	}
	if len(svc.SiteMeta(nil)) != 0 {
		t.Error("nil ids")
	}
}