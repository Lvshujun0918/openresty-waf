package service

import (
	"testing"
	"time"

	"openresty-waf/admin/internal/model"
)

// TestDashboardService_Stats_HostFilter 按站点域名过滤仪表盘聚合
func TestDashboardService_Stats_HostFilter(t *testing.T) {
	db := newTestDB(t)
	now := time.Now()
	db.Create(&model.Event{Time: now, Host: "a.com", Group: "sqli", ClientIP: "1.1.1.1", Status: 403})
	db.Create(&model.Event{Time: now, Host: "b.com", Group: "xss", ClientIP: "2.2.2.2", Status: 403})
	svc := NewDashboardService(db)

	all, err := svc.Stats(7, "")
	if err != nil {
		t.Fatalf("stats: %v", err)
	}
	if all.Total.Events != 2 {
		t.Fatalf("total events = %d", all.Total.Events)
	}

	a, err := svc.Stats(7, "a.com")
	if err != nil {
		t.Fatalf("stats a: %v", err)
	}
	if a.Total.Events != 1 {
		t.Fatalf("a events = %d", a.Total.Events)
	}
	if len(a.Groups) != 1 || a.Groups[0].Group != "sqli" {
		t.Errorf("a groups = %+v", a.Groups)
	}
	if len(a.TopIPs) != 1 || a.TopIPs[0].ClientIP != "1.1.1.1" {
		t.Errorf("a top ips = %+v", a.TopIPs)
	}
	if len(a.AttackTrend) == 0 {
		t.Error("attack trend empty")
	}
}