package service

import (
	"testing"
	"time"
)

func TestTrafficStatService_Stat(t *testing.T) {
	db := newTestDB(t)
	svc := NewTrafficStatService(db)

	now := time.Now()
	rows := []struct {
		offset  time.Duration
		ip, uri string
		host    string
		status  int
		attack  bool
		respMS  float64
	}{
		{0 * time.Hour, "1.1.1.1", "/a", "x.com", 200, false, 10},
		{0 * time.Hour, "1.1.1.1", "/b", "x.com", 403, true, 20},
		{2 * time.Hour, "2.2.2.2", "/a", "y.com", 200, false, 30},
		{2 * time.Hour, "3.3.3.3", "/c", "y.com", 502, false, 40},
	}
	for _, r := range rows {
		err := db.Exec(`INSERT INTO traffic_logs (time, req_id, client_ip, method, host, uri, status, attack, response_time, created_at)
			VALUES (?, ?, ?, 'GET', ?, ?, ?, ?, ?, ?)`,
			now.Add(-r.offset).Format("2006-01-02 15:04:05"),
			"req", r.ip, r.host, r.uri, r.status, r.attack, r.respMS,
			now.Format("2006-01-02 15:04:05")).Error
		if err != nil {
			t.Fatalf("insert: %v", err)
		}
	}

	rep, err := svc.Stat(24)
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}

	// 汇总
	if rep.Summary.Total != 4 {
		t.Fatalf("total=%d 期望 4", rep.Summary.Total)
	}
	if rep.Summary.Blocked != 2 { // 403 + 502
		t.Fatalf("blocked=%d 期望 2", rep.Summary.Blocked)
	}
	if rep.Summary.BlockRate < 49.99 || rep.Summary.BlockRate > 50.01 {
		t.Fatalf("block_rate=%v 期望 50", rep.Summary.BlockRate)
	}
	if rep.Summary.Attacks != 1 {
		t.Fatalf("attacks=%d 期望 1", rep.Summary.Attacks)
	}
	if rep.Summary.UniqueIPs != 3 {
		t.Fatalf("unique_ips=%d 期望 3", rep.Summary.UniqueIPs)
	}
	if rep.Summary.AvgResponseMS < 24.99 || rep.Summary.AvgResponseMS > 25.01 {
		t.Fatalf("avg_response_ms=%v 期望 25", rep.Summary.AvgResponseMS)
	}

	// 序列补零：全序列合计 4
	total := int64(0)
	for _, p := range rep.Series {
		total += p.Total
	}
	if total != 4 {
		t.Fatalf("序列合计=%d 期望 4（补零不应丢数据）", total)
	}
	last := rep.Series[len(rep.Series)-1]
	if last.Total != 2 || last.Blocked != 1 {
		t.Fatalf("当前桶 total=%d blocked=%d 期望 2/1", last.Total, last.Blocked)
	}

	// 状态分布
	if len(rep.StatusDist) != 3 {
		t.Fatalf("status_dist=%d 条 期望 3", len(rep.StatusDist))
	}
	if rep.StatusDist[0].Count != 2 {
		t.Fatalf("status_dist 首条 count=%d 期望 2", rep.StatusDist[0].Count)
	}

	// Top IP：1.1.1.1 两条居首
	if len(rep.TopIPs) == 0 || rep.TopIPs[0].Name != "1.1.1.1" {
		t.Fatalf("top_ips 首条应为 1.1.1.1，实际 %+v", rep.TopIPs)
	}
	if rep.TopIPs[0].Count != 2 || rep.TopIPs[0].Blocked != 1 {
		t.Fatalf("top_ips[0] count/blocked=%d/%d 期望 2/1", rep.TopIPs[0].Count, rep.TopIPs[0].Blocked)
	}

	// Top URI 首条 /a；Top Host 两条并列（各 2），仅验证条数与计数
	if len(rep.TopURIs) == 0 || rep.TopURIs[0].Name != "/a" {
		t.Fatal("top_uris 首条应为 /a")
	}
	if len(rep.TopHosts) != 2 {
		t.Fatalf("top_hosts 应有 2 个主机，实际 %d", len(rep.TopHosts))
	}
	for _, h := range rep.TopHosts {
		if h.Count != 2 {
			t.Fatalf("top_hosts 计数应为 2: %+v", rep.TopHosts)
		}
	}

	// 边界 clamp 不报错
	if _, err = svc.Stat(-5); err != nil {
		t.Fatalf("clamp low: %v", err)
	}
	if _, err = svc.Stat(10000); err != nil {
		t.Fatalf("clamp high: %v", err)
	}
}

func TestTrafficStatService_Empty(t *testing.T) {
	db := newTestDB(t)
	svc := NewTrafficStatService(db)
	rep, err := svc.Stat(24)
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if rep.Summary.Total != 0 || rep.Summary.UniqueIPs != 0 {
		t.Fatalf("空库汇总应为零值: %+v", rep.Summary)
	}
	if len(rep.StatusDist) != 0 {
		t.Fatal("空库状态分布应为空")
	}
	if len(rep.Series) == 0 {
		t.Fatal("空库也应返回补零时间轴")
	}
}
