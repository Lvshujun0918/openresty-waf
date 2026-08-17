package service

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"openresty-waf/admin/internal/model"
)

func TestIpListService_CRUD(t *testing.T) {
	db := newTestDB(t)
	s := NewIpListService(db, NewRedisManager(), newTestConfig())

	// 校验
	if err := s.Create(&model.IpListSubscription{Name: "x", URL: "ftp://x", Type: "whitelist"}); err == nil {
		t.Fatal("expected error for non-http url")
	}
	if err := s.Create(&model.IpListSubscription{Name: "x", URL: "http://x", Type: "invalid"}); err == nil {
		t.Fatal("expected error for bad type")
	}
	if err := s.Create(&model.IpListSubscription{Name: "", URL: "http://x", Type: "whitelist"}); err == nil {
		t.Fatal("expected error for empty name")
	}

	sub := &model.IpListSubscription{Name: "威胁情报", URL: "http://example.com/list.txt", Type: "blacklist", IntervalMin: 0}
	if err := s.Create(sub); err != nil {
		t.Fatalf("create: %v", err)
	}
	if sub.IntervalMin != 60 {
		t.Errorf("interval default = %d", sub.IntervalMin)
	}
	subs, _ := s.List()
	if len(subs) != 1 {
		t.Fatalf("list = %d", len(subs))
	}

	if err := s.Update(sub.ID, &model.IpListSubscription{Name: "改名", URL: "http://x", Type: "whitelist", IntervalMin: 30}); err != nil {
		t.Fatalf("update: %v", err)
	}
	if err := s.SetEnabled(sub.ID, false); err != nil {
		t.Fatal(err)
	}
	subs, _ = s.List()
	if subs[0].Enabled {
		t.Error("should be disabled")
	}
	if err := s.Delete(sub.ID); err != nil {
		t.Fatal(err)
	}
	subs, _ = s.List()
	if len(subs) != 0 {
		t.Fatalf("after delete = %d", len(subs))
	}
}

func TestIpListService_Sync(t *testing.T) {
	// mock 远程列表：注释、换行、逗号混合
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("# threat intel\n1.2.3.4\n5.6.7.8, 9.9.9.9\n\n192.168.1.0/24\n"))
	}))
	defer srv.Close()

	mr, mgr := newTestRedis(t)
	db := newTestDB(t)
	s := NewIpListService(db, mgr, newTestConfig())

	sub := &model.IpListSubscription{
		Name: "威胁情报", URL: srv.URL + "/list.txt", Type: "blacklist",
		IntervalMin: 60, Enabled: true,
	}
	if err := s.Create(sub); err != nil {
		t.Fatal(err)
	}

	// 预置已有黑名单（验证合并去重）
	wafCfg := NewWafConfigService(db, mgr, newTestConfig())
	if err := wafCfg.Save(map[string]interface{}{
		"blacklist": map[string]interface{}{"ips": []string{"1.2.3.4", "10.0.0.1"}},
	}); err != nil {
		t.Fatal(err)
	}

	n, err := s.Sync(sub.ID)
	if err != nil {
		t.Fatalf("sync: %v", err)
	}
	if n != 4 {
		t.Errorf("imported = %d", n)
	}

	cfg, _ := wafCfg.Get()
	bl, _ := cfg["blacklist"].(map[string]interface{})
	ips, _ := bl["ips"].([]interface{})
	// 1.2.3.4 已存在去重 → 共 5 条
	if len(ips) != 5 {
		t.Fatalf("merged ips = %v", ips)
	}

	// Redis 已下发
	body, err := mr.Get("waf:config:data")
	if err != nil {
		t.Fatalf("config not in redis: %v", err)
	}
	var rc map[string]interface{}
	if err := json.Unmarshal([]byte(body), &rc); err != nil {
		t.Fatal(err)
	}
	rbl, _ := rc["blacklist"].(map[string]interface{})
	rips, _ := rbl["ips"].([]interface{})
	if len(rips) != 5 {
		t.Errorf("redis ips = %v", rips)
	}

	// 订阅状态更新
	var updated model.IpListSubscription
	if err := db.First(&updated, sub.ID).Error; err != nil {
		t.Fatal(err)
	}
	if updated.LastStatus != "ok" || updated.LastCount != 4 || updated.LastSyncAt == nil {
		t.Errorf("status = %+v", updated)
	}
}

func TestIpListService_SyncFail(t *testing.T) {
	_, mgr := newTestRedis(t)
	db := newTestDB(t)
	s := NewIpListService(db, mgr, newTestConfig())
	sub := &model.IpListSubscription{Name: "bad", URL: "http://127.0.0.1:1/x", Type: "blacklist"}
	if err := s.Create(sub); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Sync(sub.ID); err == nil {
		t.Fatal("expected sync error")
	}
	var updated model.IpListSubscription
	if err := db.First(&updated, sub.ID).Error; err != nil {
		t.Fatal(err)
	}
	if updated.LastStatus == "" || updated.LastStatus == "ok" {
		t.Errorf("status should record failure: %+v", updated)
	}
}

func TestIpListService_EnsureBuiltinSubscriptions(t *testing.T) {
	_, mgr := newTestRedis(t)
	db := newTestDB(t)
	s := NewIpListService(db, mgr, newTestConfig())

	// 首次：创建两条内置订阅并完成首次同步
	if err := s.EnsureBuiltinSubscriptions(); err != nil {
		t.Fatal(err)
	}
	var subs []model.IpListSubscription
	db.Find(&subs)
	if len(subs) != 2 {
		t.Fatalf("expected 2 builtin subs, got %d", len(subs))
	}
	for _, sub := range subs {
		if !sub.Enabled {
			t.Errorf("builtin sub %s should be enabled", sub.Name)
		}
		if sub.LastStatus != "ok" || sub.LastCount == 0 {
			t.Errorf("builtin sub %s sync failed: %+v", sub.Name, sub.LastStatus)
		}
	}

	// 画像库：内置画像已写入 BotProfile 并发布
	var profiles []model.BotProfile
	db.Find(&profiles)
	if len(profiles) != 18 {
		t.Errorf("expected 18 profiles, got %d", len(profiles))
	}
	// JA4 库：内置条目已写入 Ja4Profile，malware 联动恶意指纹库
	var ja4s []model.Ja4Profile
	db.Find(&ja4s)
	if len(ja4s) != 30 {
		t.Errorf("expected 30 ja4 profiles, got %d", len(ja4s))
	}
	var fps []model.BotFingerprint
	db.Find(&fps)
	if len(fps) == 0 {
		t.Error("expected malware-linked fingerprints")
	}

	// 幂等：再次调用不重复创建
	if err := s.EnsureBuiltinSubscriptions(); err != nil {
		t.Fatal(err)
	}
	var subs2 []model.IpListSubscription
	db.Find(&subs2)
	if len(subs2) != 2 {
		t.Errorf("idempotent: got %d subs", len(subs2))
	}
}
