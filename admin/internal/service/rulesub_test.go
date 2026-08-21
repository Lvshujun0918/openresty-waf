package service

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"openresty-waf/admin/internal/model"
)

// newRuleSubFixture 构造带 Redis 的服务与本地规则源服务器
func newRuleSubFixture(t *testing.T, payload string) (*RuleSubService, *httptest.Server) {
	t.Helper()
	db := newTestDB(t)
	_, mgr := newTestRedis(t)
	svc := NewRuleSubService(db, mgr, newTestConfig())
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(payload))
	}))
	t.Cleanup(ts.Close)
	return svc, ts
}

func ruleSubPayload() string {
	rules := []model.Rule{
		{RuleID: "99001", Name: "订阅规则A", Group: "custom", Phase: "access", Severity: 3,
			Enabled: true, Operator: "CONTAINS", Pattern: "evil-token",
			Transforms: "[]", Vars: `[{"type":"URI_ARGS","name":"q"}]`,
			Actions: `{"disrupt":"BLOCK","status":403}`, Status: 403, Message: "命中订阅规则A"},
		{RuleID: "", Name: "缺 rule_id 应被跳过", Group: "custom", Phase: "access",
			Operator: "CONTAINS", Pattern: "x", Transforms: "[]", Vars: "[]",
			Actions: `{"disrupt":"BLOCK"}`},
	}
	b, _ := json.Marshal(rules)
	return string(b)
}

func TestRuleSubService_Validation(t *testing.T) {
	db := newTestDB(t)
	_, mgr := newTestRedis(t)
	svc := NewRuleSubService(db, mgr, newTestConfig())

	if err := svc.Create(&model.RuleSubscription{Name: "", URL: "http://x/rules.json"}); err == nil {
		t.Fatal("空名称应被拒绝")
	}
	if err := svc.Create(&model.RuleSubscription{Name: "s", URL: "ftp://x"}); err == nil {
		t.Fatal("非 http(s) URL 应被拒绝")
	}
	sub := &model.RuleSubscription{Name: "s", URL: "http://x/rules.json", IntervalMin: 0}
	if err := svc.Create(sub); err != nil {
		t.Fatalf("合法订阅创建失败: %v", err)
	}
	if sub.IntervalMin != 1440 {
		t.Fatalf("默认同步周期应为 1440，实际 %d", sub.IntervalMin)
	}
}

func TestRuleSubService_SyncRebuildsRules(t *testing.T) {
	svc, ts := newRuleSubFixture(t, ruleSubPayload())
	sub := &model.RuleSubscription{Name: "远程规则源", URL: ts.URL + "/rules.json"}
	if err := svc.Create(sub); err != nil {
		t.Fatal(err)
	}

	n, err := svc.Sync(sub.ID)
	if err != nil {
		t.Fatalf("同步失败: %v", err)
	}
	if n != 1 {
		t.Fatalf("应入库 1 条有效规则，实际 %d", n)
	}

	var got model.Rule
	if err := svc.db.Where("rule_id = ?", "99001").First(&got).Error; err != nil {
		t.Fatalf("订阅规则未入库: %v", err)
	}
	if got.Source != "subscription" || got.SubID != sub.ID {
		t.Fatalf("来源标记错误: source=%s sub_id=%d", got.Source, got.SubID)
	}

	// 远端更新后重复同步：重建而非追加
	payload2 := `[{"rule_id":"99002","name":"订阅规则B","group":"custom","phase":"access","severity":3,"enabled":true,"operator":"CONTAINS","pattern":"bad2","transforms":"[]","vars":"[]","actions":{"disrupt":"BLOCK"},"status":403}]`
	sub.URL = ts.URL // 复用同一 server，改 handler 内容不便；直接再建一个源
	ts2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(payload2))
	}))
	defer ts2.Close()
	svc.db.Model(&model.RuleSubscription{}).Where("id = ?", sub.ID).Update("url", ts2.URL)

	if _, err := svc.Sync(sub.ID); err != nil {
		t.Fatalf("二次同步失败: %v", err)
	}
	var count int64
	svc.db.Model(&model.Rule{}).Where("source = ? AND sub_id = ?", "subscription", sub.ID).Count(&count)
	if count != 1 {
		t.Fatalf("重建后应只剩 1 条订阅规则，实际 %d", count)
	}
	var old model.Rule
	if err := svc.db.Where("rule_id = ?", "99001").First(&old).Error; err == nil {
		t.Fatal("远端已移除的 99001 应被清理")
	}
}

func TestRuleSubService_DeleteCleansRules(t *testing.T) {
	svc, ts := newRuleSubFixture(t, ruleSubPayload())
	sub := &model.RuleSubscription{Name: "待删除源", URL: ts.URL + "/rules.json"}
	if err := svc.Create(sub); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Sync(sub.ID); err != nil {
		t.Fatal(err)
	}
	if err := svc.Delete(sub.ID); err != nil {
		t.Fatalf("删除失败: %v", err)
	}
	var count int64
	svc.db.Model(&model.Rule{}).Where("source = ? AND sub_id = ?", "subscription", sub.ID).Count(&count)
	if count != 0 {
		t.Fatalf("删除订阅后应清理其规则，残留 %d 条", count)
	}
	var subCount int64
	svc.db.Model(&model.RuleSubscription{}).Count(&subCount)
	if subCount != 0 {
		t.Fatalf("订阅未删除，残留 %d", subCount)
	}
}

func TestRuleSubService_SyncAllRespectsInterval(t *testing.T) {
	svc, ts := newRuleSubFixture(t, ruleSubPayload())
	sub := &model.RuleSubscription{Name: "周期源", URL: ts.URL + "/rules.json", IntervalMin: 1440}
	if err := svc.Create(sub); err != nil {
		t.Fatal(err)
	}
	// 首次 SyncAll：无 LastSyncAt，应执行
	svc.SyncAll()
	var count int64
	svc.db.Model(&model.Rule{}).Where("rule_id = ?", "99001").Count(&count)
	if count != 1 {
		t.Fatal("首次 SyncAll 应同步入库")
	}
	// 刚同步过、周期未到：不应重复执行（通过 last_status 不变验证）
	svc.db.Model(&model.RuleSubscription{}).Where("id = ?", sub.ID).
		Update("last_status", "sentinel")
	svc.SyncAll()
	var after model.RuleSubscription
	if err := svc.db.First(&after, sub.ID).Error; err != nil {
		t.Fatal(err)
	}
	if after.LastStatus != "sentinel" {
		t.Fatalf("周期未到不应重新同步，状态=%s", after.LastStatus)
	}
}
