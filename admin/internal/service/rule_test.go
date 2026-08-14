package service

import (
	"encoding/json"
	"strings"
	"testing"

	"openresty-waf/admin/internal/model"
)

func TestRuleService_toEngineRule(t *testing.T) {
	s := NewRuleService(newTestDB(t), nil, newTestConfig())

	r := model.Rule{
		RuleID: "30001", Group: "custom", Phase: "access", Severity: 2,
		Enabled: true, Operator: "REGEX", Pattern: "foo",
		Transforms: `["url_decode"]`, Vars: `[{"type":"URI_ARGS"}]`,
		Status: 403, Message: "hi",
	}
	out := s.toEngineRule(r)
	if out["id"] != "30001" {
		t.Errorf("id = %v", out["id"])
	}
	if out["operator"] != "REGEX" {
		t.Errorf("operator = %v", out["operator"])
	}
	vars, ok := out["vars"].([]interface{})
	if !ok || len(vars) != 1 {
		t.Errorf("vars = %#v", out["vars"])
	}
	if out["enabled"] != true {
		t.Errorf("enabled = %v", out["enabled"])
	}

	// 空 actions 时生成默认 BLOCK
	r2 := model.Rule{RuleID: "1", Operator: "REGEX", Pattern: "x", Status: 403, Message: "m"}
	out2 := s.toEngineRule(r2)
	actions, ok := out2["actions"].(map[string]interface{})
	if !ok {
		t.Fatalf("actions not a map: %#v", out2["actions"])
	}
	if actions["disrupt"] != "BLOCK" {
		t.Errorf("actions.disrupt = %v", actions["disrupt"])
	}
}

func TestRuleService_BuildRuleset(t *testing.T) {
	db := newTestDB(t)
	s := NewRuleService(db, nil, newTestConfig())

	rs, err := s.BuildRuleset()
	if err != nil {
		t.Fatalf("build empty: %v", err)
	}
	if len(rs.Rules) != 0 {
		t.Fatalf("expected 0 rules, got %d", len(rs.Rules))
	}
	if rs.Version == "" {
		t.Fatal("version should not be empty")
	}

	db.Create(&model.Rule{RuleID: "1", Operator: "REGEX", Pattern: "a", Enabled: true})
	// bool 零值 false 在 Create 时被 gorm 跳过（走 DB default:true），用 Update 显式置 false
	r2 := &model.Rule{RuleID: "2", Operator: "REGEX", Pattern: "b", Enabled: true}
	if err := db.Create(r2).Error; err != nil {
		t.Fatal(err)
	}
	if err := db.Model(&model.Rule{}).Where("rule_id = ?", "2").Update("enabled", false).Error; err != nil {
		t.Fatal(err)
	}
	rs, _ = s.BuildRuleset()
	if len(rs.Rules) != 1 {
		t.Fatalf("expected 1 enabled rule, got %d", len(rs.Rules))
	}
	if rs.Rules[0]["id"] != "1" {
		t.Errorf("first rule id = %v", rs.Rules[0]["id"])
	}
}

func TestRuleParanoiaLevel(t *testing.T) {
	cases := map[string]int{
		// PL1：关键字/语义/自定义
		"942110": 1, "10001": 1, "940001": 1, "941130": 1, "931110": 1,
		"921170": 1, "20001": 1,
		// PL2：SQL 启发式（探测/特殊字符/认证绕过）
		"942340": 2, "942370": 2, "942430": 2, "942490": 2, "942420": 2,
		// PL2：XSS 混淆/编码
		"941360": 2, "941370": 2, "941380": 2,
		// 非法/非数字
		"abc": 1, "": 1,
	}
	for id, want := range cases {
		if got := model.RuleParanoiaLevel(id); got != want {
			t.Errorf("RuleParanoiaLevel(%q) = %d, want %d", id, got, want)
		}
	}
}

func TestRuleService_BuildRuleset_Paranoia(t *testing.T) {
	db := newTestDB(t)
	s := NewRuleService(db, nil, newTestConfig())

	db.Create(&model.Rule{RuleID: "942110", Operator: "REGEX", Pattern: "a", Enabled: true}) // PL1
	db.Create(&model.Rule{RuleID: "942430", Operator: "REGEX", Pattern: "b", Enabled: true}) // PL2
	db.Create(&model.Rule{RuleID: "10001", Operator: "REGEX", Pattern: "c", Enabled: true})  // 自定义 PL1

	// 无 waf_config → 默认 PL1 → 只发布 PL1 两条
	rs, err := s.BuildRuleset()
	if err != nil {
		t.Fatal(err)
	}
	if len(rs.Rules) != 2 {
		t.Fatalf("PL1 应发布 2 条, got %d", len(rs.Rules))
	}

	// 配置 PL2 → 发布 3 条
	if err := db.Create(&model.Setup{Key: SetupKeyWafConfig, Value: `{"detection":{"paranoia_level":2}}`}).Error; err != nil {
		t.Fatal(err)
	}
	rs, err = s.BuildRuleset()
	if err != nil {
		t.Fatal(err)
	}
	if len(rs.Rules) != 3 {
		t.Fatalf("PL2 应发布 3 条, got %d", len(rs.Rules))
	}
}

func TestRuleService_CRUD(t *testing.T) {
	db := newTestDB(t)
	s := NewRuleService(db, nil, newTestConfig())

	// Create 必填校验
	if err := s.Create(&model.Rule{}); err == nil {
		t.Fatal("expected error for missing required fields")
	}
	r := &model.Rule{RuleID: "100", Operator: "REGEX", Pattern: "x", Name: "n"}
	if err := s.Create(r); err != nil {
		t.Fatalf("create: %v", err)
	}

	rules, err := s.List("", "")
	if err != nil || len(rules) != 1 {
		t.Fatalf("list = %v, err = %v", len(rules), err)
	}
	// 过滤
	if rules, _ := s.List("custom", ""); len(rules) != 0 {
		t.Fatalf("group filter should return 0, got %d", len(rules))
	}
	if rules, _ := s.List("", "100"); len(rules) != 1 {
		t.Fatalf("keyword filter should return 1, got %d", len(rules))
	}

	// Update
	r.Name = "n2"
	if err := s.Update(r.ID, r); err != nil {
		t.Fatalf("update: %v", err)
	}
	var got model.Rule
	db.First(&got, r.ID)
	if got.Name != "n2" {
		t.Errorf("name after update = %s", got.Name)
	}

	// Update/SetEnabled 不存在
	if err := s.Update(999, r); err == nil {
		t.Fatal("expected error updating non-existent rule")
	}
	if err := s.SetEnabled(999, true); err == nil {
		t.Fatal("expected error enabling non-existent rule")
	}

	// SetEnabled
	if err := s.SetEnabled(r.ID, false); err != nil {
		t.Fatalf("set enabled: %v", err)
	}
	db.First(&got, r.ID)
	if got.Enabled {
		t.Error("rule should be disabled")
	}

	// Delete
	if err := s.Delete(r.ID); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if rules, _ := s.List("", ""); len(rules) != 0 {
		t.Fatalf("expected 0 rules after delete, got %d", len(rules))
	}
}

func TestRuleService_Publish(t *testing.T) {
	db := newTestDB(t)

	// 未配置 Redis → 报错
	s := NewRuleService(db, NewRedisManager(), newTestConfig())
	if _, err := s.Publish(); err == nil {
		t.Fatal("expected error without redis")
	}

	// 配置 Redis
	mr, mgr := newTestRedis(t)
	s2 := NewRuleService(db, mgr, newTestConfig())
	db.Create(&model.Rule{RuleID: "1", Operator: "REGEX", Pattern: "a", Enabled: true})

	rs, err := s2.Publish()
	if err != nil {
		t.Fatalf("publish: %v", err)
	}
	if len(rs.Rules) != 1 {
		t.Fatalf("expected 1 rule published, got %d", len(rs.Rules))
	}
	if _, err := mr.Get("waf:rule:version"); err != nil {
		t.Errorf("version key missing: %v", err)
	}
	body, err := mr.Get("waf:rule:ruleset")
	if err != nil || body == "" {
		t.Errorf("ruleset key missing: %v", err)
	}
}

func TestRuleService_validateRule(t *testing.T) {
	s := NewRuleService(newTestDB(t), nil, newTestConfig())

	// 非法运算符拒绝
	if err := s.validateRule(&model.Rule{RuleID: "1", Operator: "BOGUS", Pattern: "a"}); err == nil {
		t.Error("expected error for unknown operator")
	}
	// 合法运算符通过（含语义运算符）
	for _, op := range []string{"REGEX", "PM", "CIDR", "EXISTS", "LIBINJECTION_SQLI", "LIBINJECTION_XSS"} {
		if err := s.validateRule(&model.Rule{RuleID: "1", Operator: op, Pattern: "a"}); err != nil {
			t.Errorf("operator %s should pass: %v", op, err)
		}
	}
	// 超长 pattern 拒绝（> 32KB）
	long := strings.Repeat("a", 32769)
	if err := s.validateRule(&model.Rule{RuleID: "1", Operator: "REGEX", Pattern: long}); err == nil {
		t.Error("expected error for overlong pattern")
	}
	// 长 CRS 正则（<= 32KB）通过
	crs := strings.Repeat("a", 32768)
	if err := s.validateRule(&model.Rule{RuleID: "1", Operator: "REGEX", Pattern: crs}); err != nil {
		t.Errorf("32KB pattern should pass: %v", err)
	}
	// 空字段拒绝
	if err := s.validateRule(&model.Rule{RuleID: "", Operator: "REGEX", Pattern: "a"}); err == nil {
		t.Error("expected error for empty rule_id")
	}
}

func TestRuleService_PublishHistoryAndRollback(t *testing.T) {
	db := newTestDB(t)
	_, mgr := newTestRedis(t)
	s := NewRuleService(db, mgr, newTestConfig())

	// 第一次发布：1 条规则
	db.Create(&model.Rule{RuleID: "1", Operator: "REGEX", Pattern: "a", Enabled: true})
	rs1, err := s.Publish()
	if err != nil {
		t.Fatalf("publish #1: %v", err)
	}
	// 修改后再发布：2 条规则
	db.Create(&model.Rule{RuleID: "2", Operator: "REGEX", Pattern: "b", Enabled: true})
	if _, err := s.Publish(); err != nil {
		t.Fatalf("publish #2: %v", err)
	}

	list, err := s.ListPublishHistory()
	if err != nil {
		t.Fatalf("list history: %v", err)
	}
	if len(list) != 2 {
		t.Fatalf("expected 2 history entries, got %d", len(list))
	}
	if list[0].Version <= list[1].Version {
		t.Errorf("history order: newest first expected")
	}
	if list[1].RuleCount != 1 {
		t.Errorf("first publish should contain 1 rule, got %d", list[1].RuleCount)
	}

	// 回滚到第一条历史（1 条规则）
	if err := s.Rollback(list[1].ID); err != nil {
		t.Fatalf("rollback: %v", err)
	}
	got, _ := s.mgr.GetClient().Get(s.ctx, "waf:rule:ruleset").Result()
	var rs Ruleset
	if err := json.Unmarshal([]byte(got), &rs); err != nil {
		t.Fatalf("rolled back ruleset invalid: %v", err)
	}
	if len(rs.Rules) != 1 {
		t.Fatalf("rollback should restore 1 rule, got %d", len(rs.Rules))
	}
	// 回滚也记录历史（共 3 条）
	list, _ = s.ListPublishHistory()
	if len(list) != 3 {
		t.Errorf("rollback should append history, got %d", len(list))
	}
	// 版本号单调递增
	ver, _ := s.mgr.GetClient().Get(s.ctx, "waf:rule:version").Int64()
	if ver != 3 {
		t.Errorf("expected version 3 after publish+rollback, got %d", ver)
	}
	// 回滚不存在的记录报错
	if err := s.Rollback(9999); err == nil {
		t.Error("expected error rolling back non-existent history")
	}
	_ = rs1
}
