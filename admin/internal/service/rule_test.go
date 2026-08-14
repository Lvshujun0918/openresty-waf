package service

import (
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

// TestRuleService_BuildRuleset_Site 站点规则下发带 site 域名字段，全局规则不带
func TestRuleService_BuildRuleset_Site(t *testing.T) {
	db := newTestDB(t)
	s := NewRuleService(db, nil, newTestConfig())

	st := &model.Site{Name: "主站", Domain: "cszj.wang"}
	if err := db.Create(st).Error; err != nil {
		t.Fatal(err)
	}
	// 全局规则（site_id=0）
	db.Create(&model.Rule{RuleID: "g1", Operator: "REGEX", Pattern: "a", Enabled: true})
	// 站点规则
	db.Create(&model.Rule{RuleID: "s1", Operator: "REGEX", Pattern: "b", Enabled: true, SiteID: st.ID})
	// 站点已删除（site_id 悬空）→ 不下发 site 字段，按全局处理
	db.Create(&model.Rule{RuleID: "s2", Operator: "REGEX", Pattern: "c", Enabled: true, SiteID: 999})

	rs, err := s.BuildRuleset()
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	byID := map[string]map[string]interface{}{}
	for _, r := range rs.Rules {
		byID[r["id"].(string)] = r
	}
	if _, ok := byID["g1"]["site"]; ok {
		t.Error("全局规则不应带 site 字段")
	}
	if v, ok := byID["s1"]["site"]; !ok || v != "cszj.wang" {
		t.Errorf("站点规则 site = %v", byID["s1"]["site"])
	}
	if _, ok := byID["s2"]["site"]; ok {
		t.Error("悬空站点规则不应带 site 字段")
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

	rules, err := s.List("", "", "")
	if err != nil || len(rules) != 1 {
		t.Fatalf("list = %v, err = %v", len(rules), err)
	}
	// 过滤
	if rules, _ := s.List("custom", "", ""); len(rules) != 0 {
		t.Fatalf("group filter should return 0, got %d", len(rules))
	}
	if rules, _ := s.List("", "", "100"); len(rules) != 1 {
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
	if rules, _ := s.List("", "", ""); len(rules) != 0 {
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
