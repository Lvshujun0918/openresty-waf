package service

import (
	"testing"
)

func TestWafConfigService_GetDefault(t *testing.T) {
	db := newTestDB(t)
	s := NewWafConfigService(db, nil, newTestConfig())

	cfg, err := s.Get()
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if cfg["mode"] != "active" {
		t.Errorf("mode = %v", cfg["mode"])
	}
	if cc, ok := cfg["cc"].(map[string]interface{}); !ok || cc["rate"] != "100/60" {
		t.Errorf("cc = %#v", cfg["cc"])
	}
	if blk, ok := cfg["block"].(map[string]interface{}); !ok || blk["status"] != 403 {
		t.Errorf("block = %#v", cfg["block"])
	}
	if ch, ok := cfg["challenge"].(map[string]interface{}); !ok || ch["mode"] != "basic" {
		t.Errorf("challenge = %#v", cfg["challenge"])
	}
}

func TestWafConfigService_Save(t *testing.T) {
	db := newTestDB(t)

	// 未配置 Redis → 报错
	s := NewWafConfigService(db, NewRedisManager(), newTestConfig())
	if err := s.Save(map[string]interface{}{"mode": "detect"}); err == nil {
		t.Fatal("expected error without redis")
	}

	// 配置 Redis
	mr, mgr := newTestRedis(t)
	db = newTestDB(t)
	s2 := NewWafConfigService(db, mgr, newTestConfig())
	custom := map[string]interface{}{"mode": "detect"}
	if err := s2.Save(custom); err != nil {
		t.Fatalf("save: %v", err)
	}

	got, err := s2.Get()
	if err != nil {
		t.Fatalf("get after save: %v", err)
	}
	if got["mode"] != "detect" {
		t.Errorf("mode after save = %v", got["mode"])
	}

	if _, err := mr.Get("waf:config:version"); err != nil {
		t.Errorf("config version key missing: %v", err)
	}
	body, err := mr.Get("waf:config:data")
	if err != nil || body == "" {
		t.Errorf("config data key missing: %v", err)
	}
}
func TestWafConfigService_BanIP(t *testing.T) {
        db := newTestDB(t)
        _, mgr := newTestRedis(t)
        s := NewWafConfigService(db, mgr, newTestConfig())

        // 非法 IP 拒绝
        if err := s.BanIP("not-an-ip", 1); err == nil {
                t.Fatal("expected error for invalid ip")
        }
        // 永久封禁
        if err := s.BanIP("1.2.3.4", 0); err != nil {
                t.Fatalf("ban permanent: %v", err)
        }
        // 临时封禁
        if err := s.BanIP("5.6.7.8", 1); err != nil {
                t.Fatalf("ban temporary: %v", err)
        }

        list, err := s.ListBans()
        if err != nil {
                t.Fatalf("list: %v", err)
        }
        if len(list) != 2 {
                t.Fatalf("expected 2 bans, got %d", len(list))
        }
        var perm, temp *BanEntry
        for i := range list {
                if list[i].IP == "1.2.3.4" {
                        perm = &list[i]
                }
                if list[i].IP == "5.6.7.8" {
                        temp = &list[i]
                }
        }
        if perm == nil || !perm.Permanent {
                t.Errorf("permanent ban missing: %+v", list)
        }
        if temp == nil || temp.ExpiresAt == nil {
                t.Errorf("temporary ban missing: %+v", list)
        }

        // 重复封禁去重
        if err := s.BanIP("1.2.3.4", 2); err != nil {
                t.Fatalf("re-ban: %v", err)
        }
        list, _ = s.ListBans()
        if len(list) != 2 {
                t.Errorf("re-ban should dedupe, got %d", len(list))
        }

        // 解除封禁
        if err := s.UnbanIP("1.2.3.4"); err != nil {
                t.Fatalf("unban: %v", err)
        }
        list, _ = s.ListBans()
        if len(list) != 1 || list[0].IP != "5.6.7.8" {
                t.Errorf("unban failed: %+v", list)
        }
}