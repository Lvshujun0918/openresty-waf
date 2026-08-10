package service

import (
	"testing"

	"openresty-waf/admin/internal/model"
)

func TestEventService_Consume(t *testing.T) {
	// 未配置 Redis
	db := newTestDB(t)
	s2 := NewEventService(db, NewRedisManager(), newTestConfig())
	if _, err := s2.Consume(10); err == nil {
		t.Fatal("expected error without redis")
	}

	// 配置 Redis + 空队列
	mr, mgr := newTestRedis(t)
	db = newTestDB(t)
	s := NewEventService(db, mgr, newTestConfig())
	if n, err := s.Consume(10); err != nil || n != 0 {
		t.Fatalf("empty queue: n=%d err=%v", n, err)
	}

	// 有效事件 + 坏数据（坏数据应跳过）
	mr.Lpush("waf:event:list",
		`{"time":"2026-01-01T00:00:00Z","client_ip":"1.2.3.4","group":"sqli","rule_id":"1","msg":"x"}`)
	mr.Lpush("waf:event:list", `not-json`)

	n, err := s.Consume(10)
	if err != nil {
		t.Fatalf("consume: %v", err)
	}
	if n != 1 {
		t.Fatalf("expected 1 consumed, got %d", n)
	}
	var evs []model.Event
	db.Find(&evs)
	if len(evs) != 1 {
		t.Fatalf("expected 1 event in db, got %d", len(evs))
	}
	if evs[0].ClientIP != "1.2.3.4" || evs[0].Group != "sqli" {
		t.Errorf("bad event: %+v", evs[0])
	}
}

func TestEventService_List(t *testing.T) {
	// 空列表
	db := newTestDB(t)
	s := NewEventService(db, nil, newTestConfig())

	db.Create(&model.Event{ClientIP: "1.2.3.4", Group: "sqli", RuleID: "1", Host: "a.example.com", Message: "m1"})
	db.Create(&model.Event{ClientIP: "5.6.7.8", Group: "xss", RuleID: "2", Host: "b.example.com", Message: "m2"})
	db.Create(&model.Event{ClientIP: "1.2.3.4", Group: "sqli", RuleID: "1", Host: "a.example.com", Message: "m3"})

	evs, total, err := s.List("", "", "", "", 1, 10)
	if err != nil || total != 3 || len(evs) != 3 {
		t.Fatalf("list all: total=%d len=%d err=%v", total, len(evs), err)
	}

	evs, total, _ = s.List("sqli", "", "", "", 1, 10)
	if total != 2 {
		t.Fatalf("group filter total = %d", total)
	}

	evs, total, _ = s.List("", "5.6.7.8", "", "", 1, 10)
	if total != 1 || evs[0].Group != "xss" {
		t.Fatalf("ip filter total = %d", total)
	}

	evs, total, _ = s.List("", "", "1", "", 1, 10)
	if total != 2 {
		t.Fatalf("rule filter total = %d", total)
	}

	evs, total, _ = s.List("", "", "", "a.example.com", 1, 10)
	if total != 2 {
		t.Fatalf("host filter total = %d", total)
	}
	evs, total, _ = s.List("", "", "", "b.example.com", 1, 10)
	if total != 1 || evs[0].Group != "xss" {
		t.Fatalf("host filter b total = %d", total)
	}

	// 分页
	evs, total, _ = s.List("", "", "", "", 1, 2)
	if len(evs) != 2 {
		t.Fatalf("page size 2 got %d", len(evs))
	}
}
