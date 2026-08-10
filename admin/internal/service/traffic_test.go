package service

import (
	"testing"
	"time"

	"openresty-waf/admin/internal/model"
)

func TestTrafficService_Consume(t *testing.T) {
	// 未配置 Redis
	db := newTestDB(t)
	s := NewTrafficService(db, NewRedisManager(), newTestConfig())
	if _, err := s.Consume(10); err == nil {
		t.Fatal("expected error without redis")
	}

	mr, mgr := newTestRedis(t)
	db = newTestDB(t)
	s = NewTrafficService(db, mgr, newTestConfig())

	// 空队列
	if n, err := s.Consume(10); err != nil || n != 0 {
		t.Fatalf("empty queue: n=%d err=%v", n, err)
	}

	// 有效 + 坏数据（坏数据跳过）
	mr.Lpush("waf:traffic:list",
		`{"time":"2026-01-01T00:00:00Z","client_ip":"1.2.3.4","method":"GET","host":"a.com","uri":"/x","status":200,"attack":false}`)
	mr.Lpush("waf:traffic:list", `not-json`)

	n, err := s.Consume(10)
	if err != nil {
		t.Fatalf("consume: %v", err)
	}
	if n != 1 {
		t.Fatalf("expected 1, got %d", n)
	}
	var logs []model.TrafficLog
	db.Find(&logs)
	if len(logs) != 1 || logs[0].Host != "a.com" || logs[0].Status != 200 {
		t.Errorf("bad log: %+v", logs)
	}
}

func TestTrafficService_List(t *testing.T) {
	db := newTestDB(t)
	s := NewTrafficService(db, NewRedisManager(), newTestConfig())

	now := time.Now()
	db.Create(&model.TrafficLog{Time: now, ClientIP: "1.2.3.4", Host: "a.com", Status: 200, Attack: false})
	db.Create(&model.TrafficLog{Time: now, ClientIP: "5.6.7.8", Host: "b.com", Status: 403, Attack: true})
	db.Create(&model.TrafficLog{Time: now, ClientIP: "1.2.3.4", Host: "a.com", Status: 200, Attack: false})

	// 全量
	logs, total, err := s.List("", "", "", 1, 10)
	if err != nil || total != 3 || len(logs) != 3 {
		t.Fatalf("list all: total=%d len=%d err=%v", total, len(logs), err)
	}
	// host 过滤
	_, total, _ = s.List("a.com", "", "", 1, 10)
	if total != 2 {
		t.Errorf("host filter = %d", total)
	}
	// attack 过滤
	_, total, _ = s.List("", "", "1", 1, 10)
	if total != 1 {
		t.Errorf("attack filter = %d", total)
	}
	// ip 过滤
	_, total, _ = s.List("", "5.6.7.8", "", 1, 10)
	if total != 1 {
		t.Errorf("ip filter = %d", total)
	}
}

func TestTrafficService_Cleanup(t *testing.T) {
	db := newTestDB(t)
	s := NewTrafficService(db, NewRedisManager(), newTestConfig())

	db.Create(&model.TrafficLog{Time: time.Now().Add(-20 * 24 * time.Hour), ClientIP: "1.1.1.1"})
	db.Create(&model.TrafficLog{Time: time.Now().Add(-2 * 24 * time.Hour), ClientIP: "2.2.2.2"})

	n, err := s.Cleanup(7)
	if err != nil {
		t.Fatalf("cleanup: %v", err)
	}
	if n != 1 {
		t.Errorf("deleted = %d (should delete only 20-day-old)", n)
	}
	var remain int64
	db.Model(&model.TrafficLog{}).Count(&remain)
	if remain != 1 {
		t.Errorf("remain = %d", remain)
	}
	// 默认保留天数 7：不删除 2 天前的记录
	n, _ = s.Cleanup(0)
	if n != 0 {
		t.Errorf("cleanup default should keep 2-day-old, deleted %d", n)
	}
	// 保留 1 天：删除 2 天前的记录
	n, _ = s.Cleanup(1)
	if n != 1 {
		t.Errorf("cleanup 1-day should delete 2-day-old, got %d", n)
	}
	db.Model(&model.TrafficLog{}).Count(&remain)
	if remain != 0 {
		t.Errorf("remain = %d", remain)
	}
}

func TestTrafficService_Stats(t *testing.T) {
	db := newTestDB(t)
	s := NewTrafficService(db, NewRedisManager(), newTestConfig())
	db.Create(&model.TrafficLog{ClientIP: "1.1.1.1", Attack: true})
	db.Create(&model.TrafficLog{ClientIP: "1.1.1.1", Attack: false})
	total, attack, err := s.GetStats()
	if err != nil || total != 2 || attack != 1 {
		t.Errorf("stats: total=%d attack=%d err=%v", total, attack, err)
	}
}
