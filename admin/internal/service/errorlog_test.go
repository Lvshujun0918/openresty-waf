package service

import (
	"context"
	"testing"

	"github.com/alicebob/miniredis/v2"
)

// pushError 推送一条引擎报错 JSON 到队列（模拟引擎 errlog.lua 上报）
func pushError(t *testing.T, srv *miniredis.Miniredis, mgr *RedisManager, raw string) {
	t.Helper()
	if err := mgr.GetClient().RPush(context.Background(), ErrorLogKey, raw).Err(); err != nil {
		t.Fatalf("rpush: %v", err)
	}
}

func TestErrorLogService_ConsumeAndList(t *testing.T) {
	srv, mgr := newTestRedis(t)
	db := newTestDB(t)
	svc := NewErrorLogService(db, mgr, newTestConfig())

	pushError(t, srv, mgr, `{"time":"2026-08-21T10:00:00+08:00","level":"error","source":"access","message":"规则引擎执行异常，fail-open 放行: boom","req_id":"1-100-5-1","client_ip":"8.8.8.8","host":"a.com","uri":"/x?y=1","engine_version":"1.0"}`)
	pushError(t, srv, mgr, `{"level":"warn","source":"operators","message":"正则执行错误: timeout pattern=(.)+x"}`)

	n, err := svc.Consume(200)
	if err != nil {
		t.Fatalf("Consume: %v", err)
	}
	if n != 2 {
		t.Fatalf("期望消费 2 条，实际 %d", n)
	}
	// 队列已空
	if n, _ := svc.Consume(200); n != 0 {
		t.Fatalf("二次消费应为 0，实际 %d", n)
	}

	logs, total, err := svc.List("", "", "", 1, 20)
	if err != nil || total != 2 {
		t.Fatalf("List total=%d err=%v", total, err)
	}
	if logs[0].Source != "access" {
		t.Fatalf("应按 id desc 排序，首条 source=%s", logs[0].Source)
	}

	// level 过滤
	_, totalWarn, _ := svc.List("warn", "", "", 1, 20)
	if totalWarn != 1 {
		t.Fatalf("warn 过滤 total=%d", totalWarn)
	}
	// 关键字命中 client_ip
	_, totalKw, _ := svc.List("", "", "8.8.8.8", 1, 20)
	if totalKw != 1 {
		t.Fatalf("关键字过滤 total=%d", totalKw)
	}
	// source 过滤
	_, totalSrc, _ := svc.List("", "access", "", 1, 20)
	if totalSrc != 1 {
		t.Fatalf("source 过滤 total=%d", totalSrc)
	}
}

func TestErrorLogService_StatsAndClear(t *testing.T) {
	srv, mgr := newTestRedis(t)
	db := newTestDB(t)
	svc := NewErrorLogService(db, mgr, newTestConfig())

	pushError(t, srv, mgr, `{"level":"error","source":"access","message":"m1"}`)
	pushError(t, srv, mgr, `{"level":"error","source":"init","message":"m2"}`)
	pushError(t, srv, mgr, `{"level":"warn","source":"upload","message":"m3"}`)
	if _, err := svc.Consume(200); err != nil {
		t.Fatalf("Consume: %v", err)
	}

	stats, err := svc.Stats()
	if err != nil {
		t.Fatalf("Stats: %v", err)
	}
	if stats["error"] != 2 || stats["warn"] != 1 {
		t.Fatalf("统计错误 error=%d warn=%d", stats["error"], stats["warn"])
	}

	if err := svc.Clear(); err != nil {
		t.Fatalf("Clear: %v", err)
	}
	_, total, _ := svc.List("", "", "", 1, 20)
	if total != 0 {
		t.Fatalf("清空后 total=%d", total)
	}
}

func TestErrorLogService_ConsumeWithoutRedis(t *testing.T) {
	svc := NewErrorLogService(newTestDB(t), &RedisManager{}, newTestConfig())
	if _, err := svc.Consume(10); err == nil {
		t.Fatal("Redis 未配置应报错")
	}
}
