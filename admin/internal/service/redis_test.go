package service

import "testing"

func TestRedisManager(t *testing.T) {
	m := NewRedisManager()

	if m.GetClient() != nil {
		t.Fatal("client should be nil initially")
	}

	m.Replace(&RedisConfig{Addr: "127.0.0.1:6379", DB: 0})
	if m.GetClient() == nil {
		t.Fatal("client should be set after Replace")
	}

	// 再次 Replace 不应 panic（旧连接关闭）
	m.Replace(&RedisConfig{Addr: "127.0.0.1:6379", DB: 1})
	if m.GetClient() == nil {
		t.Fatal("client should be set after second Replace")
	}
}
