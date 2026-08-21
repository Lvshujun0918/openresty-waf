package service

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestApiTokenLifecycle(t *testing.T) {
	svc := NewApiTokenService(newTestDB(t))

	// 创建：明文仅返回一次，前缀可识别
	tok, plain, err := svc.Create("ci-deploy")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if len(plain) < 16 || plain[:4] != "waf_" {
		t.Fatalf("明文格式异常: %q", plain[:min(8, len(plain))])
	}
	if tok.Prefix != plain[:12] || tok.TokenHash == "" {
		t.Fatalf("Prefix/TokenHash 未正确落库")
	}

	// 校验：有效令牌通过，返回名称
	name, err := svc.Verify(plain)
	if err != nil || name != "ci-deploy" {
		t.Fatalf("Verify: name=%q err=%v", name, err)
	}

	// 校验：非法令牌拒绝
	if _, err := svc.Verify("waf_deadbeef"); err == nil {
		t.Fatal("伪造令牌不应通过")
	}
	if _, err := svc.Verify(""); err == nil {
		t.Fatal("空令牌不应通过")
	}
	if _, err := svc.Verify(plain + "x"); err == nil {
		t.Fatal("篡改令牌不应通过")
	}

	// 吊销后拒绝
	if err := svc.Revoke(tok.ID); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	if _, err := svc.Verify(plain); err == nil {
		t.Fatal("已吊销令牌不应通过")
	}
	if err := svc.Revoke(tok.ID); err == nil {
		t.Fatal("重复吊销应报不存在")
	}
}

func TestApiTokenListHidesHash(t *testing.T) {
	svc := NewApiTokenService(newTestDB(t))
	if _, _, err := svc.Create("a"); err != nil {
		t.Fatalf("Create: %v", err)
	}
	list, err := svc.List()
	if err != nil || len(list) != 1 {
		t.Fatalf("List: n=%d err=%v", len(list), err)
	}
	// json:"-" 才是安全边界：序列化结果不得含哈希字段
	data, err := json.Marshal(list)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if strings.Contains(string(data), "token_hash") || strings.Contains(string(data), "TokenHash") {
		t.Fatal("列表 JSON 不得泄露 TokenHash")
	}
}
