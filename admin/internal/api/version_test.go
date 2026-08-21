package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestAPIVersionAlias 验证 /api/v1 规范前缀与旧路径 /api 双挂载行为一致：
// 同一套处理器与中间件链，旧客户端零改造。
func TestAPIVersionAlias(t *testing.T) {
	db := newTestDB(t)
	r := newTestRouter(t, db, nil)

	// 公开探针：新旧前缀均可达
	for _, p := range []string{"/api/health", "/api/v1/health"} {
		w := doReq(r, httptest.NewRequest(http.MethodGet, p, nil))
		if w.Code != http.StatusOK {
			t.Fatalf("%s: got %d want 200", p, w.Code)
		}
	}

	// v1 前缀下登录成功（限流 + 认证处理器链完整复用）
	w := doReq(r, authedReq(http.MethodPost, "/api/v1/auth/login", "",
		map[string]string{"username": testAdminUser, "password": testAdminPass}))
	if w.Code != http.StatusOK {
		t.Fatalf("v1 login: %d %s", w.Code, w.Body.String())
	}
	var resp struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil || resp.Token == "" {
		t.Fatalf("v1 login empty token: %v", err)
	}

	// 从 v1 登录响应取 CSRF cookie，验证 v1 认证接口可用
	csrf := ""
	for _, ck := range w.Result().Cookies() {
		if ck.Name == csrfCookieName {
			csrf = ck.Value
		}
	}
	req := httptest.NewRequest(http.MethodGet, "/api/v1/auth/me", nil)
	req.Header.Set("Authorization", "Bearer "+resp.Token)
	req.AddCookie(&http.Cookie{Name: csrfCookieName, Value: csrf})
	req.Header.Set("X-CSRF-Token", csrf)
	w2 := doReq(r, req)
	if w2.Code != http.StatusOK {
		t.Fatalf("v1 auth/me: %d %s", w2.Code, w2.Body.String())
	}
}
