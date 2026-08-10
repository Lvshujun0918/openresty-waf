package api

import (
	"encoding/json"
	"net/http"
	"testing"
)

// TestAuth_Login 登录接口：正确凭据 / 错误密码 / 缺字段 / 不存在用户
func TestAuth_Login(t *testing.T) {
	db := newTestDB(t)
	r := newTestRouter(t, db, nil)

	// 正确凭据
	if token := doLogin(t, r); token == "" {
		t.Fatal("token empty")
	}

	// 错误密码
	w := doReq(r, authedReq(http.MethodPost, "/api/auth/login", "",
		map[string]string{"username": testAdminUser, "password": "wrong"}))
	if w.Code != http.StatusUnauthorized {
		t.Errorf("wrong password: %d", w.Code)
	}

	// 缺字段
	w = doReq(r, authedReq(http.MethodPost, "/api/auth/login", "",
		map[string]string{"username": testAdminUser}))
	if w.Code != http.StatusBadRequest {
		t.Errorf("missing field: %d", w.Code)
	}

	// 不存在用户
	w = doReq(r, authedReq(http.MethodPost, "/api/auth/login", "",
		map[string]string{"username": "nobody", "password": "x"}))
	if w.Code != http.StatusUnauthorized {
		t.Errorf("unknown user: %d", w.Code)
	}
}

// TestAuth_Me 当前用户接口：带 token / 无 token / 无效 token
func TestAuth_Me(t *testing.T) {
	db := newTestDB(t)
	r := newTestRouter(t, db, nil)
	token := doLogin(t, r)

	w := doReq(r, authedReq(http.MethodGet, "/api/auth/me", token, nil))
	if w.Code != http.StatusOK {
		t.Fatalf("me: %d", w.Code)
	}
	var me struct {
		ID       float64 `json:"id"`
		Username string  `json:"username"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &me)
	if me.Username != testAdminUser {
		t.Errorf("username = %q", me.Username)
	}
	if me.ID == 0 {
		t.Error("id = 0")
	}

	// 无 token → 401
	w = doReq(r, authedReq(http.MethodGet, "/api/auth/me", "", nil))
	if w.Code != http.StatusUnauthorized {
		t.Errorf("no token: %d", w.Code)
	}

	// 无效 token → 401
	w = doReq(r, authedReq(http.MethodGet, "/api/auth/me", "invalid.token.value", nil))
	if w.Code != http.StatusUnauthorized {
		t.Errorf("bad token: %d", w.Code)
	}

	// 非 Bearer 前缀 → 401
	req := authedReq(http.MethodGet, "/api/auth/me", "", nil)
	req.Header.Set("Authorization", "Token "+token)
	w = doReq(r, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("non-bearer: %d", w.Code)
	}
}

// TestAuth_ProtectedEndpoints JWT 中间件对其它受保护端点同样生效
func TestAuth_ProtectedEndpoints(t *testing.T) {
	db := newTestDB(t)
	r := newTestRouter(t, db, nil)

	for _, p := range []string{"/api/rules", "/api/events", "/api/config"} {
		w := doReq(r, authedReq(http.MethodGet, p, "", nil))
		if w.Code != http.StatusUnauthorized {
			t.Errorf("%s without token: %d", p, w.Code)
		}
	}
}

// TestHealth 健康检查
func TestHealth(t *testing.T) {
	db := newTestDB(t)
	r := newTestRouter(t, db, nil)
	w := doReq(r, authedReq(http.MethodGet, "/api/health", "", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("health: %d", w.Code)
	}
	var resp map[string]string
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	if resp["status"] != "ok" {
		t.Errorf("status = %v", resp["status"])
	}
}
