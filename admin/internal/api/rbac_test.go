package api

import (
	"encoding/json"
	"net/http"
	"testing"

	"golang.org/x/crypto/bcrypt"

	"openresty-waf/admin/internal/model"
	"openresty-waf/admin/internal/service"
)

func TestModuleForPath(t *testing.T) {
	cases := []struct {
		path   string
		module string
	}{
		{"/api/tokens", service.PermSystem},
		{"/api/tokens/3", service.PermSystem},
		{"/api/users", service.PermSystem},
		{"/api/users/5", service.PermSystem},
		{"/api/db/backup", service.PermSystem},
		{"/api/setup/redis", service.PermSystem},
		{"/api/rules", service.PermRules},
		{"/api/rules/publish", service.PermRules},
		{"/api/rules/perf", service.PermRules},
		{"/api/trigger-rules/1/enabled", service.PermRules},
		{"/api/ip-list-subs/1/sync", service.PermProtection},
		{"/api/bans", service.PermProtection},
		{"/api/events/9/ban", service.PermProtection},
		{"/api/bots/fingerprints", service.PermProtection},
		{"/api/ja4/profiles", service.PermProtection},
		{"/api/alerts/channels", service.PermAlerts},
		{"/api/config", service.PermConfig},
		{"/api/traffic/cleanup", service.PermMonitor},
		{"/api/cc-logs/consume", service.PermMonitor},
		{"/api/auth/me", ""},
		{"/api/dashboard/stats", ""},
		{"/api/audit-logs", ""},
		{"/api/setup/guide", ""},
	}
	for _, tc := range cases {
		if got := service.ModuleForPath(tc.path); got != tc.module {
			t.Errorf("ModuleForPath(%q) = %q, want %q", tc.path, got, tc.module)
		}
	}
}

func TestCanWriteMatrix(t *testing.T) {
	if !service.CanWrite(service.RoleSuper, service.PermSystem) {
		t.Error("super 应可写 system")
	}
	if !service.CanWrite(service.RoleSuper, service.PermRules) {
		t.Error("super 应可写 rules")
	}
	for _, m := range []string{service.PermRules, service.PermProtection, service.PermAlerts, service.PermConfig, service.PermMonitor} {
		if !service.CanWrite(service.RoleOps, m) {
			t.Errorf("ops 应可写 %s", m)
		}
	}
	if service.CanWrite(service.RoleOps, service.PermSystem) {
		t.Error("ops 不可写 system")
	}
	if service.CanWrite(service.RoleViewer, service.PermRules) || service.CanWrite(service.RoleViewer, service.PermMonitor) {
		t.Error("viewer 只读，不可写任何模块")
	}
	if !service.CanRead(service.RoleOps, service.PermRules) {
		t.Error("ops 可读业务模块")
	}
	if service.CanRead(service.RoleViewer, service.PermSystem) || service.CanRead(service.RoleOps, service.PermSystem) {
		t.Error("system 模块读仅限 super")
	}
}

func TestRBACEndToEnd(t *testing.T) {
	db := newTestDB(t)
	_, mgr := newTestRedis(t)
	r := newTestRouter(t, db, mgr)

	// 建两个非 super 账号（直接写库，密码与 admin 相同便于复用登录流程）
	mkUser := func(name, role string) {
		hash, err := bcrypt.GenerateFromPassword([]byte(testAdminPass), bcrypt.MinCost)
		if err != nil {
			t.Fatalf("bcrypt: %v", err)
		}
		if err := db.Create(&model.User{Username: name, PasswordHash: string(hash), Role: role}).Error; err != nil {
			t.Fatalf("seed %s: %v", name, err)
		}
	}
	mkUser("ops1", service.RoleOps)
	mkUser("viewer1", service.RoleViewer)

	loginAs := func(name string) string {
		w := doReq(r, authedReq(http.MethodPost, "/api/auth/login", "",
			map[string]string{"username": name, "password": testAdminPass}))
		if w.Code != http.StatusOK {
			t.Fatalf("login %s failed: %d %s", name, w.Code, w.Body.String())
		}
		for _, ck := range w.Result().Cookies() {
			if ck.Name == csrfCookieName {
				testCSRF = ck.Value
			}
		}
		var resp struct {
			Token string `json:"token"`
		}
		_ = json.Unmarshal(w.Body.Bytes(), &resp)
		if resp.Token == "" {
			t.Fatalf("login %s: empty token", name)
		}
		return resp.Token
	}

	superTok := doLogin(t, r)
	opsTok := loginAs("ops1")
	viewerTok := loginAs("viewer1")

	// super：创建用户成功
	w := doReq(r, authedReq(http.MethodPost, "/api/users", superTok,
		map[string]string{"username": "u2", "password": "password123", "role": "ops"}))
	if w.Code != http.StatusOK {
		t.Fatalf("super 创建用户应成功: %d %s", w.Code, w.Body.String())
	}

	// ops：业务写放行（RBAC 通过后进入 handler；此处仅断言未被 RBAC 拦截）
	w = doReq(r, authedReq(http.MethodPost, "/api/bans", opsTok,
		map[string]string{"ip": "9.9.9.9"}))
	if w.Code == http.StatusForbidden {
		t.Fatalf("ops 写 bans 不应被 RBAC 拦截: %s", w.Body.String())
	}
	// ops：system 读/写均拒绝
	w = doReq(r, authedReq(http.MethodGet, "/api/users", opsTok, nil))
	if w.Code != http.StatusForbidden {
		t.Fatalf("ops GET /users 应 403: %d", w.Code)
	}
	w = doReq(r, authedReq(http.MethodPost, "/api/tokens", opsTok,
		map[string]string{"name": "x"}))
	if w.Code != http.StatusForbidden {
		t.Fatalf("ops POST /tokens 应 403: %d", w.Code)
	}
	w = doReq(r, authedReq(http.MethodGet, "/api/db/backup", opsTok, nil))
	if w.Code != http.StatusForbidden {
		t.Fatalf("ops GET /db/backup 应 403: %d", w.Code)
	}

	// viewer：查询放行、写全拒
	w = doReq(r, authedReq(http.MethodGet, "/api/events", viewerTok, nil))
	if w.Code == http.StatusForbidden {
		t.Fatal("viewer 查询 events 不应被 RBAC 拦截")
	}
	w = doReq(r, authedReq(http.MethodPost, "/api/rules", viewerTok,
		map[string]interface{}{"id": "99999"}))
	if w.Code != http.StatusForbidden {
		t.Fatalf("viewer POST /rules 应 403: %d", w.Code)
	}
	w = doReq(r, authedReq(http.MethodPost, "/api/events/1/false-positive", viewerTok, nil))
	if w.Code != http.StatusForbidden {
		t.Fatalf("viewer 事件处置应 403: %d", w.Code)
	}

	// super：system 全通
	w = doReq(r, authedReq(http.MethodGet, "/api/users", superTok, nil))
	if w.Code != http.StatusOK {
		t.Fatalf("super GET /users 应 200: %d %s", w.Code, w.Body.String())
	}
}

func TestUserHandlerGuards(t *testing.T) {
	db := newTestDB(t)
	_, mgr := newTestRedis(t)
	r := newTestRouter(t, db, mgr)
	superTok := doLogin(t, r)

	// 创建 ops 账号并登录
	w := doReq(r, authedReq(http.MethodPost, "/api/users", superTok,
		map[string]string{"username": "op2", "password": "password123", "role": "ops"}))
	if w.Code != http.StatusOK {
		t.Fatalf("create op2: %d %s", w.Code, w.Body.String())
	}

	// 非法角色拒绝
	w = doReq(r, authedReq(http.MethodPost, "/api/users", superTok,
		map[string]string{"username": "bad", "password": "password123", "role": "root"}))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("非法角色应 400: %d", w.Code)
	}

	// 短密码拒绝
	w = doReq(r, authedReq(http.MethodPost, "/api/users", superTok,
		map[string]string{"username": "shortpw", "password": "123", "role": "viewer"}))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("短密码应 400: %d", w.Code)
	}

	// 不能修改自己的角色（admin id=1）
	w = doReq(r, authedReq(http.MethodPut, "/api/users/1", superTok,
		map[string]string{"role": "viewer"}))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("修改自己角色应 400: %d %s", w.Code, w.Body.String())
	}

	// 不能删除自己
	w = doReq(r, authedReq(http.MethodDelete, "/api/users/1", superTok, nil))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("删除自己应 400: %d", w.Code)
	}

	// 唯一 super 保护：降级 admin（唯一 super）应被拒
	var cnt int64
	db.Model(&model.User{}).Where("role = ?", service.RoleSuper).Count(&cnt)
	if cnt == 1 {
		w = doReq(r, authedReq(http.MethodPut, "/api/users/1", superTok,
			map[string]string{"role": "ops"}))
		if w.Code != http.StatusBadRequest {
			t.Fatalf("降级唯一 super 应 400: %d", w.Code)
		}
	}

	// 重置他人密码成功
	var op2 model.User
	db.Where("username = ?", "op2").First(&op2)
	idBytes, _ := json.Marshal(op2.ID)
	w = doReq(r, authedReq(http.MethodPut, "/api/users/"+string(idBytes), superTok,
		map[string]string{"password": "newpassword9"}))
	if w.Code != http.StatusOK {
		t.Fatalf("重置密码应 200: %d %s", w.Code, w.Body.String())
	}
}
