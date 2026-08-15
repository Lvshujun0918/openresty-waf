package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/alicebob/miniredis/v2"
	"github.com/gin-gonic/gin"
	"github.com/glebarez/sqlite"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"

	"openresty-waf/admin/internal/config"
	"openresty-waf/admin/internal/model"
	"openresty-waf/admin/internal/service"
)

const (
	testAdminUser = "admin"
	testAdminPass = "admin123"
)

// newTestDB 内存 SQLite + 全量迁移 + 默认管理员账号
func newTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	if err := db.AutoMigrate(&model.User{}, &model.Rule{},
		&model.Event{}, &model.Setup{}, &model.IpListSubscription{},
		&model.TrafficLog{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(testAdminPass), bcrypt.MinCost)
	if err != nil {
		t.Fatalf("bcrypt: %v", err)
	}
	if err := db.Create(&model.User{Username: testAdminUser, PasswordHash: string(hash)}).Error; err != nil {
		t.Fatalf("seed admin: %v", err)
	}
	return db
}

// newTestRedis 内存 Redis（miniredis）+ 已连接的 RedisManager
func newTestRedis(t *testing.T) (*miniredis.Miniredis, *service.RedisManager) {
	t.Helper()
	mr := miniredis.RunT(t)
	mgr := service.NewRedisManager()
	mgr.Replace(&service.RedisConfig{Addr: mr.Addr()})
	return mr, mgr
}

// newTestRouter 构建带测试模式的路由；mgr 为 nil 时用空 manager（等价"未配置 Redis"）
func newTestRouter(t *testing.T, db *gorm.DB, mgr *service.RedisManager) *gin.Engine {
	t.Helper()
	gin.SetMode(gin.TestMode)
	if mgr == nil {
		mgr = service.NewRedisManager()
	}
	return NewRouter(config.Load(), db, mgr)
}

// doLogin 登录并返回 Bearer token（同时缓存登录下发的 CSRF cookie，
// 供 authedReq 自动携带——CSRF 双提交校验的测试适配）
var testCSRF = ""

func doLogin(t *testing.T, r *gin.Engine) string {
	t.Helper()
	w := doReq(r, authedReq(http.MethodPost, "/api/auth/login", "",
		map[string]string{"username": testAdminUser, "password": testAdminPass}))
	if w.Code != http.StatusOK {
		t.Fatalf("login failed: %d %s", w.Code, w.Body.String())
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
		t.Fatal("empty token")
	}
	return resp.Token
}

// authedReq 构造请求；body 为 nil 时为空 body，token 为空则不携带 Authorization。
// 自动附带 CSRF cookie + X-CSRF-Token 头（双提交校验）。
func authedReq(method, path, token string, body interface{}) *http.Request {
	var rdr *bytes.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rdr = bytes.NewReader(b)
	} else {
		rdr = bytes.NewReader(nil)
	}
	req := httptest.NewRequest(method, path, rdr)
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if testCSRF != "" {
		req.AddCookie(&http.Cookie{Name: csrfCookieName, Value: testCSRF})
		req.Header.Set("X-CSRF-Token", testCSRF)
	}
	return req
}

// doReq 执行请求并返回 recorder
func doReq(r *gin.Engine, req *http.Request) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}
