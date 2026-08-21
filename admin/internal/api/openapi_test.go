package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
)

// TestOpenAPISpec 验证规范生成：路径转换、参数、安全声明
func TestOpenAPISpec(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	h := NewOpenAPIHandler(nil)
	r.GET("/api/health", func(c *gin.Context) {})
	r.POST("/api/v1/users/:id/reset", func(c *gin.Context) {})
	r.GET("/api/openapi.json", h.SpecFor(r))

	w := doReq(r, httptest.NewRequest(http.MethodGet, "/api/openapi.json", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("spec: %d %s", w.Code, w.Body.String())
	}
	var spec map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &spec); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if spec["openapi"] != "3.0.3" {
		t.Fatalf("openapi version: %v", spec["openapi"])
	}
	paths, _ := spec["paths"].(map[string]interface{})
	if paths == nil {
		t.Fatal("empty paths")
	}

	// 公开端点：security 为空数组
	pub, ok := paths["/api/health"].(map[string]interface{})
	if !ok {
		t.Fatal("missing /api/health")
	}
	getOp := pub["get"].(map[string]interface{})
	if sec, ok := getOp["security"].([]interface{}); !ok || len(sec) != 0 {
		t.Fatalf("public path security: %v", getOp["security"])
	}

	// gin :id 参数转 {id}，受保护端点带双认证方案
	prot, ok := paths["/api/v1/users/{id}/reset"].(map[string]interface{})
	if !ok {
		t.Fatalf("missing converted path, have: %v", paths)
	}
	postOp := prot["post"].(map[string]interface{})
	params := postOp["parameters"].([]interface{})
	p0 := params[0].(map[string]interface{})
	if p0["name"] != "id" || p0["in"] != "path" || p0["required"] != true {
		t.Fatalf("path param: %v", p0)
	}
	sec := postOp["security"].([]interface{})
	if len(sec) != 2 {
		t.Fatalf("protected security schemes: %v", sec)
	}
}

// TestDocsPage 验证文档页输出：HTML、含路由与认证说明
func TestDocsPage(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	h := NewOpenAPIHandler(nil)
	r.GET("/api/health", func(c *gin.Context) {})
	r.DELETE("/api/rules/:id", func(c *gin.Context) {})
	r.GET("/api/docs", h.DocsFor(r))

	w := doReq(r, httptest.NewRequest(http.MethodGet, "/api/docs", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("docs: %d", w.Code)
	}
	ct := w.Header().Get("Content-Type")
	if ct != "text/html; charset=utf-8" {
		t.Fatalf("content-type: %s", ct)
	}
	body := w.Body.String()
	for _, want := range []string{"OpenResty WAF Admin API", "/api/health", "/api/rules/{id}", "X-API-Token"} {
		if !contains(body, want) {
			t.Fatalf("docs missing %q", want)
		}
	}
}

// TestOpenAPIWiredInRouter 全量路由下规范可用且包含业务端点（守卫 NewRouter 挂载）
func TestOpenAPIWiredInRouter(t *testing.T) {
	db := newTestDB(t)
	r := newTestRouter(t, db, nil)

	w := doReq(r, httptest.NewRequest(http.MethodGet, "/api/openapi.json", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("spec via router: %d", w.Code)
	}
	var spec struct {
		Paths map[string]json.RawMessage `json:"paths"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &spec); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	for _, p := range []string{"/api/rules/publish/canary", "/api/v1/auth/login", "/api/db/backup"} {
		if _, ok := spec.Paths[p]; !ok {
			t.Fatalf("spec missing %s", p)
		}
	}

	// 文档页两个前缀均可达
	for _, p := range []string{"/api/docs", "/api/v1/docs"} {
		w := doReq(r, httptest.NewRequest(http.MethodGet, p, nil))
		if w.Code != http.StatusOK {
			t.Fatalf("%s: %d", p, w.Code)
		}
	}
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && (func() bool {
		for i := 0; i+len(sub) <= len(s); i++ {
			if s[i:i+len(sub)] == sub {
				return true
			}
		}
		return false
	})()
}
