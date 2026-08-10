package api

import (
	"archive/tar"
	"compress/gzip"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"openresty-waf/admin/internal/config"
	"openresty-waf/admin/internal/service"
)

// TestSetup_Status 初始引导状态
func TestSetup_Status(t *testing.T) {
	db := newTestDB(t)
	r := newTestRouter(t, db, nil)

	w := doReq(r, httptest.NewRequest(http.MethodGet, "/api/setup/status", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status: %d", w.Code)
	}
	var s struct {
		Done bool `json:"done"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &s)
	if s.Done {
		t.Error("should not be done initially")
	}
}

// TestSetup_SaveRedisAndGuide 保存 Redis → 状态完成 → 接入指引可读
func TestSetup_SaveRedisAndGuide(t *testing.T) {
	db := newTestDB(t)
	mr, mgr := newTestRedis(t)
	r := newTestRouter(t, db, mgr)
	token := doLogin(t, r)

	// 未配置时 guide → 400
	w := doReq(r, httptest.NewRequest(http.MethodGet, "/api/setup/guide", nil))
	if w.Code != http.StatusBadRequest {
		t.Errorf("guide pre: %d", w.Code)
	}

	// 未登录保存 Redis → 401
	w = doReq(r, authedReq(http.MethodPost, "/api/setup/redis", "",
		map[string]interface{}{"addr": mr.Addr()}))
	if w.Code != http.StatusUnauthorized {
		t.Errorf("save redis unauth: %d", w.Code)
	}

	// 登录保存 Redis
	w = doReq(r, authedReq(http.MethodPost, "/api/setup/redis", token,
		map[string]interface{}{"addr": mr.Addr()}))
	if w.Code != http.StatusOK {
		t.Fatalf("save redis: %d %s", w.Code, w.Body.String())
	}

	// 状态完成
	w = doReq(r, httptest.NewRequest(http.MethodGet, "/api/setup/status", nil))
	var s struct {
		Done            bool `json:"done"`
		RedisConfigured bool `json:"redis_configured"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &s)
	if !s.Done || !s.RedisConfigured {
		t.Errorf("status after save: %s", w.Body.String())
	}

	// 指引 200 且含安装命令与下载地址
	w = doReq(r, httptest.NewRequest(http.MethodGet, "/api/setup/guide", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("guide: %d", w.Code)
	}
	var g struct {
		Redis          map[string]interface{} `json:"redis"`
		InstallCommand string                 `json:"install_command"`
		DownloadURL    string                 `json:"download_url"`
		NginxConfig    string                 `json:"nginx_config"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &g)
	if g.Redis["addr"] != mr.Addr() {
		t.Errorf("guide redis addr = %v", g.Redis["addr"])
	}
	if !strings.Contains(g.InstallCommand, mr.Addr()) {
		t.Errorf("install command missing addr: %s", g.InstallCommand)
	}
	if !strings.Contains(g.DownloadURL, "/api/setup/waf.tar.gz") {
		t.Errorf("download url = %s", g.DownloadURL)
	}
	if !strings.Contains(g.NginxConfig, "lua_package_path") {
		t.Error("nginx config missing lua_package_path")
	}

	// 缺字段 → 400
	w = doReq(r, authedReq(http.MethodPost, "/api/setup/redis", token,
		map[string]interface{}{}))
	if w.Code != http.StatusBadRequest {
		t.Errorf("save redis empty: %d", w.Code)
	}

	// 无法连接的地址 → 400（连接失败）
	w = doReq(r, authedReq(http.MethodPost, "/api/setup/redis", token,
		map[string]interface{}{"addr": "127.0.0.1:1"}))
	if w.Code != http.StatusBadRequest {
		t.Errorf("save redis bad addr: %d %s", w.Code, w.Body.String())
	}
}

// TestSetup_Downloads 组件下载与安装脚本
func TestSetup_Downloads(t *testing.T) {
	db := newTestDB(t)
	r := newTestRouter(t, db, nil)

	// WAF 目录不存在 → 404
	w := doReq(r, httptest.NewRequest(http.MethodGet, "/api/setup/waf.tar.gz", nil))
	if w.Code != http.StatusNotFound {
		t.Errorf("waf.tar.gz: %d", w.Code)
	}

	// 安装脚本 → 200 且为 shell
	w = doReq(r, httptest.NewRequest(http.MethodGet, "/api/setup/install.sh", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("install.sh: %d", w.Code)
	}
	body := w.Body.String()
	if !strings.Contains(body, "#!/bin/bash") {
		t.Error("install script missing shebang")
	}
	if !strings.Contains(body, "waf.tar.gz") {
		t.Error("install script missing download")
	}
	// 更新场景：保留已有 config_local.lua + FORCE=1 重新生成 + 提示 reload
	if !strings.Contains(body, "config_local.lua") {
		t.Error("install script missing config_local handling")
	}
	if !strings.Contains(body, "FORCE=1") {
		t.Error("install script missing FORCE=1 regen option")
	}
	if !strings.Contains(body, "nginx -s reload") {
		t.Error("install script missing reload hint")
	}
}

// TestSetup_DownloadWAFContent 打包内容：tar 内平铺（无 waf/ 前缀目录），
// 排除测试目录 t/ 与 .git
func TestSetup_DownloadWAFContent(t *testing.T) {
	dir := t.TempDir()
	write := func(p, content string) {
		p = filepath.Join(dir, p)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("init.lua", "-- init")
	write("rule_engine/engine.lua", "-- engine")
	write("t/run.lua", "-- test")         // 应被排除
	write(".git/config", "x")             // 应被排除
	write("detectors/cc.lua", "-- cc")

	cfg := config.Load()
	cfg.WAF.DistDir = dir
	db := newTestDB(t)
	h := NewSetupHandler(db, service.NewRedisManager(), cfg)

	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.GET("/api/setup/waf.tar.gz", h.DownloadWAF)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/setup/waf.tar.gz", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("download: %d", w.Code)
	}

	gz, err := gzip.NewReader(w.Body)
	if err != nil {
		t.Fatal(err)
	}
	tr := tar.NewReader(gz)
	var names []string
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		names = append(names, hdr.Name)
	}

	has := func(name string) bool {
		for _, n := range names {
			if n == name {
				return true
			}
		}
		return false
	}

	// 平铺结构：根目录直接含 init.lua 等，无 waf/ 前缀
	if !has("init.lua") {
		t.Errorf("missing init.lua, names=%v", names)
	}
	if !has("rule_engine/engine.lua") {
		t.Errorf("missing rule_engine/engine.lua, names=%v", names)
	}
	if !has("detectors/cc.lua") {
		t.Errorf("missing detectors/cc.lua, names=%v", names)
	}
	// 不应存在带 waf/ 前缀、t/ 或 .git 的条目
	if has("waf/init.lua") {
		t.Errorf("unexpected waf/ prefix, names=%v", names)
	}
	if has("t/run.lua") || has("t") {
		t.Errorf("test dir should be excluded, names=%v", names)
	}
	if has(".git/config") {
		t.Errorf(".git should be excluded, names=%v", names)
	}
}
