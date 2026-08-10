package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
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
	if !strings.Contains(w.Body.String(), "#!/bin/bash") {
		t.Error("install script missing shebang")
	}
	if !strings.Contains(w.Body.String(), "waf.tar.gz") {
		t.Error("install script missing download")
	}
}
