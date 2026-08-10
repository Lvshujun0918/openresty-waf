package api

import (
	"archive/tar"
	"compress/gzip"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"

	"openresty-waf/admin/internal/config"
	"openresty-waf/admin/internal/service"
)

type SetupHandler struct {
	svc     *service.SetupService
	distDir string
}

func NewSetupHandler(db *gorm.DB, mgr *service.RedisManager, cfg *config.Config) *SetupHandler {
	return &SetupHandler{svc: service.NewSetupService(db, mgr), distDir: cfg.WAF.DistDir}
}

// Status GET /api/setup/status 引导状态
func (h *SetupHandler) Status(c *gin.Context) {
	redisCfg, ok := h.svc.GetRedisConfig()
	c.JSON(http.StatusOK, gin.H{
		"done":              h.svc.IsDone(),
		"redis_configured":  ok,
		"redis_addr":        func() string { if ok { return redisCfg.Addr }; return "" }(),
	})
}

type redisReq struct {
	Addr     string `json:"addr" binding:"required"`
	Password string `json:"password"`
	DB       int    `json:"db"`
}

// SaveRedis POST /api/setup/redis 测试并保存 Redis 配置
func (h *SetupHandler) SaveRedis(c *gin.Context) {
	var req redisReq
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "参数错误"})
		return
	}
	if err := h.svc.SaveRedisConfig(req.Addr, req.Password, req.DB); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}

// Guide GET /api/setup/guide 返回本机 OpenResty 接入指引
func (h *SetupHandler) Guide(c *gin.Context) {
	redisCfg, ok := h.svc.GetRedisConfig()
	if !ok {
		c.JSON(http.StatusBadRequest, gin.H{"error": "请先完成 Redis 配置"})
		return
	}
	adminURL := c.Query("admin")
	if adminURL == "" {
		adminURL = "http://" + c.Request.Host
	}
	installCmd := fmt.Sprintf(
		"curl -fsSL %s/api/setup/install.sh | bash -s -- %s %s %s %d",
		adminURL, adminURL, redisCfg.Addr, redisCfg.Password, redisCfg.DB)
	c.JSON(http.StatusOK, gin.H{
		"redis":           redisCfg,
		"install_command": installCmd,
		"download_url":    adminURL + "/api/setup/waf.tar.gz",
		"nginx_config":    nginxSnippet,
	})
}

// DownloadWAF GET /api/setup/waf.tar.gz 打包 WAF Lua 组件
func (h *SetupHandler) DownloadWAF(c *gin.Context) {
	dir := h.distDir
	fi, err := os.Stat(dir)
	if err != nil || !fi.IsDir() {
		c.String(http.StatusNotFound, "WAF 组件目录不存在（Docker 镜像默认含于 /opt/waf-dist）")
		return
	}
	c.Header("Content-Type", "application/gzip")
	c.Header("Content-Disposition", `attachment; filename="waf.tar.gz"`)

	gz := gzip.NewWriter(c.Writer)
	tw := tar.NewWriter(gz)

	_ = filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil // 忽略目录与错误
		}
		rel, _ := filepath.Rel(dir, path)
		rel = filepath.ToSlash(rel)
		// 跳过 .git 与测试目录（t/ 仅本地单测用，不随组件分发）
		if strings.Contains(rel, ".git/") || rel == "t" || strings.HasPrefix(rel, "t/") {
			return nil
		}
		data, rerr := os.ReadFile(path)
		if rerr != nil {
			return nil
		}
		// tar 内路径不加前缀目录：解压到安装目录（如 /opt/waf）后直接平铺，
		// 使 init.lua 位于 /opt/waf/init.lua，与 nginx 配置引用一致。
		hdr := &tar.Header{
			Name: rel,
			Mode: int64(info.Mode().Perm()),
			Size: int64(len(data)),
		}
		if err := tw.WriteHeader(hdr); err != nil {
			return err
		}
		_, err = tw.Write(data)
		return err
	})
	_ = tw.Close()
	_ = gz.Close()
}

// InstallScript GET /api/setup/install.sh 一键接入脚本
func (h *SetupHandler) InstallScript(c *gin.Context) {
	c.Header("Content-Type", "application/x-sh; charset=utf-8")
	_, _ = c.Writer.WriteString(installScript)
}

// nginxSnippet OpenResty 接入配置片段
const nginxSnippet = `# OpenResty WAF 接入（管理后台自动生成，加入 nginx.conf 的 http {} 段）
lua_package_path "/opt/waf/?.lua;;";
lua_shared_dict waf_rule 20m;
lua_shared_dict waf_counter 50m;
init_by_lua_file /opt/waf/init.lua;
init_worker_by_lua_file /opt/waf/init.lua;
# 在需要防护的 server / location 内追加：
#   access_by_lua_file /opt/waf/access.lua;
#   log_by_lua_file    /opt/waf/log.lua;`

// installScript 一键接入本机 OpenResty 的脚本
const installScript = `#!/bin/bash
# OpenResty WAF 一键接入脚本（管理后台引导页生成）
# 用法: bash install.sh <管理后台地址> [Redis地址] [Redis密码] [RedisDB] [安装目录]
set -euo pipefail

ADMIN_URL="${1:-}"
REDIS_ADDR="${2:-127.0.0.1:6379}"
REDIS_PASSWORD="${3:-}"
REDIS_DB="${4:-0}"
INSTALL_DIR="${5:-/opt/waf}"

if [ -z "$ADMIN_URL" ]; then
  echo "用法: bash install.sh <管理后台地址> [Redis地址] [Redis密码] [RedisDB] [安装目录]"
  echo "示例: bash install.sh http://192.168.1.10:18081 192.168.1.20:6379 '' 0 /opt/waf"
  exit 1
fi

echo "[1/4] 下载 WAF 组件..."
mkdir -p "$INSTALL_DIR"
if ! curl -fsSL "$ADMIN_URL/api/setup/waf.tar.gz" | tar xz -C "$INSTALL_DIR"; then
  echo "下载失败，请确认管理后台地址可访问: $ADMIN_URL"
  exit 1
fi

# 兼容旧版包结构：若解压后多了一层 waf/ 子目录则上移到安装目录
if [ -f "$INSTALL_DIR/waf/init.lua" ] && [ ! -f "$INSTALL_DIR/init.lua" ]; then
  echo "  检测到旧版包结构，整理目录..."
  mv "$INSTALL_DIR/waf"/* "$INSTALL_DIR/"
  rm -rf "$INSTALL_DIR/waf"
fi
if [ ! -f "$INSTALL_DIR/init.lua" ]; then
  echo "组件解压异常：$INSTALL_DIR 下未找到 init.lua"
  exit 1
fi

echo "[2/4] 生成本地 Redis 配置..."
HOST="${REDIS_ADDR%%:*}"
PORT="${REDIS_ADDR##*:}"
if [ "$PORT" = "$REDIS_ADDR" ]; then PORT=6379; fi
if [ -n "$REDIS_PASSWORD" ]; then
  PASS="[[$REDIS_PASSWORD]]"
else
  PASS="nil"
fi
cat > "$INSTALL_DIR/config_local.lua" <<EOF
-- 由 OpenResty WAF 接入脚本生成（深合并覆盖 config.lua）
return { redis = { host = [[$HOST]], port = $PORT, password = $PASS, db = $REDIS_DB },
         log = { backend = "redis", redis_key = "waf:event:list" } }
EOF

echo "[3/4] 生成 nginx 接入配置..."
cat > "$INSTALL_DIR/waf-nginx.conf" <<EOF
# OpenResty WAF 接入配置（复制到 nginx.conf 的 http {} 段）
lua_package_path "$INSTALL_DIR/?.lua;;";
lua_shared_dict waf_rule 20m;
lua_shared_dict waf_counter 50m;
init_by_lua_file $INSTALL_DIR/init.lua;
init_worker_by_lua_file $INSTALL_DIR/init.lua;
# 在需要防护的 server/location 内追加：
#   access_by_lua_file $INSTALL_DIR/access.lua;
#   log_by_lua_file    $INSTALL_DIR/log.lua;
EOF

echo "[4/4] 完成"
echo "  WAF 组件:   $INSTALL_DIR"
echo "  Redis:      $REDIS_ADDR (db=$REDIS_DB)"
echo "  下一步: 将 $INSTALL_DIR/waf-nginx.conf 内容加入 nginx.conf，"
echo "          在目标 server/location 加 access_by_lua_file / log_by_lua_file，"
echo "          然后执行: nginx -t && nginx -s reload"
`
