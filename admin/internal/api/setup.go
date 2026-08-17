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
	// 选项式参数：-a 地址 -d 库号，无密码时不传 -p，避免"无密码直接填库号"被误判为密码
	installCmd := fmt.Sprintf(
		"curl -fsSL %s/api/setup/install.sh | bash -s -- %s -a %s -d %d",
		adminURL, adminURL, redisCfg.Addr, redisCfg.DB)
	if redisCfg.Password != "" {
		installCmd += " -p " + shQuote(redisCfg.Password)
	}
	// 强制覆盖命令：加 -f 使脚本重新生成 config_local.lua（修改 Redis 后快速同步下游引擎）
	installCmdForce := installCmd + " -f"
	c.JSON(http.StatusOK, gin.H{
		// redis 配置脱敏返回：密码不回显（安装命令中已含实际密码，仅登录用户可见）
		"redis": map[string]interface{}{
			"addr":     redisCfg.Addr,
			"db":       redisCfg.DB,
			"password": maskSecret(redisCfg.Password),
		},
		"install_command":       installCmd,
		"install_command_force": installCmdForce,
		"download_url":          adminURL + "/api/setup/waf.tar.gz",
		"nginx_config":          nginxSnippet,
	})
}

// maskSecret 密码类字段脱敏：非空时显示为掩码（无明文回显）
func maskSecret(s string) string {
	if s == "" {
		return ""
	}
	return "******"
}

// shQuote 单引号包裹并转义，保证密码含特殊字符时在 bash 中安全传递
func shQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
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
lua_package_path  "/opt/waf/?.lua;;";
lua_package_cpath "/opt/waf/?.so;;";
lua_shared_dict waf_rule 20m;
lua_shared_dict waf_counter 50m;
init_by_lua_file /opt/waf/init.lua;
init_worker_by_lua_file /opt/waf/init.lua;
# 慢速攻击防护（http 段）：读头/读体超时与 body 缓冲上限
#   client_header_timeout 10s;   # slowloris：请求头读超时
#   client_body_timeout   30s;   # 慢 body 传输超时
#   client_body_buffer_size 128k;# 超过则落盘，WAF 仍扫描前 512KB（见 config.lua upload.spooled_scan_bytes）
#   send_timeout 30s;
# 在需要防护的 server / location 内追加：
#   access_by_lua_file /opt/waf/access.lua;
#   log_by_lua_file    /opt/waf/log.lua;
# 可选（响应检测）：
#   header_filter_by_lua_file /opt/waf/header_filter.lua;
#   body_filter_by_lua_file   /opt/waf/body_filter.lua;`

// installScript 一键接入/更新本机 OpenResty 的脚本
// 支持两种场景：
//   - 首次安装：/opt/waf 不存在 → 全新解压并生成 config_local.lua
//   - 更新组件：/opt/waf 已存在 → 覆盖更新组件文件，保留已有 config_local.lua
//     （如需同步覆盖 Redis 配置，加 -f / --force 参数 或 FORCE=1 环境变量）
const installScript = `#!/bin/bash
# OpenResty WAF 一键接入 / 更新脚本（管理后台引导页生成）
# 用法（推荐，无歧义）:
#   bash install.sh <管理后台地址> -a <Redis地址> [-p <Redis密码>] [-d <库号>] [-i <安装目录>] [-f]
# 兼容旧式（需提供完整参数，避免密码/库号错位）:
#   bash install.sh <管理后台地址> <Redis地址> <Redis密码> <RedisDB> [安装目录]
# 更新组件时默认保留已有 config_local.lua；加 -f/--force（或 FORCE=1）则按本次参数重新生成 Redis 配置
set -euo pipefail

ADMIN_URL="${1:-}"
shift || true

# ---- 参数解析：优先选项式；兼容完整的位置式 ----
REDIS_ADDR="127.0.0.1:6379"
REDIS_PASSWORD=""
REDIS_DB="0"
INSTALL_DIR="/opt/waf"

if [ "$#" -ge 1 ] && [ "${1#-}" = "$1" ]; then
  # 位置式兼容（旧命令）：需提供完整的 <地址> <密码> <库号>，
  # 少于 3 个值时无法区分「密码」和「数据库编号」，明确报错避免错位
  case "$#" in
    1|2)
      echo "错误：位置式参数需完整提供 <Redis地址> <密码> <库号>，仅 $# 个无法区分，请改用选项式：" >&2
      echo "  bash install.sh <管理后台地址> -a <Redis地址> [-p <密码>] [-d <库号>]" >&2
      exit 1
      ;;
    *)
      REDIS_ADDR="$1"
      REDIS_PASSWORD="$2"
      REDIS_DB="${3:-0}"
      INSTALL_DIR="${4:-/opt/waf}"
      ;;
  esac
else
  while [ "$#" -gt 0 ]; do
    case "$1" in
      -a|--addr) REDIS_ADDR="${2:-}"; shift 2 ;;
      -p|--password) REDIS_PASSWORD="${2:-}"; shift 2 ;;
      -d|--db) REDIS_DB="${2:-0}"; shift 2 ;;
      -i|--install-dir) INSTALL_DIR="${2:-/opt/waf}"; shift 2 ;;
      -f|--force) FORCE=1; shift ;;
      *) echo "忽略未知选项: $1" >&2; shift ;;
    esac
  done
fi

if [ -z "$ADMIN_URL" ]; then
  echo "用法: bash install.sh <管理后台地址> -a <Redis地址> [-p <密码>] [-d <库号>] [-i <安装目录>]"
  echo "示例: bash install.sh http://192.168.1.10:18081 -a 192.168.1.20:6379 -d 8"
  echo "兼容: bash install.sh <地址> <Redis地址> <密码> <库号> [安装目录]"
  exit 1
fi

echo "[1/4] 下载并更新 WAF 组件..."
mkdir -p "$INSTALL_DIR"
TMP_DIR="$(mktemp -d)"
if ! curl -fsSL "$ADMIN_URL/api/setup/waf.tar.gz" | tar xz -C "$TMP_DIR"; then
  rm -rf "$TMP_DIR"
  echo "下载失败，请确认管理后台地址可访问: $ADMIN_URL"
  exit 1
fi

# 兼容旧版包结构：若多了一层 waf/ 子目录则上移到临时目录根
if [ -f "$TMP_DIR/waf/init.lua" ] && [ ! -f "$TMP_DIR/init.lua" ]; then
  echo "  检测到旧版包结构，整理目录..."
  mv "$TMP_DIR/waf"/* "$TMP_DIR/"
  rm -rf "$TMP_DIR/waf"
fi
if [ ! -f "$TMP_DIR/init.lua" ]; then
  rm -rf "$TMP_DIR"
  echo "组件包异常：未找到 init.lua"
  exit 1
fi

# 覆盖更新组件文件（config_local.lua 由本脚本生成、不在包内，天然保留）
cp -a "$TMP_DIR"/. "$INSTALL_DIR"/
rm -rf "$TMP_DIR"
echo "  组件已更新: $INSTALL_DIR"

echo "[2/4] Redis 配置..."
if [ -f "$INSTALL_DIR/config_local.lua" ] && [ "${FORCE:-0}" != "1" ]; then
  echo "  已存在 config_local.lua，保留现有 Redis 配置"
  echo "  如需按本次参数重新生成，请加 -f/--force 参数: bash install.sh ... -f"
  if ! grep -q 'cookie_secret' "$INSTALL_DIR/config_local.lua" 2>/dev/null; then
    COOKIE_SECRET="$(od -An -N16 -tx1 /dev/urandom | tr -d ' \n')"
    printf '\nchallenge = { cookie_secret = "%s" }\n' "$COOKIE_SECRET" >> "$INSTALL_DIR/config_local.lua"
    echo "  已为 config_local.lua 追加随机 cookie_secret"
  fi
else
  HOST="${REDIS_ADDR%%:*}"
  PORT="${REDIS_ADDR##*:}"
  if [ "$PORT" = "$REDIS_ADDR" ]; then PORT=6379; fi
  case "$REDIS_DB" in
    ''|*[!0-9]*) echo "错误：Redis 库号必须为数字: $REDIS_DB" >&2; exit 1 ;;
  esac
  # 长括号字符串转义：密码/主机含 ]] 会提前闭合 [[...]] 逃逸注入 Lua，替换为 ] ] 破坏闭合
  HOST_SAFE="${HOST//]]/] ]}"
  PASS_SAFE="nil"
  if [ -n "$REDIS_PASSWORD" ]; then
    PASS_SAFE="[[${REDIS_PASSWORD//]]/] ]}]]"
  fi
  # 人机验证 cookie 签名密钥：随机 16 字节，避免默认密钥被伪造放行 cookie
  COOKIE_SECRET="$(od -An -N16 -tx1 /dev/urandom | tr -d ' \n')"
  cat > "$INSTALL_DIR/config_local.lua" <<EOF
-- 由 OpenResty WAF 接入脚本生成（深合并覆盖 config.lua）
return { redis = { host = [[$HOST_SAFE]], port = $PORT, password = $PASS_SAFE, db = $REDIS_DB },
         log = { backend = "redis", redis_key = "waf:event:list" },
         challenge = { cookie_secret = "$COOKIE_SECRET" } }
EOF
  echo "  已生成 config_local.lua (Redis: $REDIS_ADDR db=$REDIS_DB)"
fi

echo "[3/4] 生成 nginx 接入配置..."
cat > "$INSTALL_DIR/waf-nginx.conf" <<EOF
# OpenResty WAF 接入配置（复制到 nginx.conf 的 http {} 段）
lua_package_path  "$INSTALL_DIR/?.lua;;";
lua_package_cpath "$INSTALL_DIR/?.so;;";
lua_shared_dict waf_rule 20m;
lua_shared_dict waf_counter 50m;
init_by_lua_file $INSTALL_DIR/init.lua;
init_worker_by_lua_file $INSTALL_DIR/init.lua;
# 慢速攻击防护（http 段，按需取消注释）
#   client_header_timeout 10s;   # slowloris：请求头读超时
#   client_body_timeout   30s;   # 慢 body 传输超时
#   client_body_buffer_size 128k;# 超过则落盘，WAF 仍扫描前 512KB
#   send_timeout 30s;
# 在需要防护的 server/location 内追加：
#   access_by_lua_file $INSTALL_DIR/access.lua;
#   log_by_lua_file    $INSTALL_DIR/log.lua;
# 可选（响应检测）：
#   header_filter_by_lua_file $INSTALL_DIR/header_filter.lua;
#   body_filter_by_lua_file   $INSTALL_DIR/body_filter.lua;
EOF

echo "[4/4] 完成"
echo "  WAF 组件:   $INSTALL_DIR"
echo "  Redis:      $REDIS_ADDR (db=$REDIS_DB)"
echo "  下一步:"
echo "    1. 首次接入: 将 $INSTALL_DIR/waf-nginx.conf 内容加入 nginx.conf，"
echo "       并在目标 server/location 加 access_by_lua_file / log_by_lua_file（响应检测可再加 header_filter/body_filter）"
echo "    2. 更新组件: 组件文件已更新，执行 nginx -t && nginx -s reload 生效"
`
