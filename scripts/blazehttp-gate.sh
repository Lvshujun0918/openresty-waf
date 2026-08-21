#!/usr/bin/env bash
# blazehttp 检测质量门禁
# 完整链路：Redis → 管理后台(发布规则) → OpenResty(WAF 引擎, fail-closed) → blazehttp 跑分 → 阈值判定
# 用法：bash scripts/blazehttp-gate.sh
# 可调环境变量：
#   MIN_DETECTION  检测率下限（百分比，默认 80）
#   MAX_FP         误报率上限（百分比，默认 2）
#   REPORT         报告输出路径（默认 /tmp/blazehttp-report.txt）
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REDIS_C=waf-gate-redis
NGX_C=waf-gate-openresty
ADMIN_BIN=${ADMIN_BIN:-/tmp/waf-gate-admin}
DB_FILE=${DB_FILE:-/tmp/waf-gate.db}
COOKIE_JAR=/tmp/waf-gate.cookies
REPORT=${REPORT:-/tmp/blazehttp-report.txt}
BASE=http://127.0.0.1:8232
MIN_DETECTION=${MIN_DETECTION:-80}
MAX_FP=${MAX_FP:-2}

log() { echo "[gate] $*"; }
die() { echo "[gate][FATAL] $*" >&2; exit 1; }

cleanup() {
    if [[ -n "${ADMIN_PID:-}" ]]; then kill "$ADMIN_PID" 2>/dev/null || true; fi
    docker rm -f "$NGX_C"   >/dev/null 2>&1 || true
    docker rm -f "$REDIS_C" >/dev/null 2>&1 || true
}
trap cleanup EXIT

command -v docker >/dev/null || die "需要 docker"
docker info >/dev/null 2>&1 || die "docker 不可用"

# ---------- 1. Redis ----------
log "启动 Redis..."
docker run -d --rm --name "$REDIS_C" --network=host redis:7-alpine >/dev/null
for i in $(seq 1 30); do
    docker exec "$REDIS_C" redis-cli ping 2>/dev/null | grep -q PONG && break
    [[ $i == 30 ]] && die "Redis 启动超时"
    sleep 1
done

# ---------- 2. 管理后台 ----------
log "构建并启动管理后台..."
( cd "$ROOT/admin" && go build -o "$ADMIN_BIN" . )
rm -f "$DB_FILE"
ADMIN_DB_DSN="$DB_FILE" ADMIN_ADDR=:8232 ADMIN_INIT_PASSWORD=admin123 "$ADMIN_BIN" &
ADMIN_PID=$!
for i in $(seq 1 30); do
    curl -s -o /dev/null "$BASE/api/auth/login" && break
    [[ $i == 30 ]] && die "admin 启动超时"
    sleep 1
done

# ---------- 3. 登录 + CSRF 双提交 ----------
TOKEN=$(curl -s -c "$COOKIE_JAR" -X POST "$BASE/api/auth/login" \
    -H 'Content-Type: application/json' \
    -d '{"username":"admin","password":"admin123"}' \
    | sed -n 's/.*"token":"\([^"]*\)".*/\1/p')
[[ -n "$TOKEN" && "$TOKEN" != "null" ]] || die "登录失败"
CSRF=$(awk '$6=="waf_csrf"{print $7}' "$COOKIE_JAR")
[[ -n "$CSRF" ]] || die "未获取到 CSRF Cookie"

# ---------- 4. 配置 Redis 并发布规则 ----------
code=$(curl -s -o /dev/null -w '%{http_code}' \
    -b "$COOKIE_JAR" -H "X-CSRF-Token: $CSRF" -H "Authorization: Bearer $TOKEN" \
    -X POST "$BASE/api/setup/redis" -H 'Content-Type: application/json' \
    -d '{"addr":"127.0.0.1:6379","password":"","db":0}')
[[ $code == 200 ]] || die "配置 Redis 失败 HTTP $code"

code=$(curl -s -o /dev/null -w '%{http_code}' \
    -b "$COOKIE_JAR" -H "X-CSRF-Token: $CSRF" -H "Authorization: Bearer $TOKEN" \
    -X POST "$BASE/api/rules/publish")
[[ $code == 200 ]] || die "发布规则失败 HTTP $code"
log "规则已发布到 Redis"

# ---------- 5. OpenResty + WAF 引擎 ----------
log "启动 WAF 引擎（OpenResty）..."
docker run -d --rm --name "$NGX_C" --network=host \
    -v "$ROOT/waf":/waf:ro \
    -v "$ROOT/deploy/nginx-blazehttp.conf":/usr/local/openresty/nginx/conf/nginx.conf:ro \
    openresty/openresty:alpine >/dev/null
docker exec "$NGX_C" mkdir -p /var/log/waf

HOST_IP=$(hostname -I | awk '{print $1}')
[[ -n "$HOST_IP" ]] || die "无法获取宿主 IP（引擎白名单放行 127.0.0.1，必须打非回环地址）"

log "等待规则热更新生效（引擎 5s 轮询）..."
ok=0 normal="" attack=""
for i in $(seq 1 60); do
    normal=$(curl -s -o /dev/null -w '%{http_code}' "http://$HOST_IP:8083/?id=1")
    attack=$(curl -s -o /dev/null -w '%{http_code}' "http://$HOST_IP:8083/?id=1%20union%20select%201")
    if [[ $normal == 200 && $attack == 403 ]]; then ok=1; break; fi
    sleep 2
done
if [[ $ok != 1 ]]; then
    docker logs --tail 50 "$NGX_C" >&2 || true
    die "链路未就绪（normal=$normal attack=$attack）"
fi
log "链路就绪：普通请求放行 / 攻击请求拦截"

# ---------- 6. blazehttp 跑分 ----------
log "运行 blazehttp 基准（33669 样本，约数分钟）..."
docker run --rm --net=host chaitin/blazehttp:latest \
    /app/blazehttp -t "http://$HOST_IP:8083" | tee "$REPORT"

# ---------- 7. 解析指标并判定阈值 ----------
DET=$(grep -E '(检测率|检出率)' "$REPORT" | grep -Eo '[0-9]+(\.[0-9]+)?%' | head -1 | tr -d '%')
FP=$(grep '误报率' "$REPORT" | grep -Eo '[0-9]+(\.[0-9]+)?%' | head -1 | tr -d '%')
if [[ -z "$DET" || -z "$FP" ]]; then
    log "警告：未能从输出解析检测率/误报率，请人工检查报告 $REPORT"
    exit 1
fi

log "结果：检测率 ${DET}%（阈值 ≥${MIN_DETECTION}%）｜误报率 ${FP}%（阈值 ≤${MAX_FP}%）"
fail=0
awk -v d="$DET" -v m="$MIN_DETECTION" 'BEGIN{exit !(d+0>=m+0)}' || { log "❌ 检测率低于阈值"; fail=1; }
awk -v f="$FP"  -v x="$MAX_FP"      'BEGIN{exit !(f+0<=x+0)}' || { log "❌ 误报率高于阈值"; fail=1; }
[[ $fail == 0 ]] && log "✅ 检测质量门禁通过"
exit $fail
