# ---------- 阶段 1：构建前端（web/dist，Soybean Admin + pnpm） ----------
# 前端产物与 CPU 架构无关：锁定 BUILDPLATFORM，多架构构建时避免 QEMU 慢速模拟
FROM --platform=$BUILDPLATFORM node:24-alpine AS web
WORKDIR /app
RUN corepack enable
COPY web/package.json web/pnpm-lock.yaml web/pnpm-workspace.yaml ./
COPY web/packages/ ./packages/
RUN pnpm install --frozen-lockfile --ignore-scripts
COPY web/ ./
RUN pnpm build

# ---------- 阶段 2：构建后台（embed 前端产物 + 携带 WAF 组件） ----------
# CGO_ENABLED=0 纯静态 Go：锁定 BUILDPLATFORM 并按 TARGETARCH 交叉编译，
# 全部 RUN 在构建机原生架构执行，arm64 构建无需 QEMU
FROM --platform=$BUILDPLATFORM golang:1.25-alpine AS admin
ARG TARGETARCH
# 国内网络环境使用 goproxy.cn 镜像
ENV GOPROXY=https://goproxy.cn,direct \
    CGO_ENABLED=0 \
    GOOS=linux \
    GOARCH=${TARGETARCH}
WORKDIR /app
COPY admin/ ./
COPY --from=web /app/dist ./internal/webui/dist
# WAF Lua 组件打包目录（供引导页下载、接入本机 OpenResty）
# libinjection.so 为 glibc x86_64 预编译产物（libinjection BSD 许可，可用
# scripts/build-libinjection.sh 在其他架构/环境重新编译；arm64 引擎侧加载
# 失败时 available=false 自动降级，不影响其余检测逻辑）
COPY waf/ ./waf-dist/
COPY waf/libinjection/libinjection.so ./waf-dist/libinjection.so
RUN go mod download && go build -o /out/waf-admin .

# ---------- 阶段 3：运行 ----------
FROM alpine:3.20
RUN apk add --no-cache ca-certificates tzdata
COPY --from=admin /out/waf-admin /usr/local/bin/waf-admin
COPY --from=admin /app/waf-dist /opt/waf-dist
ENV ADMIN_ADDR=:8081
EXPOSE 8081
CMD ["waf-admin"]
