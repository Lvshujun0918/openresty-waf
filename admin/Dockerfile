# ---------- 阶段 1：构建前端（web/dist，Soybean Admin + pnpm） ----------
FROM node:24-alpine AS web
WORKDIR /app
RUN corepack enable
COPY web/package.json web/pnpm-lock.yaml web/pnpm-workspace.yaml ./
COPY web/packages/ ./packages/
RUN pnpm install --frozen-lockfile --ignore-scripts
COPY web/ ./
RUN pnpm build

# ---------- 阶段 2：构建后台（embed 前端产物 + 携带 WAF 组件） ----------
FROM golang:1.25-alpine AS admin
# 国内网络环境使用 goproxy.cn 镜像
ENV GOPROXY=https://goproxy.cn,direct
WORKDIR /app
COPY admin/ ./
COPY --from=web /app/dist ./internal/webui/dist
# WAF Lua 组件打包目录（供引导页下载、接入本机 OpenResty）
# libinjection.so 为 glibc x86_64 预编译产物（libinjection BSD 许可，可用
# scripts/build-libinjection.sh 在其他架构/环境重新编译）
COPY waf/ ./waf-dist/
COPY waf/libinjection/libinjection.so ./waf-dist/libinjection.so
RUN go mod download && CGO_ENABLED=0 go build -o /out/waf-admin .

# ---------- 阶段 3：运行 ----------
FROM alpine:3.20
RUN apk add --no-cache ca-certificates tzdata
COPY --from=admin /out/waf-admin /usr/local/bin/waf-admin
COPY --from=admin /app/waf-dist /opt/waf-dist
ENV ADMIN_ADDR=:8081
EXPOSE 8081
CMD ["waf-admin"]
