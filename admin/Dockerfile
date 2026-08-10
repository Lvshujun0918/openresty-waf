# ---------- 阶段 1：构建前端（web/dist） ----------
FROM node:20-alpine AS web
WORKDIR /app
COPY web/package.json web/package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY web/ ./
RUN npm run build

# ---------- 阶段 2：构建后台（embed 前端产物 + 携带 WAF 组件） ----------
FROM golang:1.25-alpine AS admin
# 国内网络环境使用 goproxy.cn 镜像
ENV GOPROXY=https://goproxy.cn,direct
WORKDIR /app
COPY admin/ ./
COPY --from=web /app/dist ./internal/webui/dist
# WAF Lua 组件打包目录（供引导页下载、接入本机 OpenResty）
COPY waf/ ./waf-dist/
RUN go mod download && CGO_ENABLED=0 go build -o /out/waf-admin .

# ---------- 阶段 3：运行 ----------
FROM alpine:3.20
RUN apk add --no-cache ca-certificates tzdata
COPY --from=admin /out/waf-admin /usr/local/bin/waf-admin
COPY --from=admin /app/waf-dist /opt/waf-dist
ENV ADMIN_ADDR=:8081
EXPOSE 8081
CMD ["waf-admin"]
