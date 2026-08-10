// Package webui 内嵌前端构建产物（web/dist）。
// 后台编译为单一二进制，同时提供 REST API 与前端页面（SPA）。
// Docker 多阶段构建会自动将 web 构建产物复制到 dist 目录；本地未构建时
// 使用占位页。
package webui

import "embed"

//go:embed dist
var FS embed.FS
