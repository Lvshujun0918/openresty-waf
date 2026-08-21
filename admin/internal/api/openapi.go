package api

import (
	"encoding/json"
	"fmt"
	"html"
	"net/http"
	"sort"
	"strings"
	"sync"

	"github.com/gin-gonic/gin"

	"openresty-waf/admin/internal/config"
)

// OpenAPIHandler 基于运行时路由表动态生成 OpenAPI 3.0 规范与轻量接口文档页。
// 路由在进程启动后不再变化，规范与文档页均在首次访问时生成并缓存；
// 不引入代码注解生成器，避免额外构建依赖。
type OpenAPIHandler struct {
	cfg      *config.Config
	once     sync.Once
	spec     []byte
	docsHTML []byte
}

func NewOpenAPIHandler(cfg *config.Config) *OpenAPIHandler {
	return &OpenAPIHandler{cfg: cfg}
}

// SpecFor 返回输出 OpenAPI JSON 的处理器（捕获引擎以读取路由表）。
func (h *OpenAPIHandler) SpecFor(r *gin.Engine) gin.HandlerFunc {
	return func(c *gin.Context) {
		h.build(r)
		c.Data(http.StatusOK, "application/json; charset=utf-8", h.spec)
	}
}

// DocsFor 返回输出接口文档页的处理器（纯内联样式，无外部资源依赖）。
func (h *OpenAPIHandler) DocsFor(r *gin.Engine) gin.HandlerFunc {
	return func(c *gin.Context) {
		h.build(r)
		c.Data(http.StatusOK, "text/html; charset=utf-8", h.docsHTML)
	}
}

func (h *OpenAPIHandler) build(r *gin.Engine) {
	h.once.Do(func() {
		routes := apiRoutes(r)
		spec := buildSpec(routes)
		h.spec, _ = json.MarshalIndent(spec, "", "  ")
		h.docsHTML = []byte(buildDocs(routes))
	})
}

// ---------------------------------------------------------------------------
// 路由提取

type apiRoute struct {
	Method  string
	Path    string
	Tag     string
	Handler string
}

// 文档自描述端点不进规范（元信息而非业务接口）
var docSelfPaths = map[string]bool{
	"/api/openapi.json": true, "/api/v1/openapi.json": true,
	"/api/docs": true, "/api/v1/docs": true,
}

// 公开端点无需认证
var publicPaths = map[string]bool{
	"/api/health": true, "/api/v1/health": true,
	"/api/auth/login": true, "/api/v1/auth/login": true,
	"/api/setup/status": true, "/api/v1/setup/status": true,
	"/api/setup/waf.tar.gz": true, "/api/v1/setup/waf.tar.gz": true,
	"/api/setup/install.sh": true, "/api/v1/setup/install.sh": true,
}

func apiRoutes(r *gin.Engine) []apiRoute {
	all := r.Routes()
	routes := make([]apiRoute, 0, len(all))
	for _, ri := range all {
		if !strings.HasPrefix(ri.Path, "/api") || docSelfPaths[ri.Path] {
			continue
		}
		routes = append(routes, apiRoute{
			Method:  ri.Method,
			Path:    ri.Path,
			Tag:     routeTag(ri.Path),
			Handler: shortHandler(ri.Handler),
		})
	}
	sort.Slice(routes, func(i, j int) bool {
		if routes[i].Tag != routes[j].Tag {
			return routes[i].Tag < routes[j].Tag
		}
		if routes[i].Path != routes[j].Path {
			return routes[i].Path < routes[j].Path
		}
		return routes[i].Method < routes[j].Method
	})
	return routes
}

// routeTag 取 /api(/v1) 后的第一段作为模块标签
func routeTag(path string) string {
	p := strings.TrimPrefix(path, "/api/v1/")
	if p == path {
		p = strings.TrimPrefix(path, "/api/")
	}
	if i := strings.Index(p, "/"); i >= 0 {
		p = p[:i]
	}
	return p
}

// shortHandler 提取处理器短名："pkg.(*RuleHandler).List-fm" → "List"
func shortHandler(h string) string {
	h = strings.TrimSuffix(h, "-fm")
	if i := strings.LastIndex(h, "."); i >= 0 && i+1 < len(h) {
		h = h[i+1:]
	}
	return h
}

// ---------------------------------------------------------------------------
// 模块标签中文说明

var tagDesc = map[string]string{
	"audit-logs":    "操作审计日志",
	"auth":          "认证与会话管理",
	"bans":          "封禁管理",
	"bots":          "爬虫画像与恶意指纹防护",
	"cc-logs":       "CC 触发记录",
	"challenges":    "人机验证记录",
	"config":        "WAF 运行配置",
	"dashboard":     "仪表盘聚合统计",
	"db":            "数据库备份",
	"events":        "攻击事件",
	"health":        "健康探针与引擎状态",
	"ip-list-subs":  "IP 名单远程订阅",
	"ja4":           "JA4 客户端指纹库",
	"monitor":       "实时监控",
	"alerts":        "告警通知（通道与规则）",
	"rules":         "规则管理与灰度发布",
	"setup":         "部署引导",
	"tokens":        "API Token 管理（仅超管）",
	"traffic":       "全量流量记录",
	"trigger-rules": "触发规则",
	"users":         "用户管理（仅超管）",
}

// ---------------------------------------------------------------------------
// OpenAPI 3.0 规范生成

func buildSpec(routes []apiRoute) map[string]interface{} {
	paths := map[string]interface{}{}
	for _, rt := range routes {
		key := specPath(rt.Path)
		item, ok := paths[key].(map[string]interface{})
		if !ok {
			item = map[string]interface{}{}
			paths[key] = item
		}
		op := map[string]interface{}{
			"tags":        []string{rt.Tag},
			"summary":     rt.Handler,
			"operationId": opID(rt),
			"responses": map[string]interface{}{
				"200": map[string]interface{}{"description": "成功"},
			},
		}
		if params := pathParams(rt.Path); len(params) > 0 {
			op["parameters"] = params
		}
		if publicPaths[rt.Path] {
			op["security"] = []interface{}{}
		} else {
			op["security"] = []interface{}{
				map[string]interface{}{"bearerAuth": []string{}},
				map[string]interface{}{"apiTokenAuth": []string{}},
			}
		}
		item[strings.ToLower(rt.Method)] = op
	}
	return map[string]interface{}{
		"openapi": "3.0.3",
		"info": map[string]interface{}{
			"title":   "OpenResty WAF Admin API",
			"version": "1.0.0",
			"description": "OpenResty WAF 管理面板接口。" +
				"认证方式：浏览器会话（Authorization: Bearer <JWT> + CSRF 双提交 cookie）或脚本调用（X-API-Token 头，权限等同超管）。" +
				"/api 为兼容前缀，/api/v1 为规范版本前缀，两者行为一致。",
		},
		"servers": []interface{}{map[string]string{"url": "/"}},
		"paths":   paths,
		"components": map[string]interface{}{
			"securitySchemes": map[string]interface{}{
				"bearerAuth":   map[string]interface{}{"type": "http", "scheme": "bearer", "bearerFormat": "JWT"},
				"apiTokenAuth": map[string]interface{}{"type": "apiKey", "in": "header", "name": "X-API-Token"},
			},
		},
	}
}

// specPath 将 gin 参数语法转为 OpenAPI 花括号语法：/rules/:id → /rules/{id}
func specPath(p string) string {
	segs := strings.Split(p, "/")
	for i, s := range segs {
		if strings.HasPrefix(s, ":") || strings.HasPrefix(s, "*") {
			segs[i] = "{" + strings.TrimLeft(s, ":*") + "}"
		}
	}
	return strings.Join(segs, "/")
}

func pathParams(p string) []map[string]interface{} {
	var params []map[string]interface{}
	for _, seg := range strings.Split(p, "/") {
		if strings.HasPrefix(seg, ":") || strings.HasPrefix(seg, "*") {
			params = append(params, map[string]interface{}{
				"name":     strings.TrimLeft(seg, ":*"),
				"in":       "path",
				"required": true,
				"schema":   map[string]string{"type": "string"},
			})
		}
	}
	return params
}

func opID(rt apiRoute) string {
	r := strings.NewReplacer("/", "_", ":", "-", "*", "-")
	return strings.ToLower(rt.Method) + r.Replace(specPath(rt.Path))
}

// ---------------------------------------------------------------------------
// 轻量文档页（内联样式，无外部依赖）

var methodColor = map[string]string{
	http.MethodGet:    "#16a34a",
	http.MethodPost:   "#2563eb",
	http.MethodPut:    "#d97706",
	http.MethodPatch:  "#ca8a04",
	http.MethodDelete: "#dc2626",
}

func buildDocs(routes []apiRoute) string {
	var b strings.Builder
	b.WriteString(`<!DOCTYPE html><html lang="zh-CN"><head><meta charset="utf-8">` +
		`<meta name="viewport" content="width=device-width,initial-scale=1">` +
		`<title>OpenResty WAF Admin API 文档</title><style>` +
		`body{font-family:system-ui,-apple-system,"Segoe UI",Roboto,"PingFang SC","Microsoft YaHei",sans-serif;` +
		`max-width:960px;margin:24px auto;padding:0 16px;color:#1f2937;line-height:1.6}` +
		`h1{font-size:22px;border-bottom:2px solid #2563eb;padding-bottom:8px}` +
		`h2{font-size:17px;margin-top:28px;color:#111827}` +
		`.meta{color:#6b7280;font-size:14px}` +
		`.note{background:#eff6ff;border-left:3px solid #2563eb;padding:10px 14px;font-size:14px;border-radius:0 6px 6px 0;margin:12px 0}` +
		`table{width:100%;border-collapse:collapse;font-size:14px}` +
		`td{padding:7px 8px;border-bottom:1px solid #f0f0f0;vertical-align:top}` +
		`code{background:#f5f5f5;padding:2px 6px;border-radius:4px;font-size:13px;word-break:break-all}` +
		`.badge{display:inline-block;min-width:52px;text-align:center;color:#fff;border-radius:4px;` +
		`font-size:12px;font-weight:600;padding:2px 6px}` +
		`.desc{color:#6b7280;font-size:13px;margin:2px 0 8px}` +
		`</style></head><body>`)

	b.WriteString("<h1>OpenResty WAF Admin API</h1>")
	b.WriteString(`<div class="note"><strong>认证方式</strong>：<br>` +
		`① 浏览器会话：<code>Authorization: Bearer &lt;JWT&gt;</code>，写操作需携带 CSRF 双提交 cookie；<br>` +
		`② 脚本调用：<code>X-API-Token: waf_xxx</code>（「API Token」页签发，权限等同超管，免 CSRF）。<br>` +
		`<strong>版本前缀</strong>：<code>/api</code> 为兼容前缀，<code>/api/v1</code> 为规范前缀，行为一致。<br>` +
		`机器可读规范：<a href="/api/openapi.json">/api/openapi.json</a>（OpenAPI 3.0）</div>`)

	prevTag := ""
	for _, rt := range routes {
		if rt.Tag != prevTag {
			prevTag = rt.Tag
			title := rt.Tag
			if d := tagDesc[rt.Tag]; d != "" {
				title = fmt.Sprintf("%s <span class='desc'>%s</span>", html.EscapeString(rt.Tag), html.EscapeString(d))
			}
			b.WriteString("<h2>" + title + "</h2><table>")
		}
		color := methodColor[rt.Method]
		if color == "" {
			color = "#6b7280"
		}
		b.WriteString(fmt.Sprintf("<tr><td><span class='badge' style='background:%s'>%s</span></td>"+
			"<td><code>%s</code></td><td class='desc'>%s</td></tr>",
			color, html.EscapeString(rt.Method), html.EscapeString(specPath(rt.Path)), html.EscapeString(rt.Handler)))
	}
	// 收尾未闭合表格（最后一个分组）
	b.WriteString("</table></body></html>")
	return b.String()
}
