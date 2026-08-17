package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
	"time"

	"gorm.io/gorm"

	"openresty-waf/admin/internal/config"
	"openresty-waf/admin/internal/model"
)

// Setup 表 key：WAF 运行配置（JSON）
const SetupKeyWafConfig = "waf_config"

// WafConfigService WAF 运行配置：后台统一管理（取代直接改 config.lua），
// 保存后下发 Redis 并自增版本号，Lua 引擎轮询热更新。
type WafConfigService struct {
	db  *gorm.DB
	mgr *RedisManager
	cfg *config.Config
	ctx context.Context
}

func NewWafConfigService(db *gorm.DB, mgr *RedisManager, cfg *config.Config) *WafConfigService {
	return &WafConfigService{db: db, mgr: mgr, cfg: cfg, ctx: context.Background()}
}

// Get 读取当前 WAF 配置（无则返回默认模板）
func (s *WafConfigService) Get() (map[string]interface{}, error) {
	var row model.Setup
	err := s.db.Where("key = ?", SetupKeyWafConfig).First(&row).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return defaultWafConfig(), nil
	}
	if err != nil {
		return nil, err
	}
	var cfg map[string]interface{}
	if err := json.Unmarshal([]byte(row.Value), &cfg); err != nil {
		return defaultWafConfig(), nil
	}
	return cfg, nil
}

// Save 保存配置到 DB 并下发 Redis（版本自增触发引擎热更新）
func (s *WafConfigService) Save(cfg map[string]interface{}) error {
	// 规范化：拦截页分组（block.pages）缺省时补空数组。
	// 引擎按「数组整体替换」做热更新合并——若缺失该键会保留旧值（清理不干净）。
	if block, ok := cfg["block"].(map[string]interface{}); ok {
		if _, has := block["pages"]; !has {
			block["pages"] = []map[string]interface{}{}
		}
	}
	body, err := json.Marshal(cfg)
	if err != nil {
		return err
	}
	var row model.Setup
	err = s.db.Where("key = ?", SetupKeyWafConfig).First(&row).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		err = s.db.Create(&model.Setup{Key: SetupKeyWafConfig, Value: string(body)}).Error
	} else if err == nil {
		err = s.db.Model(&row).Update("value", string(body)).Error
	}
	if err != nil {
		return err
	}

	rdb := s.mgr.GetClient()
	if rdb == nil {
		return errors.New("Redis 未配置，请先在引导页完成 Redis 配置")
	}
	pipe := rdb.TxPipeline()
	pipe.Set(s.ctx, s.cfg.WAFConfig.DataKey, string(body), 0)
	pipe.Incr(s.ctx, s.cfg.WAFConfig.VersionKey)
	if _, err := pipe.Exec(s.ctx); err != nil {
		return err
	}
	return nil
}

// Versions 版本健康信息：rule_version / config_version 来自 Redis
// （后台下发的当前版本号）；engine_version 优先取引擎心跳（实时，不依赖事件），
// 无心跳时回退最近事件上报的引擎版本。
func (s *WafConfigService) Versions() (map[string]string, error) {
	out := map[string]string{
		"engine_version": "",
		"rule_version":   "",
		"config_version": "",
	}
	rdb := s.mgr.GetClient()
	if rdb != nil {
		if v, err := rdb.Get(s.ctx, s.cfg.Rule.VersionKey).Result(); err == nil && v != "" {
			out["rule_version"] = v
		}
		if v, err := rdb.Get(s.ctx, s.cfg.WAFConfig.VersionKey).Result(); err == nil && v != "" {
			out["config_version"] = v
		}
		// 引擎版本：优先从心跳读取（任一在线引擎）
		engines, err := NewHealthService(s.mgr, s.cfg).ListEngines()
		if err == nil {
			for _, e := range engines {
				if e.EngineVersion != "" {
					out["engine_version"] = e.EngineVersion
					break
				}
			}
		}
	}
	if out["engine_version"] == "" {
		var ev model.Event
		if err := s.db.Where("engine_version <> ''").Order("id desc").First(&ev).Error; err == nil {
			out["engine_version"] = ev.EngineVersion
		}
	}
	return out, nil
}

// BanEntry 临时/永久封禁条目
// UA 为空 = 按 IP 封禁；非空 = 按 IP+UA 封禁（引擎侧 UA 子串匹配）
type BanEntry struct {
	IP        string `json:"ip"`
	UA        string `json:"ua,omitempty"`
	ExpiresAt *int64 `json:"expires_at"` // nil = 永久封禁
	Permanent bool   `json:"permanent"`
}

// parseBanEntry 解析黑名单条目：
//
//	"地址" | "地址|unix时间戳" | "地址|UA|unix时间戳"（IP+UA 维度封禁）
func parseBanEntry(entry string) (ip, ua string, ts int64) {
	if idx := strings.LastIndexByte(entry, '|'); idx >= 0 {
		part := entry[idx+1:]
		if n, err := strconv.ParseInt(part, 10, 64); err == nil && n > 0 {
			ts = n
			rest := entry[:idx]
			if j := strings.IndexByte(rest, '|'); j >= 0 {
				return rest[:j], rest[j+1:], ts
			}
			return rest, "", ts
		}
	}
	return entry, "", 0
}

// BanIP 封禁 IP：hours<=0 永久封禁，否则封禁 hours 小时；
// 写入配置 blacklist.ips（条目格式 ip|unix_ts，引擎侧过期自动跳过）并下发。
func (s *WafConfigService) BanIP(ip string, hours int) error {
	return s.Ban(ip, "", hours)
}

// Ban 封禁：ua 非空时按 IP+UA 维度封禁（条目格式 ip|ua|unix_ts，UA 子串匹配）
func (s *WafConfigService) Ban(ip, ua string, hours int) error {
	ip = strings.TrimSpace(ip)
	if net.ParseIP(ip) == nil {
		return errors.New("非法 IP 地址")
	}
	if ua != "" && (strings.Contains(ua, "|") || len(ua) > 128) {
		return errors.New("UA 维度非法（不能包含 | 且不超过 128 字符）")
	}
	cfg, err := s.Get()
	if err != nil {
		return err
	}
	blacklist, _ := cfg["blacklist"].(map[string]interface{})
	if blacklist == nil {
		blacklist = map[string]interface{}{"ips": []string{}, "urls": []string{}}
		cfg["blacklist"] = blacklist
	}
	ips := toStringSlice(blacklist["ips"])
	out := make([]string, 0, len(ips)+1)
	for _, e := range ips {
		partIP, partUA, _ := parseBanEntry(e)
		if partIP != ip || partUA != ua {
			out = append(out, e)
		}
	}
	entry := ip
	if ua != "" {
		entry = ip + "|" + ua
	}
	if hours > 0 {
		entry = fmt.Sprintf("%s|%d", entry, time.Now().Add(time.Duration(hours)*time.Hour).Unix())
	}
	out = append(out, entry)
	blacklist["ips"] = out
	return s.Save(cfg)
}

// ListBans 当前生效的封禁条目（已过期的临时条目不展示，引擎侧亦自动跳过）
func (s *WafConfigService) ListBans() ([]BanEntry, error) {
	cfg, err := s.Get()
	if err != nil {
		return nil, err
	}
	blacklist, _ := cfg["blacklist"].(map[string]interface{})
	out := []BanEntry{}
	if blacklist == nil {
		return out, nil
	}
	now := time.Now().Unix()
	for _, e := range toStringSlice(blacklist["ips"]) {
		ip, ua, ts := parseBanEntry(e)
		if ip == "" || net.ParseIP(ip) == nil {
			continue
		}
		if ts > 0 && ts <= now {
			continue // 已过期
		}
		b := BanEntry{IP: ip, UA: ua}
		if ts > 0 {
			t := ts
			b.ExpiresAt = &t
		} else {
			b.Permanent = true
		}
		out = append(out, b)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].IP < out[j].IP })
	return out, nil
}

// UnbanIP 解除指定 IP 的封禁（含过期条目；ip+ua 维度条目一并解除）
func (s *WafConfigService) UnbanIP(ip string) error {
	cfg, err := s.Get()
	if err != nil {
		return err
	}
	blacklist, _ := cfg["blacklist"].(map[string]interface{})
	if blacklist == nil {
		return nil
	}
	ips := toStringSlice(blacklist["ips"])
	out := make([]string, 0, len(ips))
	for _, e := range ips {
		part, _, _ := parseBanEntry(e)
		if part != ip {
			out = append(out, e)
		}
	}
	blacklist["ips"] = out
	return s.Save(cfg)
}

func toStringSlice(v interface{}) []string {
	slice, ok := v.([]interface{})
	if !ok {
		return nil
	}
	out := make([]string, 0, len(slice))
	for _, item := range slice {
		if str, ok := item.(string); ok {
			out = append(out, str)
		}
	}
	return out
}

// 不含 redis 连接——该信息由部署引导 config_local.lua 提供）
func defaultWafConfig() map[string]interface{} {
	return map[string]interface{}{
		"mode": "active",
		// 检测能力由规则集驱动（规则管理页停用），无模块级开关
		"detection": map[string]interface{}{
			"exclude_paths":  []string{},
			"geo":            true,
			"paranoia_level": 1,
			// 响应体检测缓冲上限（字节，默认 8KB）；检测 watchdog（毫秒，0 关闭）
			"response_body_buffer": 8192,
			"watchdog_ms":          10,
			// 静态资源剪枝：命中后缀/前缀时跳过规则引擎检测（名单/CC/人机验证仍生效）
			"skip_static": map[string]interface{}{
				"ext": []string{".js", ".css", ".png", ".jpg", ".jpeg", ".gif",
					".svg", ".ico", ".webp", ".avif", ".woff", ".woff2", ".ttf",
					".eot", ".map", ".mp3", ".mp4", ".webm"},
				"prefix": []string{},
			},
		},
		"cc": map[string]interface{}{
			"rate": "100/60", "ban_duration": 300, "backend": "shared",
			"ban_key_prefix": "waf:cc:ban:", "counter_prefix": "waf:cc:cnt:",
		},
		"block": map[string]interface{}{
			"status": 403,
			"html": `<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>访问已被拦截</title>
<style>
  * { margin: 0; padding: 0; box-sizing: border-box; }
  html, body { height: 100%; }
  body {
    font-family: "PingFang SC", "Helvetica Neue", "Microsoft YaHei", Arial, sans-serif;
    background: linear-gradient(135deg, #1e293b 0%, #0f172a 100%);
    display: flex; align-items: center; justify-content: center;
    min-height: 100vh; padding: 20px; color: #334155;
  }
  .card {
    background: #ffffff; border-radius: 16px;
    width: 92%; max-width: 520px; padding: 48px 40px 36px;
    text-align: center; position: relative;
    box-shadow: 0 24px 64px rgba(0, 0, 0, 0.35);
  }
  .icon {
    width: 76px; height: 76px; margin: 0 auto 24px;
    display: flex; align-items: center; justify-content: center;
    border-radius: 50%; background: #fef2f2; border: 1px solid #fecaca;
  }
  .icon svg { width: 42px; height: 42px; }
  h1 { font-size: 22px; font-weight: 600; color: #0f172a; margin-bottom: 12px; }
  .desc { font-size: 14px; color: #64748b; line-height: 1.9; margin-bottom: 26px; }
  .meta {
    background: #f8fafc; border: 1px solid #e2e8f0; border-radius: 10px;
    padding: 14px 18px; font-size: 13px; color: #94a3b8; text-align: left;
    display: grid; gap: 8px; margin-bottom: 26px;
  }
  .meta .row { display: flex; gap: 8px; }
  .meta .k { color: #64748b; flex-shrink: 0; min-width: 72px; }
  .meta .v { color: #334155; font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; word-break: break-all; }
  .footer { font-size: 12px; color: #94a3b8; }
  .footer b { color: #64748b; font-weight: 500; }
</style>
</head>
<body>
  <div class="card">
    <div class="icon">
      <svg viewBox="0 0 24 24" fill="none">
        <path d="M12 3 2 20h20L12 3z" fill="#ef4444"/>
        <path d="M13 9.5h-2V15h2V9.5zm0 7.5h-2v2h2v-2z" fill="#ffffff"/>
      </svg>
    </div>
    <h1>访问已被拦截</h1>
    <p class="desc">检测到您的请求存在恶意行为或异常特征，已由安全防火墙拦截。如有疑问请联系网站管理员。</p>
    <div class="meta">
      <div class="row"><span class="k">来源 IP</span><span class="v">{ip}</span></div>
      <div class="row"><span class="k">请求地址</span><span class="v">{uri}</span></div>
      <div class="row"><span class="k">拦截原因</span><span class="v">{group}</span></div>
      <div class="row"><span class="k">事件编号</span><span class="v">{req_id}</span></div>
    </div>
    <div class="footer">Web Application Firewall 安全防护 · <b>请求已被拦截</b></div>
  </div>
</body>
</html>`,
			// 自定义拦截页面：按命中规则分组（group）显示不同 HTML；未配置分组回退上方 html 兜底
			"pages": []map[string]interface{}{},
		},
		"log": map[string]interface{}{
			// 默认走 Redis：攻击事件由后台消费展示（与 config_local 部署模式一致）；
			// 需要本地文件可在此改为 "file"
			"enabled": true, "backend": "redis", "dir": "/var/log/waf",
			"format": "json", "level": "info", "redis_key": "waf:event:list",
		},
		"whitelist": map[string]interface{}{
			"ips":         []string{"127.0.0.1", "::1"},
			"urls":        []string{"/favicon.ico"},
			"user_agents": []string{},
		},
		// 可信反向代理（精确 IP 或 CIDR）：直连地址命中时才信任 X-Forwarded-For；
		// 留空 = 无条件信任 XFF（兼容旧行为），公网直连部署建议配置以防伪造。
		"trusted_proxies": []string{},
		// 自定义来源 IP 头（优先级高于 XFF）：如腾讯云 EdgeOne 的 eo-connecting-ip
		"client_ip_header": "",
		"blacklist": map[string]interface{}{
			"ips":  []string{},
			"urls": []string{},
		},
		"upload": map[string]interface{}{
			"enabled":      true,
			"deny_ext":     []string{"php", "php3", "php5", "phtml", "jsp", "jspx", "asp", "aspx", "asa", "cer", "cgi", "pl", "sh", "py", "exe"},
			"deny_mime":    []string{"application/x-php", "application/x-httpd-php", "application/x-msdownload"},
			"content_scan": true,
			// 请求体落临时文件时扫描文件前缀字节数（防超大上传绕过）
			"spooled_scan_bytes": 524288,
		},
		"challenge": map[string]interface{}{
			"enabled": true, "mode": "basic", "cookie_name": "waf_pass",
			"cookie_secret": "openresty-waf-change-me", "cookie_ttl": 300,
			"page_path": "/__waf_challenge__", "verify_path": "/__waf_challenge_verify__",
			"pow_bits": 20, "issue_limit": 20, "issue_window": 60,
			"captcha": map[string]interface{}{
				"id": "", "key": "",
				"verify_api": "https://gcaptcha4.geetest.com/validate",
				"sdk":        "https://static.geetest.com/v4/gt4.js",
			},
		},
		"traffic_log": map[string]interface{}{
			"enabled": false, "retention_days": 7, "redis_key": "waf:traffic:list",
		},
		"auto_ban": map[string]interface{}{
			"enabled": true, "threshold": 10, "window": 60, "duration": 600,
			"ban_key_prefix": "waf:ab:ban:", "counter_prefix": "waf:ab:cnt:",
		},
	}
}
