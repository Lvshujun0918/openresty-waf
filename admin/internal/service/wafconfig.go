package service

import (
	"context"
	"encoding/json"
	"errors"

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

// defaultWafConfig 出厂默认配置（与 waf/config.lua 默认值一致，
// 不含 redis 连接——该信息由部署引导 config_local.lua 提供）
func defaultWafConfig() map[string]interface{} {
	return map[string]interface{}{
		"mode": "active",
		"modules": map[string]interface{}{
			"ip_check": true, "ua_check": true, "url_check": true,
			"args_check": true, "cookie_check": true, "header_check": true,
			"post_check": true, "upload_check": true, "cc_check": true,
			"challenge": true, "protocol_check": true, "leak_check": true,
			"semisense": false,
		},
		"detection": map[string]interface{}{
			"exclude_paths": []string{},
			"geo":           true,
		},
		"cc": map[string]interface{}{
			"rate": "100/60", "ban_duration": 300,
			"ban_key_prefix": "waf:cc:ban:", "counter_prefix": "waf:cc:cnt:",
		},
		"block": map[string]interface{}{
			"status": 403,
			"html": `<!DOCTYPE html>
<html lang="zh-CN"><head><meta charset="utf-8">
<title>访问被拒绝</title>
<style>body{font-family:sans-serif;text-align:center;padding:80px 20px;color:#444}
h1{font-size:36px;color:#c0392b}.code{font-size:72px;color:#eee}</style>
</head><body><div class="code">403</div>
<h1>您的请求已被防火墙拦截</h1>
<p>该请求可能包含恶意内容，如有疑问请联系网站管理员。</p>
</body></html>`,
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
		"blacklist": map[string]interface{}{
			"ips":  []string{},
			"urls": []string{},
		},
		"upload": map[string]interface{}{
			"deny_ext":  []string{"php", "php3", "php5", "phtml", "jsp", "jspx", "asp", "aspx", "asa", "cer", "cgi", "pl", "sh", "py", "exe"},
			"deny_mime": []string{"application/x-php", "application/x-httpd-php", "application/x-msdownload"},
		},
		"challenge": map[string]interface{}{
			"enabled": true, "mode": "basic", "cookie_name": "waf_pass",
			"cookie_secret": "openresty-waf-change-me", "cookie_ttl": 300,
			"page_path": "/__waf_challenge__", "verify_path": "/__waf_challenge_verify__",
			"trigger_paths": []string{},
			"captcha": map[string]interface{}{
				"id": "", "key": "",
				"verify_api": "https://gcaptcha4.geetest.com/validate",
				"sdk":        "https://static.geetest.com/v4/gt4.js",
			},
		},
		"traffic_log": map[string]interface{}{
			"enabled": false, "retention_days": 7, "redis_key": "waf:traffic:list",
		},
	}
}
