package service

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/redis/go-redis/v9"
	"gorm.io/gorm"

	"openresty-waf/admin/internal/config"
	"openresty-waf/admin/internal/model"
)

// BotService 爬虫与指纹体系：
//   - 恶意指纹库 CRUD → 合并进 WAF 配置 blacklist.fingerprints 下发引擎拦截
//   - 爬虫画像库 CRUD → 独立 Redis 键热更新（waf:bot:profiles + 版本）
//   - 爬虫访问记录消费落库 + 统计（真实/虚假爬虫、Top 维度、趋势）
type BotService struct {
	db  *gorm.DB
	mgr *RedisManager
	cfg *config.Config
	waf *WafConfigService
	ctx context.Context
}

func NewBotService(db *gorm.DB, mgr *RedisManager, cfg *config.Config) *BotService {
	return &BotService{
		db: db, mgr: mgr, cfg: cfg,
		waf: NewWafConfigService(db, mgr, cfg),
		ctx: context.Background(),
	}
}

// ============================================================================
// 恶意指纹库
// ============================================================================

func (s *BotService) ListFingerprints() ([]model.BotFingerprint, error) {
	var list []model.BotFingerprint
	if err := s.db.Order("id asc").Find(&list).Error; err != nil {
		return nil, err
	}
	return list, nil
}

func (s *BotService) CreateFingerprint(f *model.BotFingerprint) error {
	if f.Name == "" || f.Value == "" {
		return errors.New("名称与指纹值不能为空")
	}
	if f.Match != "regex" {
		f.Match = "exact"
	}
	if err := s.db.Create(f).Error; err != nil {
		return err
	}
	return s.publishFingerprints()
}

func (s *BotService) UpdateFingerprint(id uint, f *model.BotFingerprint) error {
	var existing model.BotFingerprint
	if err := s.db.First(&existing, id).Error; err != nil {
		return errors.New("指纹不存在")
	}
	if f.Match != "regex" {
		f.Match = "exact"
	}
	if err := s.db.Model(&existing).Updates(map[string]interface{}{
		"name": f.Name, "value": f.Value, "match": f.Match,
		"description": f.Description, "enabled": f.Enabled, "updated_at": time.Now(),
	}).Error; err != nil {
		return err
	}
	return s.publishFingerprints()
}

func (s *BotService) DeleteFingerprint(id uint) error {
	if err := s.db.Delete(&model.BotFingerprint{}, id).Error; err != nil {
		return err
	}
	return s.publishFingerprints()
}

// publishFingerprints 把启用中的恶意指纹合并进 WAF 配置 blacklist.fingerprints 下发
func (s *BotService) publishFingerprints() error {
	list, err := s.ListFingerprints()
	if err != nil {
		return err
	}
	out := []map[string]interface{}{}
	for _, f := range list {
		if !f.Enabled {
			continue
		}
		out = append(out, map[string]interface{}{
			"name": f.Name, "value": f.Value, "match": f.Match,
		})
	}
	cfg, err := s.waf.Get()
	if err != nil {
		return err
	}
	bl, _ := cfg["blacklist"].(map[string]interface{})
	if bl == nil {
		bl = map[string]interface{}{"ips": []string{}, "urls": []string{}}
		cfg["blacklist"] = bl
	}
	bl["fingerprints"] = out
	return s.waf.Save(cfg)
}

// ============================================================================
// 爬虫画像库
// ============================================================================

func (s *BotService) ListProfiles() ([]model.BotProfile, error) {
	var list []model.BotProfile
	if err := s.db.Order("sort_order asc, id asc").Find(&list).Error; err != nil {
		return nil, err
	}
	return list, nil
}

func (s *BotService) CreateProfile(p *model.BotProfile) error {
	if p.Name == "" || p.UA == "" {
		return errors.New("名称与 UA 正则不能为空")
	}
	if err := s.db.Create(p).Error; err != nil {
		return err
	}
	return s.publishProfiles()
}

func (s *BotService) UpdateProfile(id uint, p *model.BotProfile) error {
	var existing model.BotProfile
	if err := s.db.First(&existing, id).Error; err != nil {
		return errors.New("画像不存在")
	}
	if err := s.db.Model(&existing).Updates(map[string]interface{}{
		"name": p.Name, "ua": p.UA, "ips": p.Ips, "engine": p.Engine,
		"enabled": p.Enabled, "sort_order": p.SortOrder, "updated_at": time.Now(),
	}).Error; err != nil {
		return err
	}
	return s.publishProfiles()
}

func (s *BotService) DeleteProfile(id uint) error {
	if err := s.db.Delete(&model.BotProfile{}, id).Error; err != nil {
		return err
	}
	return s.publishProfiles()
}

// SeedProfiles 内置画像种子（引擎内置的同类画像，供后台展示与编辑）
func (s *BotService) SeedProfiles() {
	var count int64
	s.db.Model(&model.BotProfile{}).Count(&count)
	if count > 0 {
		return
	}
	seeds := []model.BotProfile{
		{Name: "Googlebot", UA: `Googlebot|Google-InspectionTool|Mediapartners-Google`, Engine: true, Enabled: true,
			Ips: `["66.249.64.0/19","64.233.160.0/19","66.249.80.0/20","216.58.192.0/19"]`, SortOrder: 1},
		{Name: "Bingbot", UA: `bingbot|adidxbot`, Engine: true, Enabled: true,
			Ips: `["40.77.0.0/16","157.55.0.0/16","13.64.0.0/16","52.160.0.0/11"]`, SortOrder: 2},
		{Name: "Baiduspider", UA: `Baiduspider`, Engine: true, Enabled: true,
			Ips: `["220.181.108.0/24","119.63.192.0/21","123.125.68.0/24","180.76.15.0/24","116.179.32.0/19"]`, SortOrder: 3},
		{Name: "Sogou", UA: `Sogou.*spider|Sogou web spider`, Engine: true, Enabled: true,
			Ips: `["61.135.162.0/24","220.181.0.0/16"]`, SortOrder: 4},
		{Name: "360Spider", UA: `360Spider|haosouSpider`, Engine: true, Enabled: true,
			Ips: `["60.191.0.0/16","221.200.0.0/16","180.163.220.0/24"]`, SortOrder: 5},
		{Name: "YandexBot", UA: `YandexBot|YandexImages|YaDirectFetcher`, Engine: true, Enabled: true,
			Ips: `["77.88.0.0/18","5.255.192.0/18","213.180.192.0/19"]`, SortOrder: 6},
		{Name: "bytespider", UA: `bytespider`, Engine: true, Enabled: true,
			Ips: `["108.160.160.0/19","8.39.224.0/24"]`, SortOrder: 7},
		{Name: "facebookexternalhit", UA: `facebookexternalhit|Facebot`, Engine: true, Enabled: true,
			Ips: `["69.171.224.0/19","31.13.24.0/21"]`, SortOrder: 8},
		{Name: "curl", UA: `^curl/`, Engine: false, Enabled: true, SortOrder: 20},
		{Name: "python-requests", UA: `^python-requests/`, Engine: false, Enabled: true, SortOrder: 21},
		{Name: "Go-http-client", UA: `^Go-http-client/`, Engine: false, Enabled: true, SortOrder: 22},
		{Name: "Java/OkHttp", UA: `^Java/|OkHttp/`, Engine: false, Enabled: true, SortOrder: 23},
		{Name: "Scrapy", UA: `Scrapy`, Engine: false, Enabled: true, SortOrder: 24},
		{Name: "Wget", UA: `^Wget/`, Engine: false, Enabled: true, SortOrder: 25},
		{Name: "AhrefsBot", UA: `AhrefsBot`, Engine: false, Enabled: true, SortOrder: 30},
		{Name: "SemrushBot", UA: `SemrushBot`, Engine: false, Enabled: true, SortOrder: 31},
		{Name: "MJ12bot", UA: `MJ12bot`, Engine: false, Enabled: true, SortOrder: 32},
		{Name: "PetalBot", UA: `PetalBot`, Engine: false, Enabled: true, SortOrder: 33},
	}
	_ = s.db.Create(&seeds).Error
}

// publishProfiles 发布启用中的画像到 Redis（引擎轮询热更新）
func (s *BotService) publishProfiles() error {
	rdb := s.mgr.GetClient()
	if rdb == nil {
		return errors.New("Redis 未配置")
	}
	var profiles []model.BotProfile
	if err := s.db.Where("enabled = ?", true).
		Order("sort_order asc, id asc").Find(&profiles).Error; err != nil {
		return err
	}
	type outProfile struct {
		Name   string   `json:"name"`
		UA     string   `json:"ua"`
		Ips    []string `json:"ips"`
		Engine bool     `json:"engine"`
	}
	out := make([]outProfile, 0, len(profiles))
	for _, p := range profiles {
		var ips []string
		_ = json.Unmarshal([]byte(p.Ips), &ips)
		out = append(out, outProfile{Name: p.Name, UA: p.UA, Ips: ips, Engine: p.Engine})
	}
	body, err := json.Marshal(map[string]interface{}{"profiles": out})
	if err != nil {
		return err
	}
	pipe := rdb.TxPipeline()
	pipe.Set(s.ctx, "waf:bot:profiles", string(body), 0)
	pipe.Incr(s.ctx, "waf:bot:version")
	if _, err := pipe.Exec(s.ctx); err != nil {
		return err
	}
	return nil
}

// ============================================================================
// 爬虫访问记录
// ============================================================================

// Consume 批量消费爬虫记录并落库
func (s *BotService) Consume(limit int) (int, error) {
	rdb := s.mgr.GetClient()
	if rdb == nil {
		return 0, errors.New("Redis 未配置")
	}
	raws, err := rdb.RPopCount(s.ctx, "waf:bot:list", limit).Result()
	if err == redis.Nil {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	logs := make([]model.BotLog, 0, len(raws))
	for _, raw := range raws {
		var rec model.BotLog
		if err := json.Unmarshal([]byte(raw), &rec); err != nil {
			continue
		}
		if rec.Time.IsZero() {
			rec.Time = time.Now()
		}
		logs = append(logs, rec)
	}
	if len(logs) > 0 {
		if err := s.db.CreateInBatches(logs, 100).Error; err != nil {
			return 0, err
		}
	}
	return len(logs), nil
}

// List 分页查询爬虫记录，支持 profile / fake / malicious / client_ip 过滤
func (s *BotService) List(profile, clientIP, fake, malicious string, page, pageSize int) ([]model.BotLog, int64, error) {
	q := s.db.Model(&model.BotLog{})
	if profile != "" {
		q = q.Where("profile = ?", profile)
	}
	if clientIP != "" {
		q = q.Where("client_ip LIKE ?", "%"+clientIP+"%")
	}
	if fake == "1" {
		q = q.Where("fake = ?", true)
	}
	if malicious == "1" {
		q = q.Where("malicious_ip = ? OR malicious_fp <> ?", true, "")
	}
	var total int64
	if err := q.Count(&total).Error; err != nil {
		return nil, 0, err
	}
	var list []model.BotLog
	if err := q.Order("id desc").Offset((page - 1) * pageSize).Limit(pageSize).Find(&list).Error; err != nil {
		return nil, 0, err
	}
	return list, total, nil
}

// BotStats 爬虫统计总览
type BotStats struct {
	Total       int64 `json:"total"`        // 爬虫请求总数
	Real        int64 `json:"real"`         // 真实搜索引擎爬虫
	Fake        int64 `json:"fake"`         // 虚假爬虫（UA 伪造）
	Tools       int64 `json:"tools"`        // 工具/采集类爬虫
	MaliciousIP int64 `json:"malicious_ip"` // 恶意 IP 来源
	MaliciousFP int64 `json:"malicious_fp"` // 恶意指纹命中
}

func (s *BotService) Stats() (*BotStats, error) {
	st := &BotStats{}
	if err := s.db.Model(&model.BotLog{}).Count(&st.Total).Error; err != nil {
		return nil, err
	}
	if err := s.db.Model(&model.BotLog{}).Where("engine = ? AND fake = ?", true, false).Count(&st.Real).Error; err != nil {
		return nil, err
	}
	if err := s.db.Model(&model.BotLog{}).Where("fake = ?", true).Count(&st.Fake).Error; err != nil {
		return nil, err
	}
	if err := s.db.Model(&model.BotLog{}).Where("engine = ?", false).Count(&st.Tools).Error; err != nil {
		return nil, err
	}
	if err := s.db.Model(&model.BotLog{}).Where("malicious_ip = ?", true).Count(&st.MaliciousIP).Error; err != nil {
		return nil, err
	}
	if err := s.db.Model(&model.BotLog{}).Where("malicious_fp <> ?", "").Count(&st.MaliciousFP).Error; err != nil {
		return nil, err
	}
	return st, nil
}

// TopItem 聚合排行项
type TopItem struct {
	Key   string `json:"key"`
	Count int64  `json:"count"`
}

// Top 按维度聚合排行（dim: ip | ua | fingerprint | profile）
func (s *BotService) Top(dim string, limit int) ([]TopItem, error) {
	if limit <= 0 || limit > 100 {
		limit = 20
	}
	col := "client_ip"
	switch dim {
	case "ua":
		col = "ua"
	case "fingerprint":
		col = "fingerprint"
	case "profile":
		col = "profile"
	}
	var out []TopItem
	if err := s.db.Raw(`SELECT `+col+` AS key, COUNT(*) AS count FROM bot_logs
		WHERE `+col+` IS NOT NULL AND `+col+` != ''
		GROUP BY `+col+` ORDER BY count DESC LIMIT ?`, limit).Scan(&out).Error; err != nil {
		return nil, err
	}
	return out, nil
}

// TrendPoint 某天爬虫/虚假爬虫数量
type BotTrendPoint struct {
	Date  string `json:"date"`
	Total int64  `json:"total"`
	Fake  int64  `json:"fake"`
}

// Trend 最近 days 天趋势（缺失补 0）
func (s *BotService) Trend(days int) ([]BotTrendPoint, error) {
	if days <= 0 || days > 90 {
		days = 7
	}
	now := time.Now()
	start := now.Add(-time.Duration(days-1) * 24 * time.Hour)
	type row struct {
		Date  string
		Total int64
		Fake  int64
	}
	var rows []row
	if err := s.db.Raw(`SELECT strftime('%Y-%m-%d', time) AS date,
		COUNT(*) AS total,
		COALESCE(SUM(CASE WHEN fake THEN 1 ELSE 0 END), 0) AS fake
		FROM bot_logs WHERE time >= ?
		GROUP BY strftime('%Y-%m-%d', time) ORDER BY date`,
		start.Format("2006-01-02 15:04:05")).Scan(&rows).Error; err != nil {
		return nil, err
	}
	byDate := make(map[string]row, len(rows))
	for _, r := range rows {
		byDate[r.Date] = r
	}
	out := make([]BotTrendPoint, 0, days)
	for i := 0; i < days; i++ {
		d := now.Add(-time.Duration(days-1-i) * 24 * time.Hour).Format("2006-01-02")
		if r, ok := byDate[d]; ok {
			out = append(out, BotTrendPoint{Date: d, Total: r.Total, Fake: r.Fake})
		} else {
			out = append(out, BotTrendPoint{Date: d})
		}
	}
	return out, nil
}

