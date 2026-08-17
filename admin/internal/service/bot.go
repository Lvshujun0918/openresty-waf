package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
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

// List 分页查询爬虫记录，支持 profile / fake / malicious / client_ip / unknown_ja4 过滤
func (s *BotService) List(profile, clientIP, fake, malicious, unknownJa4 string, page, pageSize int) ([]model.BotLog, int64, error) {
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
	if unknownJa4 == "1" {
		q = q.Where("ja4 <> '' AND NOT EXISTS (SELECT 1 FROM ja4_profiles p WHERE p.enabled = ? AND p.ja4 = bot_logs.ja4)", true)
	}
	var total int64
	if err := q.Count(&total).Error; err != nil {
		return nil, 0, err
	}
	// 列表不返回大字段（请求头/请求体），详情接口单独获取
	var list []model.BotLog
	if err := q.Select("id", "time", "req_id", "client_ip", "country", "province", "city",
		"method", "host", "uri", "ua", "fingerprint", "ja4", "profile", "engine",
		"fake", "malicious_ip", "malicious_fp", "fp_source", "status", "created_at").
		Order("id desc").Offset((page - 1) * pageSize).Limit(pageSize).Find(&list).Error; err != nil {
		return nil, 0, err
	}
	// 附加 JA4 客户端识别（精确 → ja4_ac 前缀）
	s.attachJa4Recognition(list)
	return list, total, nil
}

// attachJa4Recognition 批量附加客户端识别（内存索引，避免逐条查询）
func (s *BotService) attachJa4Recognition(list []model.BotLog) {
	var profiles []model.Ja4Profile
	if err := s.db.Where("enabled = ?", true).Find(&profiles).Error; err != nil || len(profiles) == 0 {
		return
	}
	byJa4 := map[string]model.Ja4Profile{}
	byAc := map[string]model.Ja4Profile{}
	for _, p := range profiles {
		if p.Ja4 != "" {
			byJa4[p.Ja4] = p
		}
		if p.AcPrefix != "" {
			if _, ok := byAc[p.AcPrefix]; !ok {
				byAc[p.AcPrefix] = p
			}
		}
	}
	for i := range list {
		ja4 := list[i].Ja4
		if ja4 == "" {
			continue
		}
		if p, ok := byJa4[ja4]; ok {
			list[i].ClientName = p.Name
			list[i].ClientCat = p.Category
			list[i].Ja4Match = "exact"
		} else if ac := AcPrefix(ja4); ac != "" {
			if p, ok2 := byAc[ac]; ok2 {
				list[i].ClientName = p.Name
				list[i].ClientCat = p.Category
				list[i].Ja4Match = "ac"
			}
		}
	}
}

// Get 按 ID 获取爬虫记录完整信息（含请求头/请求体证据）
func (s *BotService) Get(id uint) (*model.BotLog, error) {
	var rec model.BotLog
	if err := s.db.First(&rec, id).Error; err != nil {
		return nil, errors.New("记录不存在")
	}
	return &rec, nil
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

// BlacklistLog 把爬虫记录的指纹（TLS 指纹优先，HTTP 指纹兜底）一键加入恶意指纹库
// 并下发引擎（同指纹请求后续直接拦截）
func (s *BotService) BlacklistLog(id uint) (uint, error) {
	var rec model.BotLog
	if err := s.db.First(&rec, id).Error; err != nil {
		return 0, errors.New("记录不存在")
	}
	fp := rec.Ja4
	if fp == "" {
		fp = rec.Fingerprint
	}
	if fp == "" {
		return 0, errors.New("该记录无指纹可拉黑")
	}
	var exist int64
	s.db.Model(&model.BotFingerprint{}).Where("value = ? AND match = ?", fp, "exact").Count(&exist)
	if exist > 0 {
		return 0, errors.New("该指纹已在恶意指纹库中")
	}
	desc := "爬虫记录拉黑"
	if rec.Profile != "" {
		desc += ": " + rec.Profile
	}
	if rec.ClientIP != "" {
		desc += " (" + rec.ClientIP + ")"
	}
	f := model.BotFingerprint{
		Name:  "记录#" + fmt.Sprintf("%d", rec.ID) + "-" + rec.Profile,
		Value: fp, Match: "exact", Description: desc,
		Enabled: true,
	}
	if err := s.db.Create(&f).Error; err != nil {
		return 0, err
	}
	if err := s.publishFingerprints(); err != nil {
		return 0, err
	}
	return f.ID, nil
}
