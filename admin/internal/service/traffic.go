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

// TrafficService 全量流量记录：消费引擎推送的 Redis 队列落库 + 分页查询 + 过期清理。
// 与攻击事件分离：全量记录模式下引擎对每个请求上报一条（含是否命中攻击）。
type TrafficService struct {
	db     *gorm.DB
	mgr    *RedisManager
	cfg    *config.Config
	ctx    context.Context
}

func NewTrafficService(db *gorm.DB, mgr *RedisManager, cfg *config.Config) *TrafficService {
	return &TrafficService{db: db, mgr: mgr, cfg: cfg, ctx: context.Background()}
}

// Consume 从 Redis 队列批量消费流量记录并写入 DB，返回本次消费条数
func (s *TrafficService) Consume(limit int) (int, error) {
	rdb := s.mgr.GetClient()
	if rdb == nil {
		return 0, errors.New("Redis 未配置，请先在引导页完成 Redis 配置")
	}
	key := "waf:traffic:list"
	raws, err := rdb.RPopCount(s.ctx, key, limit).Result()
	if err == redis.Nil {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	logs := make([]model.TrafficLog, 0, len(raws))
	for _, raw := range raws {
		var rec model.TrafficLog
		if err := json.Unmarshal([]byte(raw), &rec); err != nil {
			continue // 跳过坏数据
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

// List 分页查询流量记录，支持 host / client_ip / attack 过滤
func (s *TrafficService) List(host, clientIP, attack string, page, pageSize int) ([]model.TrafficLog, int64, error) {
	q := s.db.Model(&model.TrafficLog{})
	if host != "" {
		q = q.Where("host LIKE ?", "%"+host+"%")
	}
	if clientIP != "" {
		q = q.Where("client_ip LIKE ?", "%"+clientIP+"%")
	}
	if attack == "1" {
		q = q.Where("attack = ?", true)
	} else if attack == "0" {
		q = q.Where("attack = ?", false)
	}
	var total int64
	if err := q.Count(&total).Error; err != nil {
		return nil, 0, err
	}
	var logs []model.TrafficLog
	if err := q.Order("id desc").Offset((page - 1) * pageSize).Limit(pageSize).Find(&logs).Error; err != nil {
		return nil, 0, err
	}
	return logs, total, nil
}

// Cleanup 清理 retentionDays 天前的流量记录，返回删除条数
func (s *TrafficService) Cleanup(retentionDays int) (int64, error) {
	if retentionDays < 1 {
		retentionDays = 7
	}
	cutoff := time.Now().Add(-time.Duration(retentionDays) * 24 * time.Hour)
	res := s.db.Where("time < ?", cutoff).Delete(&model.TrafficLog{})
	return res.RowsAffected, res.Error
}

// GetStats 统计总记录数与命中攻击数（仪表盘/页头展示）
func (s *TrafficService) GetStats() (total int64, attack int64, err error) {
	if err = s.db.Model(&model.TrafficLog{}).Count(&total).Error; err != nil {
		return
	}
	if err = s.db.Model(&model.TrafficLog{}).Where("attack = ?", true).Count(&attack).Error; err != nil {
		return
	}
	return
}

// TrendPoint 某一天的请求/攻击计数（仪表盘趋势图）
type TrendPoint struct {
	Date   string `json:"date"`
	Total  int64  `json:"total"`
	Attack int64  `json:"attack"`
}

// Trend 返回最近 days 天按天聚合的请求/攻击趋势（缺失日期补 0，SQLite）
func (s *TrafficService) Trend(days int) ([]TrendPoint, error) {
	if days <= 0 || days > 90 {
		days = 7
	}
	start := time.Now().Add(-time.Duration(days-1) * 24 * time.Hour)
	type row struct {
		Date   string
		Total  int64
		Attack int64
	}
	var rows []row
	if err := s.db.Raw(`SELECT strftime('%Y-%m-%d', time) AS date,
		COUNT(*) AS total,
		COALESCE(SUM(CASE WHEN attack THEN 1 ELSE 0 END), 0) AS attack
		FROM traffic_logs
		WHERE time >= ?
		GROUP BY strftime('%Y-%m-%d', time)
		ORDER BY date`, start.Format("2006-01-02 15:04:05")).Scan(&rows).Error; err != nil {
		return nil, err
	}
	byDate := make(map[string]row, len(rows))
	for _, r := range rows {
		byDate[r.Date] = r
	}
	points := make([]TrendPoint, 0, days)
	for i := 0; i < days; i++ {
		d := time.Now().Add(-time.Duration(days-1-i) * 24 * time.Hour).Format("2006-01-02")
		if r, ok := byDate[d]; ok {
			points = append(points, TrendPoint{Date: d, Total: r.Total, Attack: r.Attack})
		} else {
			points = append(points, TrendPoint{Date: d})
		}
	}
	return points, nil
}
