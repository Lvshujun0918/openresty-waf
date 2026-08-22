package service

import (
	"fmt"
	"time"

	"gorm.io/gorm"
)

// TrafficStatService 流量统计聚合（基于 traffic_logs 全量请求记录）
type TrafficStatService struct {
	db *gorm.DB
}

func NewTrafficStatService(db *gorm.DB) *TrafficStatService {
	return &TrafficStatService{db: db}
}

// TrafficSummary 汇总指标
type TrafficSummary struct {
	Total         int64   `json:"total"`
	Blocked       int64   `json:"blocked"`
	BlockRate     float64 `json:"block_rate"`
	Attacks       int64   `json:"attacks"`
	UniqueIPs     int64   `json:"unique_ips"`
	AvgResponseMS float64 `json:"avg_response_ms"`
}

// TrafficPoint 时间序列点
type TrafficPoint struct {
	Label   string `json:"label"`
	Total   int64  `json:"total"`
	Blocked int64  `json:"blocked"`
	Attacks int64  `json:"attacks"`
}

// NameCount 名称-计数对（状态分布/Top 列表通用）
type NameCount struct {
	Name    string `json:"name"`
	Count   int64  `json:"count"`
	Blocked int64  `json:"blocked"`
}

// TrafficStatReport 统计报告
type TrafficStatReport struct {
	Hours      int            `json:"hours"`
	Summary    TrafficSummary `json:"summary"`
	Series     []TrafficPoint `json:"series"`
	StatusDist []NameCount    `json:"status_dist"`
	TopIPs     []NameCount    `json:"top_ips"`
	TopURIs    []NameCount    `json:"top_uris"`
	TopHosts   []NameCount    `json:"top_hosts"`
}

// Stat 聚合最近 hours 小时的流量统计
func (s *TrafficStatService) Stat(hours int) (*TrafficStatReport, error) {
	if hours < 1 {
		hours = 24
	}
	if hours > 720 {
		hours = 720
	}
	since := time.Now().Add(-time.Duration(hours) * time.Hour)
	sinceStr := since.Format("2006-01-02 15:04:05")

	report := &TrafficStatReport{Hours: hours}

	// 汇总：总量/拦截(status>=400)/攻击/独立 IP/平均耗时
	var summary TrafficSummary
	if err := s.db.Raw(`SELECT
			COUNT(*) AS total,
			COALESCE(SUM(CASE WHEN status >= 400 THEN 1 ELSE 0 END), 0) AS blocked,
			COALESCE(SUM(CASE WHEN attack = 1 THEN 1 ELSE 0 END), 0) AS attacks,
			COUNT(DISTINCT client_ip) AS unique_ips,
			COALESCE(AVG(response_time), 0) AS avg_response_ms
		FROM traffic_logs WHERE time >= ?`, sinceStr).
		Scan(&summary).Error; err != nil {
		return nil, fmt.Errorf("查询流量汇总失败: %w", err)
	}
	if summary.Total > 0 {
		summary.BlockRate = float64(summary.Blocked) / float64(summary.Total) * 100
	}
	report.Summary = summary

	// 时间序列：≤48h 按小时桶，>48h 按天桶；存储为本地时区文本，无需 localtime 修饰
	step := time.Hour
	bucketFmt, goLayout := "%Y-%m-%d %H:00", "2006-01-02 15:00"
	if hours > 48 {
		step = 24 * time.Hour
		bucketFmt, goLayout = "%Y-%m-%d", "2006-01-02"
	}
	type seriesRow struct {
		Label   string
		Total   int64
		Blocked int64
		Attacks int64
	}
	var rows []seriesRow
	if err := s.db.Raw(fmt.Sprintf(`SELECT strftime('%s', time) AS label,
			COUNT(*) AS total,
			COALESCE(SUM(CASE WHEN status >= 400 THEN 1 ELSE 0 END), 0) AS blocked,
			COALESCE(SUM(CASE WHEN attack = 1 THEN 1 ELSE 0 END), 0) AS attacks
		FROM traffic_logs WHERE time >= ?
		GROUP BY label ORDER BY label`, bucketFmt), sinceStr).
		Scan(&rows).Error; err != nil {
		return nil, fmt.Errorf("查询流量趋势失败: %w", err)
	}
	byLabel := make(map[string]seriesRow, len(rows))
	for _, r := range rows {
		byLabel[r.Label] = r
	}
	// Go 端生成期望桶并补零，保证时间轴连续
	for t := since.Truncate(step); !t.After(time.Now()); t = t.Add(step) {
		label := t.Format(goLayout)
		r := byLabel[label]
		report.Series = append(report.Series, TrafficPoint{
			Label:   label[5:], // 去掉年份，图表轴更紧凑
			Total:   r.Total,
			Blocked: r.Blocked,
			Attacks: r.Attacks,
		})
	}

	// 状态码分布
	if err := s.db.Raw(`SELECT CAST(status AS TEXT) AS name, COUNT(*) AS count
		FROM traffic_logs WHERE time >= ? AND status > 0
		GROUP BY status ORDER BY count DESC LIMIT 8`, sinceStr).
		Scan(&report.StatusDist).Error; err != nil {
		return nil, fmt.Errorf("查询状态分布失败: %w", err)
	}

	// TopN（白名单列防注入）
	for _, item := range []struct {
		col string
		dst *[]NameCount
	}{
		{"client_ip", &report.TopIPs},
		{"uri", &report.TopURIs},
		{"host", &report.TopHosts},
	} {
		nc, err := s.queryTop(item.col, sinceStr)
		if err != nil {
			return nil, err
		}
		*item.dst = nc
	}

	return report, nil
}

func (s *TrafficStatService) queryTop(col, sinceStr string) ([]NameCount, error) {
	switch col {
	case "client_ip", "uri", "host":
	default:
		return nil, fmt.Errorf("不支持的统计列: %s", col)
	}
	var out []NameCount
	err := s.db.Raw(fmt.Sprintf(`SELECT %s AS name, COUNT(*) AS count,
			COALESCE(SUM(CASE WHEN status >= 400 THEN 1 ELSE 0 END), 0) AS blocked
		FROM traffic_logs WHERE time >= ? AND %s <> ''
		GROUP BY %s ORDER BY count DESC LIMIT 10`, col, col, col), sinceStr).
		Scan(&out).Error
	if err != nil {
		return nil, fmt.Errorf("查询 Top%s 失败: %w", col, err)
	}
	return out, nil
}
