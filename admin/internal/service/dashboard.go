package service

import (
	"time"

	"gorm.io/gorm"

	"openresty-waf/admin/internal/model"
)

// DashboardService 仪表盘聚合统计：攻击事件（events）+ 全量流量（traffic_logs）。
// 攻击侧始终有数据；请求/QPS 侧依赖全量记录模式是否开启。
type DashboardService struct {
	db *gorm.DB
}

func NewDashboardService(db *gorm.DB) *DashboardService {
	return &DashboardService{db: db}
}

// GroupCount 攻击类型分布（event.group）
type GroupCount struct {
	Group string `json:"group"`
	Count int64  `json:"count"`
}

// TopIP 攻击来源 Top N（含归属地，取该 IP 最新记录中的归属）
type TopIP struct {
	ClientIP string `json:"client_ip"`
	Count    int64  `json:"count"`
	Country  string `json:"country"`
	Province string `json:"province"`
	City     string `json:"city"`
}

// CountryCount 归属地分布（按国家聚合）
type CountryCount struct {
	Country string `json:"country"`
	Count   int64  `json:"count"`
}

// AttackTrendPoint 某一天命中攻击数（事件表按天）
type AttackTrendPoint struct {
	Date   string `json:"date"`
	Attack int64  `json:"attack"`
}

// DashboardStats 仪表盘一次拉取的全部聚合数据
type DashboardStats struct {
	Today struct {
		Request      int64 `json:"request"`        // 今日请求（流量表）
		Attack       int64 `json:"attack"`         // 今日攻击（事件表）
		Intercept24h int64 `json:"intercept_24h"`  // 近 24 小时拦截
	} `json:"today"`
	Total struct {
		Events  int64 `json:"events"`
		Traffic int64 `json:"traffic"`
	} `json:"total"`
	QPS         float64            `json:"qps"`         // 近 60s 请求+攻击 / 60
	AttackTrend []AttackTrendPoint `json:"attack_trend"` // 近 days 天攻击趋势（事件表）
	Groups      []GroupCount       `json:"groups"`       // 攻击类型分布
	TopIPs      []TopIP            `json:"top_ips"`       // 攻击来源 Top 10
	Countries   []CountryCount     `json:"countries"`     // 归属地分布 Top 8
}

// Stats 聚合仪表盘数据；host 非空时仅统计指定站点域名的数据（多站点隔离）
func (s *DashboardService) Stats(days int, host string) (*DashboardStats, error) {
	if days <= 0 || days > 90 {
		days = 14
	}
	st := &DashboardStats{}
	now := time.Now()
	loc := now.Location()
	todayStart := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, loc)
	dayAgo := now.Add(-24 * time.Hour)
	trendStart := now.Add(-time.Duration(days-1) * 24 * time.Hour)

	ev := s.db.Model(&model.Event{})
	tr := s.db.Model(&model.TrafficLog{})
	if host != "" {
		ev = ev.Where("host = ?", host)
		tr = tr.Where("host = ?", host)
	}

	// —— 今日 / 近24h / 累计 ——
	if err := ev.Where("time >= ?", todayStart).Count(&st.Today.Attack).Error; err != nil {
		return nil, err
	}
	if err := ev.Where("time >= ?", dayAgo).Count(&st.Today.Intercept24h).Error; err != nil {
		return nil, err
	}
	if err := tr.Where("time >= ?", todayStart).Count(&st.Today.Request).Error; err != nil {
		return nil, err
	}
	if err := ev.Count(&st.Total.Events).Error; err != nil {
		return nil, err
	}
	if err := tr.Count(&st.Total.Traffic).Error; err != nil {
		return nil, err
	}

	// —— QPS：近 60s（请求 + 攻击） / 60 ——
	var req60 int64
	if err := tr.Where("time >= ?", now.Add(-60*time.Second)).Count(&req60).Error; err != nil {
		return nil, err
	}
	var atk60 int64
	if err := ev.Where("time >= ?", now.Add(-60*time.Second)).Count(&atk60).Error; err != nil {
		return nil, err
	}
	st.QPS = float64(req60+atk60) / 60.0

	// —— 攻击趋势（事件表按天，缺失补 0） ——
	type atkRow struct {
		Date   string
		Attack int64
	}
	var atkRows []atkRow
	hostCond := ""
	if host != "" {
		hostCond = " AND host = ?"
	}
	if err := s.db.Raw(`SELECT strftime('%Y-%m-%d', time) AS date, COUNT(*) AS attack
		FROM events WHERE time >= ?`+hostCond+
		` GROUP BY strftime('%Y-%m-%d', time) ORDER BY date`,
		append([]interface{}{trendStart.Format("2006-01-02 15:04:05")}, hostArgs(host)...)...).Scan(&atkRows).Error; err != nil {
		return nil, err
	}
	byDate := make(map[string]int64, len(atkRows))
	for _, r := range atkRows {
		byDate[r.Date] = r.Attack
	}
	st.AttackTrend = make([]AttackTrendPoint, 0, days)
	for i := 0; i < days; i++ {
		d := now.Add(-time.Duration(days-1-i) * 24 * time.Hour).Format("2006-01-02")
		st.AttackTrend = append(st.AttackTrend, AttackTrendPoint{Date: d, Attack: byDate[d]})
	}

	// —— 攻击类型分布 ——
	if err := s.db.Raw("SELECT `group`, COUNT(*) AS count FROM events WHERE 1=1"+hostCond+
		" GROUP BY `group` ORDER BY count DESC", hostArgs(host)...).
		Scan(&st.Groups).Error; err != nil {
		return nil, err
	}

	// —— 攻击来源 Top 10（含归属地） ——
	if err := s.db.Raw(`SELECT client_ip, COUNT(*) AS count,
		MAX(country) AS country, MAX(province) AS province, MAX(city) AS city
		FROM events WHERE 1=1`+hostCond+
		` GROUP BY client_ip ORDER BY count DESC LIMIT 10`, hostArgs(host)...).
		Scan(&st.TopIPs).Error; err != nil {
		return nil, err
	}

	// —— 归属地分布 Top 8（国家维度） ——
	if err := s.db.Raw(`SELECT country, COUNT(*) AS count FROM events
		WHERE country IS NOT NULL AND country != ''`+hostCond+
		` GROUP BY country ORDER BY count DESC LIMIT 8`, hostArgs(host)...).
		Scan(&st.Countries).Error; err != nil {
		return nil, err
	}

	return st, nil
}

// hostArgs 站点过滤参数（host 为空时返回空切片）
func hostArgs(host string) []interface{} {
	if host == "" {
		return []interface{}{}
	}
	return []interface{}{host}
}
