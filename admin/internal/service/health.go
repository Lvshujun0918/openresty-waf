package service

import (
	"context"
	"encoding/json"
	"errors"
	"sort"
	"time"

	"openresty-waf/admin/internal/config"
)

// EngineStatus 引擎在线状态（来自 Redis 心跳）
type EngineStatus struct {
	PID             int64  `json:"pid"`
	EngineVersion   string `json:"engine_version"`
	RulesetVersion  string `json:"ruleset_version"`
	ConfigVersion   string `json:"config_version"`
	TriggerVersion  string `json:"trigger_version"`
	LastSeen        int64  `json:"last_seen"`
	Online          bool   `json:"online"`
	RuleSynced      bool   `json:"rule_synced"` // 心跳规则版本与后台已下发版本一致
}

// RealtimePoint 实时监控秒级数据点
type RealtimePoint struct {
	Ts     int64 `json:"ts"`
	Total  int64 `json:"total"`
	Attack int64 `json:"attack"`
}

// HealthService 引擎健康状态与实时监控：读取引擎心跳与秒级统计（Redis）。
type HealthService struct {
	mgr *RedisManager
	cfg *config.Config
	ctx context.Context
}

func NewHealthService(mgr *RedisManager, cfg *config.Config) *HealthService {
	return &HealthService{mgr: mgr, cfg: cfg, ctx: context.Background()}
}

const heartbeatPrefix = "waf:heartbeat:"

// ListEngines 扫描心跳键返回引擎在线状态列表
func (s *HealthService) ListEngines() ([]EngineStatus, error) {
	rdb := s.mgr.GetClient()
	if rdb == nil {
		return nil, errors.New("Redis 未配置")
	}
	now := time.Now().Unix()
	published := ""
	if v, err := rdb.Get(s.ctx, s.cfg.Rule.VersionKey).Result(); err == nil {
		published = v
	}
	var out []EngineStatus
	var cursor uint64
	for {
		keys, next, err := rdb.Scan(s.ctx, cursor, heartbeatPrefix+"*", 100).Result()
		if err != nil {
			return nil, err
		}
		for _, k := range keys {
			raw, err := rdb.Get(s.ctx, k).Result()
			if err != nil {
				continue // 心跳刚过期，跳过
			}
			var st EngineStatus
			if err := json.Unmarshal([]byte(raw), &st); err != nil {
				continue
			}
			st.Online = now-st.LastSeen <= 30
			st.RuleSynced = published != "" && st.RulesetVersion == published
			out = append(out, st)
		}
		if next == 0 {
			break
		}
		cursor = next
	}
	sort.Slice(out, func(i, j int) bool { return out[i].PID < out[j].PID })
	return out, nil
}

// Realtime 读取实时统计列表最近 minutes 分钟（秒级窗口聚合）
func (s *HealthService) Realtime(minutes int) ([]RealtimePoint, error) {
	rdb := s.mgr.GetClient()
	if rdb == nil {
		return nil, errors.New("Redis 未配置")
	}
	if minutes <= 0 || minutes > 60 {
		minutes = 10
	}
	n := int64(minutes * 60)
	raws, err := rdb.LRange(s.ctx, "waf:stats:live", -n, -1).Result()
	if err != nil {
		return nil, err
	}
	now := time.Now().Unix()
	out := make([]RealtimePoint, 0, len(raws))
	for _, raw := range raws {
		var p RealtimePoint
		if err := json.Unmarshal([]byte(raw), &p); err != nil {
			continue
		}
		if p.Ts > now+10 || p.Ts < now-int64(minutes)*60-10 {
			continue // 过滤异常/过期数据点
		}
		out = append(out, p)
	}
	return out, nil
}
