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

// ErrorLogKey 引擎推送错误汇总的 Redis 队列 key（与 waf/errlog.lua 一致）
const ErrorLogKey = "waf:error:list"

// ErrorLogService 引擎报错汇总：消费 Redis 队列落库 + 分页查询 + 统计 + 清空。
type ErrorLogService struct {
	db  *gorm.DB
	mgr *RedisManager
	cfg *config.Config
	ctx context.Context
}

func NewErrorLogService(db *gorm.DB, mgr *RedisManager, cfg *config.Config) *ErrorLogService {
	return &ErrorLogService{db: db, mgr: mgr, cfg: cfg, ctx: context.Background()}
}

// Consume 从 Redis 队列批量消费引擎报错并写入 DB，返回本次消费条数
func (s *ErrorLogService) Consume(limit int) (int, error) {
	rdb := s.mgr.GetClient()
	if rdb == nil {
		return 0, errors.New("Redis 未配置")
	}
	raws, err := rdb.RPopCount(s.ctx, ErrorLogKey, limit).Result()
	if err == redis.Nil {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	logs := make([]model.ErrorLog, 0, len(raws))
	for _, raw := range raws {
		var rec model.ErrorLog
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

// List 分页查询报错，支持 level（error/warn）/ source / 关键字（消息/IP/host/req_id）过滤
func (s *ErrorLogService) List(level, source, keyword string, page, pageSize int) ([]model.ErrorLog, int64, error) {
	q := s.db.Model(&model.ErrorLog{})
	if level != "" {
		q = q.Where("level = ?", level)
	}
	if source != "" {
		q = q.Where("source = ?", source)
	}
	if keyword != "" {
		kw := "%" + keyword + "%"
		q = q.Where("message LIKE ? OR client_ip LIKE ? OR host LIKE ? OR req_id LIKE ?", kw, kw, kw, kw)
	}
	var total int64
	if err := q.Count(&total).Error; err != nil {
		return nil, 0, err
	}
	var logs []model.ErrorLog
	if err := q.Order("id desc").Offset((page - 1) * pageSize).Limit(pageSize).Find(&logs).Error; err != nil {
		return nil, 0, err
	}
	return logs, total, nil
}

// Stats 近 24 小时按级别统计（页面顶部横幅用）
func (s *ErrorLogService) Stats() (map[string]int64, error) {
	since := time.Now().Add(-24 * time.Hour)
	var out []struct {
		Level string
		N     int64
	}
	if err := s.db.Model(&model.ErrorLog{}).
		Select("level, COUNT(*) as n").
		Where("time >= ?", since).
		Group("level").
		Scan(&out).Error; err != nil {
		return nil, err
	}
	stats := map[string]int64{"error": 0, "warn": 0}
	for _, r := range out {
		stats[r.Level] = r.N
	}
	return stats, nil
}

// Clear 清空全部报错记录
func (s *ErrorLogService) Clear() error {
	return s.db.Where("1 = 1").Delete(&model.ErrorLog{}).Error
}
