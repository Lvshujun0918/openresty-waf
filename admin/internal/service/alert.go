package service

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/smtp"
	"strings"
	"time"

	"gorm.io/gorm"

	"openresty-waf/admin/internal/config"
	"openresty-waf/admin/internal/model"
)

// NotifyRequest 通知内容
type NotifyRequest struct {
	Title   string
	Content string
	Level   string // info | warning | critical
}

// AlertService 告警：通知通道管理 + 规则触发检查（定时任务调用）+ 通知发送。
type AlertService struct {
	db  *gorm.DB
	hsv *HealthService
	cfg *config.Config
}

func NewAlertService(db *gorm.DB, mgr *RedisManager, cfg *config.Config) *AlertService {
	return &AlertService{db: db, hsv: NewHealthService(mgr, cfg), cfg: cfg}
}

// ============================================================================
// 通知通道
// ============================================================================

func (s *AlertService) ListChannels() ([]model.AlertChannel, error) {
	var list []model.AlertChannel
	if err := s.db.Order("id asc").Find(&list).Error; err != nil {
		return nil, err
	}
	return list, nil
}

func (s *AlertService) CreateChannel(ch *model.AlertChannel) error {
	if ch.Name == "" || ch.Type == "" {
		return errors.New("名称与类型不能为空")
	}
	return s.db.Create(ch).Error
}

func (s *AlertService) UpdateChannel(id uint, ch *model.AlertChannel) error {
	var existing model.AlertChannel
	if err := s.db.First(&existing, id).Error; err != nil {
		return errors.New("通道不存在")
	}
	updates := map[string]interface{}{
		"name": ch.Name, "type": ch.Type, "enabled": ch.Enabled,
		"webhook_url": ch.WebhookURL, "smtp_host": ch.SMTPHost, "smtp_port": ch.SMTPPort,
		"smtp_user": ch.SMTPUser, "smtp_from": ch.SMTPFrom, "updated_at": time.Now(),
	}
	if ch.Secret != "" { // 留空保持原值（不回显）
		updates["secret"] = ch.Secret
	}
	if ch.SMTPPass != "" {
		updates["smtp_pass"] = ch.SMTPPass
	}
	return s.db.Model(&existing).Updates(updates).Error
}

func (s *AlertService) DeleteChannel(id uint) error {
	var cnt int64
	if err := s.db.Model(&model.AlertRule{}).Where("channel_id = ?", id).Count(&cnt).Error; err != nil {
		return err
	}
	if cnt > 0 {
		return errors.New("该通道正被告警规则引用，请先删除相关规则")
	}
	return s.db.Delete(&model.AlertChannel{}, id).Error
}

// TestChannel 发送测试通知验证通道配置
func (s *AlertService) TestChannel(id uint) error {
	var ch model.AlertChannel
	if err := s.db.First(&ch, id).Error; err != nil {
		return errors.New("通道不存在")
	}
	return s.send(&ch, NotifyRequest{
		Title:   "WAF 告警测试",
		Content: "这是一条测试通知：告警通道配置正常。",
		Level:   "info",
	})
}

// ============================================================================
// 告警规则
// ============================================================================

func (s *AlertService) ListRules() ([]model.AlertRule, error) {
	var list []model.AlertRule
	if err := s.db.Order("id asc").Find(&list).Error; err != nil {
		return nil, err
	}
	return list, nil
}

func (s *AlertService) CreateRule(r *model.AlertRule) error {
	if r.Name == "" {
		return errors.New("名称不能为空")
	}
	if r.Type != "event_surge" && r.Type != "engine_offline" {
		return errors.New("类型必须是 event_surge 或 engine_offline")
	}
	if r.Action != "rollback_rules" {
		r.Action = "notify"
	}
	if r.WindowSec <= 0 {
		r.WindowSec = 60
	}
	if r.CooldownSec <= 0 {
		r.CooldownSec = 300
	}
	if err := s.db.First(&model.AlertChannel{}, r.ChannelID).Error; err != nil {
		return errors.New("通知通道不存在")
	}
	return s.db.Create(r).Error
}

func (s *AlertService) UpdateRule(id uint, r *model.AlertRule) error {
	var existing model.AlertRule
	if err := s.db.First(&existing, id).Error; err != nil {
		return errors.New("规则不存在")
	}
	if r.Action != "rollback_rules" {
		r.Action = "notify"
	}
	return s.db.Model(&existing).Updates(map[string]interface{}{
		"name": r.Name, "type": r.Type, "window_sec": r.WindowSec, "threshold": r.Threshold,
		"action": r.Action, "channel_id": r.ChannelID, "cooldown_sec": r.CooldownSec,
		"enabled": r.Enabled, "updated_at": time.Now(),
	}).Error
}

func (s *AlertService) DeleteRule(id uint) error {
	return s.db.Delete(&model.AlertRule{}, id).Error
}

func (s *AlertService) SetRuleEnabled(id uint, enabled bool) error {
	return s.db.Model(&model.AlertRule{}).Where("id = ?", id).
		Update("enabled", enabled).Error
}

// ============================================================================
// 触发检查（定时任务每 10s 调用）
// ============================================================================

// CheckAll 检查所有启用规则，命中则发送通知（含防抖）；返回本次触发数量
func (s *AlertService) CheckAll() int {
	rules, err := s.ListRules()
	if err != nil {
		return 0
	}
	triggered := 0
	for i := range rules {
		r := rules[i]
		if !r.Enabled {
			continue
		}
		if r.LastTriggeredAt != nil &&
			time.Since(*r.LastTriggeredAt) < time.Duration(r.CooldownSec)*time.Second {
			continue // 冷却期内
		}
		var hit bool
		var content string
		switch r.Type {
		case "event_surge":
			hit, content = s.checkEventSurge(&r)
		case "engine_offline":
			hit, content = s.checkEngineOffline(&r)
		}
		if !hit {
			continue
		}
		if s.triggerRule(&r, content) {
			triggered++
		}
	}
	return triggered
}

// checkEventSurge 窗口内攻击事件数超阈值
func (s *AlertService) checkEventSurge(r *model.AlertRule) (bool, string) {
	var count int64
	cutoff := time.Now().Add(-time.Duration(r.WindowSec) * time.Second)
	if err := s.db.Model(&model.Event{}).Where("time >= ?", cutoff).Count(&count).Error; err != nil {
		return false, ""
	}
	if count < int64(r.Threshold) {
		return false, ""
	}
	return true, fmt.Sprintf("近 %d 秒检测到 %d 条攻击事件（阈值 %d）", r.WindowSec, count, r.Threshold)
}

// checkEngineOffline 全部引擎离线（无在线心跳）
func (s *AlertService) checkEngineOffline(r *model.AlertRule) (bool, string) {
	engines, err := s.hsv.ListEngines()
	if err != nil {
		return false, ""
	}
	if len(engines) > 0 {
		for _, e := range engines {
			if e.Online {
				return false, ""
			}
		}
	}
	return true, "全部引擎心跳超时（离线），请检查 OpenResty 服务状态"
}

// triggerRule 命中后的处置：发送通知 + 可选自动回滚规则，更新防抖时间
func (s *AlertService) triggerRule(r *model.AlertRule, content string) bool {
	var ch model.AlertChannel
	if err := s.db.First(&ch, r.ChannelID).Error; err != nil || !ch.Enabled {
		return false
	}
	title := fmt.Sprintf("[WAF 告警] %s", r.Name)
	_ = s.send(&ch, NotifyRequest{Title: title, Content: content, Level: "warning"})
	if r.Action == "rollback_rules" {
		if err := s.rollbackLastPublish(); err == nil {
			content += "\n已自动回滚到最近一次规则发布快照"
		}
	}
	now := time.Now()
	return s.db.Model(&model.AlertRule{}).Where("id = ?", r.ID).
		Update("last_triggered_at", &now).Error == nil
}

// rollbackLastPublish 回滚到最近一次 rules 发布历史
func (s *AlertService) rollbackLastPublish() error {
	var h model.PublishHistory
	if err := s.db.Where("kind = ?", "rules").Order("id desc").First(&h).Error; err != nil {
		return err
	}
	ruleSvc := NewRuleService(s.db, nil, s.cfg)
	return ruleSvc.Rollback(h.ID)
}

// ============================================================================
// 发送
// ============================================================================

func (s *AlertService) send(ch *model.AlertChannel, req NotifyRequest) error {
	switch ch.Type {
	case "email":
		return s.sendEmail(ch, req)
	default: // webhook / dingtalk / wecom / feishu
		return s.sendWebhook(ch, req)
	}
}

// sendWebhook 按通道类型构造对应平台 JSON 格式后 POST
func (s *AlertService) sendWebhook(ch *model.AlertChannel, req NotifyRequest) error {
	if !strings.HasPrefix(ch.WebhookURL, "http") {
		return errors.New("webhook 地址非法")
	}
	var body map[string]interface{}
	switch ch.Type {
	case "dingtalk":
		body = map[string]interface{}{
			"msgtype": "markdown",
			"markdown": map[string]interface{}{
				"title": req.Title,
				"text":  fmt.Sprintf("### %s\n\n%s\n\n级别：%s\n时间：%s", req.Title, req.Content, req.Level, time.Now().Format("2006-01-02 15:04:05")),
			},
		}
	case "wecom":
		body = map[string]interface{}{
			"msgtype": "markdown",
			"markdown": map[string]interface{}{
				"content": fmt.Sprintf("**%s**\n> %s\n> 级别：%s　时间：%s", req.Title, req.Content, req.Level, time.Now().Format("2006-01-02 15:04:05")),
			},
		}
	case "feishu":
		body = map[string]interface{}{
			"msg_type": "text",
			"content":  map[string]interface{}{"text": fmt.Sprintf("%s\n%s\n级别：%s　时间：%s", req.Title, req.Content, req.Level, time.Now().Format("2006-01-02 15:04:05"))},
		}
	default: // webhook 通用 JSON
		body = map[string]interface{}{
			"title": req.Title, "content": req.Content, "level": req.Level,
			"time": time.Now().Format("2006-01-02 15:04:05"),
		}
	}
	payload, err := json.Marshal(body)
	if err != nil {
		return err
	}
	resp, err := (&http.Client{Timeout: 10 * time.Second}).Post(ch.WebhookURL, "application/json", bytes.NewReader(payload))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("webhook 返回状态码 %d", resp.StatusCode)
	}
	return nil
}

// sendEmail 通过 SMTP 发送邮件
func (s *AlertService) sendEmail(ch *model.AlertChannel, req NotifyRequest) error {
	if ch.SMTPHost == "" || ch.SMTPPort == 0 || ch.SMTPFrom == "" {
		return errors.New("SMTP 配置不完整（host/port/from）")
	}
	addr := fmt.Sprintf("%s:%d", ch.SMTPHost, ch.SMTPPort)
	msg := fmt.Sprintf("From: %s\r\nTo: %s\r\nSubject: %s\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=UTF-8\r\n\r\n%s\n\n级别：%s\n时间：%s",
		ch.SMTPFrom, ch.SMTPFrom, req.Title, req.Content, req.Level, time.Now().Format("2006-01-02 15:04:05"))
	var auth smtp.Auth
	if ch.SMTPUser != "" {
		auth = smtp.PlainAuth("", ch.SMTPUser, ch.SMTPPass, ch.SMTPHost)
	}
	return smtp.SendMail(addr, auth, ch.SMTPFrom, []string{ch.SMTPFrom}, []byte(msg))
}
