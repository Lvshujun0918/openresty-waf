// Package service API Token 服务：生成/校验/吊销。
package service

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"time"

	"gorm.io/gorm"

	"openresty-waf/admin/internal/model"
)

// ErrTokenInvalid 令牌不存在/已吊销/格式非法。
var ErrTokenInvalid = errors.New("api token 无效")

const apiTokenPrefix = "waf_" // 明文统一前缀，便于识别与 secret 扫描

// ApiTokenService API Token 管理。
type ApiTokenService struct {
	db *gorm.DB
}

func NewApiTokenService(db *gorm.DB) *ApiTokenService {
	return &ApiTokenService{db: db}
}

func hashToken(plain string) string {
	sum := sha256.Sum256([]byte(plain))
	return hex.EncodeToString(sum[:])
}

// Create 生成新令牌，明文仅此一次返回。
func (s *ApiTokenService) Create(name string) (*model.ApiToken, string, error) {
	buf := make([]byte, 24)
	if _, err := rand.Read(buf); err != nil {
		return nil, "", err
	}
	plain := apiTokenPrefix + hex.EncodeToString(buf)
	t := &model.ApiToken{
		Name:      name,
		Prefix:    plain[:len(apiTokenPrefix)+8],
		TokenHash: hashToken(plain),
	}
	if err := s.db.Create(t).Error; err != nil {
		return nil, "", err
	}
	return t, plain, nil
}

// List 全部令牌（不含哈希）。
func (s *ApiTokenService) List() ([]model.ApiToken, error) {
	var list []model.ApiToken
	err := s.db.Order("id DESC").Find(&list).Error
	return list, err
}

// Revoke 吊销令牌（软删除，保留审计线索）。
func (s *ApiTokenService) Revoke(id uint) error {
	now := time.Now()
	res := s.db.Model(&model.ApiToken{}).
		Where("id = ? AND revoked_at IS NULL", id).Update("revoked_at", now)
	if res.Error != nil {
		return res.Error
	}
	if res.RowsAffected == 0 {
		return gorm.ErrRecordNotFound
	}
	return nil
}

// Verify 校验明文令牌；有效则更新最后使用时间并返回名称。
// 最后使用时间写入做 60s 节流，避免高频脚本调用造成写放大。
func (s *ApiTokenService) Verify(plain string) (string, error) {
	plain = strings.TrimSpace(plain)
	if !strings.HasPrefix(plain, apiTokenPrefix) {
		return "", ErrTokenInvalid
	}
	var t model.ApiToken
	if err := s.db.Where("token_hash = ? AND revoked_at IS NULL", hashToken(plain)).
		First(&t).Error; err != nil {
		return "", ErrTokenInvalid
	}
	now := time.Now()
	if t.LastUsedAt == nil || now.Sub(*t.LastUsedAt) > time.Minute {
		_ = s.db.Model(&t).Update("last_used_at", now).Error
	}
	return t.Name, nil
}
