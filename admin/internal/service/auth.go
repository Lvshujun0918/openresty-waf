// Package service 业务逻辑层。
package service

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"

	"openresty-waf/admin/internal/config"
	"openresty-waf/admin/internal/model"
)

// Claims JWT 声明
type Claims struct {
	UserID   uint   `json:"user_id"`
	Username string `json:"username"`
	JTI      string `json:"jti"` // 会话 ID（Redis 记录，用于会话管理/强制下线）
	jwt.RegisteredClaims
}

// 登录防爆破参数
const (
	maxLoginFailures = 5                // 连续失败次数阈值
	lockoutDuration  = 15 * time.Minute // 锁定时长
)

var b32NoPad = base32.StdEncoding.WithPadding(base32.NoPadding)

type AuthService struct {
	db  *gorm.DB
	mgr *RedisManager
	cfg *config.Config
	ctx context.Context
}

func NewAuthService(db *gorm.DB, mgr *RedisManager, cfg *config.Config) *AuthService {
	return &AuthService{db: db, mgr: mgr, cfg: cfg, ctx: context.Background()}
}

// Login 校验用户名密码（无 TOTP），成功返回 JWT。
// 兼容旧调用方；启用 TOTP 的账号请用 LoginWithTOTP。
func (s *AuthService) Login(username, password string) (string, error) {
	return s.LoginWithTOTP(username, password, "", "", "")
}

// LoginWithTOTP 校验用户名密码（启用 TOTP 时同时校验动态验证码），成功返回 JWT。
// clientIP/ua 用于会话记录（会话管理/强制下线）。
// 防爆破：连续失败 maxLoginFailures 次锁定 lockoutDuration；
// 成功后重置失败计数与锁定状态。
func (s *AuthService) LoginWithTOTP(username, password, totpCode, clientIP, ua string) (string, error) {
	var user model.User
	if err := s.db.Where("username = ?", username).First(&user).Error; err != nil {
		return "", errors.New("用户名或密码错误")
	}
	now := time.Now()
	if user.LockedUntil != nil && user.LockedUntil.After(now) {
		return "", errors.New("登录失败次数过多，账号已锁定，请 15 分钟后再试")
	}
	if bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password)) != nil {
		s.recordFailure(&user, now)
		return "", errors.New("用户名或密码错误")
	}
	if user.TotpEnabled {
		if strings.TrimSpace(totpCode) == "" {
			return "", errors.New("该账号已启用动态验证码，请输入 6 位验证码")
		}
		if !s.VerifyTOTP(user.TotpSecret, totpCode) {
			s.recordFailure(&user, now)
			return "", errors.New("动态验证码错误")
		}
	}
	// 登录成功：重置失败计数与锁定状态
	s.db.Model(&model.User{}).Where("id = ?", user.ID).Updates(map[string]interface{}{
		"failed_logins": 0,
		"locked_until":  nil,
	})
	return s.GenerateTokenWithMeta(user, clientIP, ua)
}

// recordFailure 记录一次失败：达到阈值即锁定并重置计数
func (s *AuthService) recordFailure(user *model.User, now time.Time) {
	updates := map[string]interface{}{"failed_logins": user.FailedLogins + 1}
	if user.FailedLogins+1 >= maxLoginFailures {
		locked := now.Add(lockoutDuration)
		updates["locked_until"] = &locked
		updates["failed_logins"] = 0
	}
	_ = s.db.Model(&model.User{}).Where("id = ?", user.ID).Updates(updates).Error
}

// ============================================================================
// TOTP（RFC 6238，HMAC-SHA1，30 秒窗口）
// ============================================================================

func totpCodeAt(secret string, unixSec int64) string {
	key, err := b32NoPad.DecodeString(strings.ToUpper(strings.TrimSpace(secret)))
	if err != nil || len(key) == 0 {
		return ""
	}
	var counter [8]byte
	binary.BigEndian.PutUint64(counter[:], uint64(unixSec/30))
	mac := hmac.New(sha1.New, key)
	_, _ = mac.Write(counter[:])
	sum := mac.Sum(nil)
	offset := sum[len(sum)-1] & 0x0F
	code := (binary.BigEndian.Uint32(sum[offset:offset+4]) & 0x7FFFFFFF) % 1000000
	return fmt.Sprintf("%06d", code)
}

// VerifyTOTP 校验 6 位动态验证码（±1 时间步容差）
func (s *AuthService) VerifyTOTP(secret, code string) bool {
	code = strings.TrimSpace(code)
	if len(code) != 6 {
		return false
	}
	now := time.Now().Unix()
	for _, step := range []int64{-1, 0, 1} {
		if totpCodeAt(secret, now+step*30) == code {
			return true
		}
	}
	return false
}

// SetupTOTP 生成新密钥并暂存（未确认前不生效），返回密钥与 otpauth URL
func (s *AuthService) SetupTOTP(userID uint) (string, string, error) {
	var user model.User
	if err := s.db.First(&user, userID).Error; err != nil {
		return "", "", errors.New("账号不存在")
	}
	buf := make([]byte, 20)
	if _, err := rand.Read(buf); err != nil {
		return "", "", err
	}
	secret := b32NoPad.EncodeToString(buf)
	if err := s.db.Model(&model.User{}).Where("id = ?", userID).
		Update("totp_secret", secret).Error; err != nil {
		return "", "", err
	}
	url := fmt.Sprintf("otpauth://totp/openresty-waf:%s?secret=%s&issuer=openresty-waf",
		user.Username, secret)
	return secret, url, nil
}

// ConfirmTOTP 校验一次动态码后启用 TOTP
func (s *AuthService) ConfirmTOTP(userID uint, code string) error {
	var user model.User
	if err := s.db.First(&user, userID).Error; err != nil {
		return errors.New("账号不存在")
	}
	if user.TotpSecret == "" {
		return errors.New("请先生成密钥")
	}
	if !s.VerifyTOTP(user.TotpSecret, code) {
		return errors.New("动态验证码错误")
	}
	return s.db.Model(&model.User{}).Where("id = ?", userID).
		Update("totp_enabled", true).Error
}

// DisableTOTP 校验一次动态码后关闭 TOTP
func (s *AuthService) DisableTOTP(userID uint, code string) error {
	var user model.User
	if err := s.db.First(&user, userID).Error; err != nil {
		return errors.New("账号不存在")
	}
	if !user.TotpEnabled {
		return nil
	}
	if !s.VerifyTOTP(user.TotpSecret, code) {
		return errors.New("动态验证码错误")
	}
	return s.db.Model(&model.User{}).Where("id = ?", userID).Updates(map[string]interface{}{
		"totp_enabled": false,
		"totp_secret":  "",
	}).Error
}

// TOTPStatus 查询账号 TOTP 启用状态
func (s *AuthService) TOTPStatus(userID uint) (bool, error) {
	var user model.User
	if err := s.db.First(&user, userID).Error; err != nil {
		return false, errors.New("账号不存在")
	}
	return user.TotpEnabled, nil
}

// GenerateToken 签发 JWT 并记录会话（Redis，用于会话管理/强制下线）。
// mgr 未配置 Redis 时退化为无会话状态（仅 JWT 校验，与旧行为一致）。
func (s *AuthService) GenerateToken(user model.User) (string, error) {
	return s.GenerateTokenWithMeta(user, "", "")
}

// GenerateTokenWithMeta 签发 JWT（附带客户端 IP / UA 写入会话记录）
func (s *AuthService) GenerateTokenWithMeta(user model.User, clientIP, ua string) (string, error) {
	expire := time.Duration(s.cfg.JWT.Expire) * time.Hour
	claims := Claims{
		UserID:   user.ID,
		Username: user.Username,
		JTI:      newJTI(),
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(expire)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			Issuer:    "openresty-waf",
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := token.SignedString([]byte(s.cfg.JWT.Secret))
	if err != nil {
		return "", err
	}
	// 会话记录（TTL = token 有效期；踢下线 = 删除该键）
	if s.mgr != nil {
		if rdb := s.mgr.GetClient(); rdb != nil {
			entry := map[string]interface{}{
				"user_id": user.ID, "username": user.Username,
				"ip": clientIP, "ua": ua, "created_at": time.Now().Unix(),
			}
			if body, err2 := json.Marshal(entry); err2 == nil {
				_ = rdb.Set(s.ctx, sessionKey(claims.JTI), string(body), expire).Err()
			}
		}
	}
	return signed, nil
}

// newJTI 随机会话 ID
func newJTI() string {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return fmt.Sprintf("%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(buf)
}

func sessionKey(jti string) string {
	return "waf:session:" + jti
}

// ParseToken 校验并解析 JWT（会话已被踢下线时返回错误）
func (s *AuthService) ParseToken(tokenStr string) (*Claims, error) {
	token, err := jwt.ParseWithClaims(tokenStr, &Claims{}, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.New("非法签名算法")
		}
		return []byte(s.cfg.JWT.Secret), nil
	})
	if err != nil {
		return nil, err
	}
	claims, ok := token.Claims.(*Claims)
	if !ok || !token.Valid {
		return nil, errors.New("无效 token")
	}
	// 会话校验：Redis 中无对应会话（被踢下线/会话过期）→ 拒绝
	if claims.JTI != "" && s.mgr != nil {
		if rdb := s.mgr.GetClient(); rdb != nil {
			exists, err := rdb.Exists(s.ctx, sessionKey(claims.JTI)).Result()
			if err == nil && exists == 0 {
				return nil, errors.New("会话已失效")
			}
		}
	}
	return claims, nil
}

// Session 会话记录（列表展示）
type Session struct {
	JTI       string `json:"jti"`
	UserID    uint   `json:"user_id"`
	Username  string `json:"username"`
	ClientIP  string `json:"ip"`
	UserAgent string `json:"ua"`
	CreatedAt int64  `json:"created_at"`
}

// ListSessions 当前全部登录会话（按创建时间倒序）
func (s *AuthService) ListSessions() ([]Session, error) {
	rdb := s.mgr.GetClient()
	if rdb == nil {
		return nil, errors.New("Redis 未配置")
	}
	var out []Session
	var cursor uint64
	for {
		keys, next, err := rdb.Scan(s.ctx, cursor, "waf:session:*", 100).Result()
		if err != nil {
			return nil, err
		}
		for _, k := range keys {
			raw, err := rdb.Get(s.ctx, k).Result()
			if err != nil {
				continue
			}
			var sess Session
			if err := json.Unmarshal([]byte(raw), &sess); err != nil {
				continue
			}
			sess.JTI = strings.TrimPrefix(k, "waf:session:")
			out = append(out, sess)
		}
		if next == 0 {
			break
		}
		cursor = next
	}
	return out, nil
}

// KickSession 强制下线指定会话（删除 Redis 记录，该 JWT 立即失效）
func (s *AuthService) KickSession(jti string) error {
	rdb := s.mgr.GetClient()
	if rdb == nil {
		return errors.New("Redis 未配置")
	}
	return rdb.Del(s.ctx, sessionKey(jti)).Err()
}
