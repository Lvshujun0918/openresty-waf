package service

import (
	"fmt"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"

	"openresty-waf/admin/internal/model"
)

func seedUser(t *testing.T, db *gorm.DB, username, password string) {
	t.Helper()
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.MinCost)
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	if err := db.Create(&model.User{Username: username, PasswordHash: string(hash)}).Error; err != nil {
		t.Fatalf("create user: %v", err)
	}
}

func TestAuthService_Login(t *testing.T) {
	db := newTestDB(t)
	seedUser(t, db, "admin", "secret")
	s := NewAuthService(db, nil, newTestConfig())

	token, err := s.Login("admin", "secret")
	if err != nil {
		t.Fatalf("expected login ok, got %v", err)
	}
	if token == "" {
		t.Fatal("token should not be empty")
	}

	if _, err := s.Login("admin", "wrong"); err == nil {
		t.Fatal("expected error for wrong password")
	}
	if _, err := s.Login("nobody", "x"); err == nil {
		t.Fatal("expected error for unknown user")
	}
}

func TestAuthService_TokenRoundTrip(t *testing.T) {
	s := NewAuthService(nil, nil, newTestConfig())

	token, err := s.GenerateToken(model.User{ID: 7, Username: "u1"})
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	claims, err := s.ParseToken(token)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if claims.UserID != 7 || claims.Username != "u1" {
		t.Fatalf("bad claims: %+v", claims)
	}

	if _, err := s.ParseToken("invalid.token.here"); err == nil {
		t.Fatal("expected parse error for invalid token")
	}
	if _, err := s.ParseToken(""); err == nil {
		t.Fatal("expected parse error for empty token")
	}
}

func TestAuthService_LoginLockout(t *testing.T) {
	db := newTestDB(t)
	seedUser(t, db, "admin", "secret")
	s := NewAuthService(db, nil, newTestConfig())

	// 连续失败 5 次
	for i := 0; i < 5; i++ {
		if _, err := s.Login("admin", "wrong"); err == nil {
			t.Fatal("expected error for wrong password")
		}
	}
	// 锁定后即使密码正确也拒绝
	if _, err := s.Login("admin", "secret"); err == nil {
		t.Fatal("expected locked error")
	}
	// 锁定过期后（模拟时间流逝）恢复登录
	if err := db.Model(&model.User{}).Where("username = ?", "admin").
		Update("locked_until", nil).Error; err != nil {
		t.Fatalf("unlock: %v", err)
	}
	if _, err := s.Login("admin", "secret"); err != nil {
		t.Fatalf("expected login ok after unlock, got %v", err)
	}
}

func TestAuthService_TOTPFlow(t *testing.T) {
	db := newTestDB(t)
	seedUser(t, db, "admin", "secret")
	s := NewAuthService(db, nil, newTestConfig())
	var u model.User
	if err := db.Where("username = ?", "admin").First(&u).Error; err != nil {
		t.Fatalf("find user: %v", err)
	}

	secret, url, err := s.SetupTOTP(u.ID)
	if err != nil {
		t.Fatalf("setup: %v", err)
	}
	if secret == "" || url == "" {
		t.Fatal("secret/url should not be empty")
	}

	// 用确定错误的验证码确认失败
	good := totpCodeAt(secret, time.Now().Unix())
	wrong := fmt.Sprintf("%06d", (mustInt(good)+1)%1000000)
	if err := s.ConfirmTOTP(u.ID, wrong); err == nil {
		t.Fatal("expected error for wrong code")
	}
	// 正确验证码确认启用
	if err := s.ConfirmTOTP(u.ID, totpCodeAt(secret, time.Now().Unix())); err != nil {
		t.Fatalf("confirm: %v", err)
	}
	// 启用后无验证码登录失败
	if _, err := s.Login("admin", "secret"); err == nil {
		t.Fatal("expected totp required")
	}
	// 错误验证码登录失败
	if _, err := s.LoginWithTOTP("admin", "secret", wrong, "", ""); err == nil {
		t.Fatal("expected wrong totp error")
	}
	// 正确验证码登录成功
	if _, err := s.LoginWithTOTP("admin", "secret", totpCodeAt(secret, time.Now().Unix()), "", ""); err != nil {
		t.Fatalf("login with totp: %v", err)
	}
	// 关闭 TOTP 后无验证码登录成功
	if err := s.DisableTOTP(u.ID, totpCodeAt(secret, time.Now().Unix())); err != nil {
		t.Fatalf("disable: %v", err)
	}
	if _, err := s.Login("admin", "secret"); err != nil {
		t.Fatalf("login after disable: %v", err)
	}
}

func mustInt(s string) int {
	var n int
	_, _ = fmt.Sscanf(s, "%d", &n)
	return n
}
