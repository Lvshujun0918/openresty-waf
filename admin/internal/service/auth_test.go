package service

import (
	"testing"

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
	s := NewAuthService(db, newTestConfig())

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
	s := NewAuthService(nil, newTestConfig())

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
