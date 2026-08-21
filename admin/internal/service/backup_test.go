package service

import (
	"path/filepath"
	"testing"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"

	"openresty-waf/admin/internal/model"
)

// 验证 VACUUM INTO 在 glebarez/sqlite（modernc）驱动下可用，且快照文件可独立打开并读到数据。
func TestBackupService_Create(t *testing.T) {
	db := newTestDB(t)
	if err := db.Create(&model.User{Username: "admin", PasswordHash: "x"}).Error; err != nil {
		t.Fatalf("seed user: %v", err)
	}

	svc := NewBackupService(db, "sqlite")
	dst := filepath.Join(t.TempDir(), "backup.db")
	if err := svc.Create(dst); err != nil {
		t.Fatalf("Create: %v", err)
	}

	// 打开快照验证数据完整
	snap, err := gorm.Open(sqlite.Open(dst), &gorm.Config{})
	if err != nil {
		t.Fatalf("open snapshot: %v", err)
	}
	var count int64
	if err := snap.Model(&model.User{}).Count(&count).Error; err != nil {
		t.Fatalf("count users in snapshot: %v", err)
	}
	if count != 1 {
		t.Fatalf("expected 1 user in snapshot, got %d", count)
	}
}

// 非 SQLite 驱动应明确拒绝
func TestBackupService_RejectsNonSQLite(t *testing.T) {
	db := newTestDB(t)
	svc := NewBackupService(db, "mysql")
	if err := svc.Create(filepath.Join(t.TempDir(), "x.db")); err == nil {
		t.Fatal("expected error for mysql driver")
	}
}
