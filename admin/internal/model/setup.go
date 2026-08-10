package model

// Setup 系统配置键值存储（Redis 连接信息、引导状态等）
type Setup struct {
	ID    uint   `gorm:"primaryKey" json:"id"`
	Key   string `gorm:"uniqueIndex;size:64" json:"key"`
	Value string `gorm:"type:text" json:"value"`
}
