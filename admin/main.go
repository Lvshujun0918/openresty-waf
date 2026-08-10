// 管理后台入口：Go + Gin + GORM
package main

import (
	"log"

	"openresty-waf/admin/internal/api"
	"openresty-waf/admin/internal/config"
	"openresty-waf/admin/internal/database"
)

func main() {
	cfg := config.Load()
	db := database.Init(cfg)

	r := api.NewRouter(cfg, db)
	log.Printf("WAF 管理后台启动，监听 %s", cfg.Server.Addr)
	if err := r.Run(cfg.Server.Addr); err != nil {
		log.Fatalf("服务启动失败: %v", err)
	}
}
