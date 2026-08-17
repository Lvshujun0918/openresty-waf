package service

import (
	"fmt"
	"strings"
	"time"

	"gorm.io/gorm"

	"openresty-waf/admin/internal/model"
)

// 内置订阅名称（订阅库中预置，由用户启停/同步；数据内置于系统，不依赖外部 URL）
const (
	BuiltinProfileSubName = "内置爬虫画像库"
	BuiltinJa4SubName     = "内置JA4客户端库"
)

// 内置爬虫画像库数据（JSON 数组：name/ua/ips/engine，与 syncBotProfiles 解析格式一致）
const builtinProfileJSON = `[
{"name":"Googlebot","ua":"Googlebot|Google-InspectionTool|Mediapartners-Google","ips":["66.249.64.0/19","64.233.160.0/19","66.249.80.0/20","216.58.192.0/19"],"engine":true},
{"name":"Bingbot","ua":"bingbot|adidxbot","ips":["40.77.0.0/16","157.55.0.0/16","13.64.0.0/16","52.160.0.0/11"],"engine":true},
{"name":"Baiduspider","ua":"Baiduspider","ips":["220.181.108.0/24","119.63.192.0/21","123.125.68.0/24","180.76.15.0/24","116.179.32.0/19"],"engine":true},
{"name":"Sogou","ua":"Sogou.*spider|Sogou web spider","ips":["61.135.162.0/24","220.181.0.0/16"],"engine":true},
{"name":"360Spider","ua":"360Spider|haosouSpider","ips":["60.191.0.0/16","221.200.0.0/16","180.163.220.0/24"],"engine":true},
{"name":"YandexBot","ua":"YandexBot|YandexImages|YaDirectFetcher","ips":["77.88.0.0/18","5.255.192.0/18","213.180.192.0/19"],"engine":true},
{"name":"bytespider","ua":"bytespider","ips":["108.160.160.0/19","8.39.224.0/24"],"engine":true},
{"name":"facebookexternalhit","ua":"facebookexternalhit|Facebot","ips":["69.171.224.0/19","31.13.24.0/21"],"engine":true},
{"name":"curl","ua":"^curl/","ips":[],"engine":false},
{"name":"python-requests","ua":"^python-requests/","ips":[],"engine":false},
{"name":"Go-http-client","ua":"^Go-http-client/","ips":[],"engine":false},
{"name":"Java/OkHttp","ua":"^Java/|OkHttp/","ips":[],"engine":false},
{"name":"Scrapy","ua":"Scrapy","ips":[],"engine":false},
{"name":"Wget","ua":"^Wget/","ips":[],"engine":false},
{"name":"AhrefsBot","ua":"AhrefsBot","ips":[],"engine":false},
{"name":"SemrushBot","ua":"SemrushBot","ips":[],"engine":false},
{"name":"MJ12bot","ua":"MJ12bot","ips":[],"engine":false},
{"name":"PetalBot","ua":"PetalBot","ips":[],"engine":false}
]`

// 内置 JA4 客户端库数据（CSV：名称,ja4[,分类]，与 parseJa4ProfileCSV 解析格式一致）
const builtinJa4CSV = `# 恶意软件（malware 类自动联动恶意指纹库拦截）
Cobalt Strike v4.9.1 beacon,t12i190700_d83cc789557e_16bbda4055b2,malware
Cobalt Strike v4.9.1 beacon,t12i210700_76e208dd3e22_16bbda4055b2,malware
Cobalt Strike v4.9.1 beacon,t12d190800_d83cc789557e_16bbda4055b2,malware
Cobalt Strike v4.9.1 beacon,t12d210800_76e208dd3e22_16bbda4055b2,malware
IcedID,t13d201100_2b729b4bf6f3_9e7b989ebec8,malware
Sliver Agent,t13d190900_9dc949149365_97f8aa674fd9,malware
Sliver Agent,t13i190800_9dc949149365_97f8aa674fd9,malware
# 浏览器
Chromium Browser,t13d1516h2_8daaf6152771_02713d6af862,browser
Chromium Browser,t13d1517h2_8daaf6152771_b0da82dd1658,browser
Chromium Browser,t13d1517h2_8daaf6152771_b1ff8ab2d16f,browser
Chromium Browser,t13i1515h2_8daaf6152771_02713d6af862,browser
Chromium Browser,t13i1516h2_8daaf6152771_b0da82dd1658,browser
Chromium Browser,t13i1516h2_8daaf6152771_b1ff8ab2d16f,browser
Mozilla Firefox,t13d1715h2_5b57614c22b0_7121afd63204,browser
Mozilla Firefox,t13i1714h2_5b57614c22b0_7121afd63204,browser
Safari,t13d2014h2_a09f3c656075_14788d8d241b,browser
Safari,t13i2013h2_a09f3c656075_14788d8d241b,browser
# 工具/库
Python,t13i181000_85036bcba153_d41ae481755e,tool
Python,t13d181000_85036bcba153_d41ae481755e,tool
Python,t13d4312h1_c7886603b240_b26ce05bbdd6,tool
GoLang net package,t13d191000_9dc949149365_e7c285222651,tool
GoLang webhooks,t13d1412h2_e33ad33b3d25_6b314db333b6,tool
GoLang,t12d160700_8cdfa2d4673b_18dd7303c4a5,tool
GoLang,t13d141000_cbb2034c60b8_e7c285222651,tool
WinINET / GoLang,t12d190800_d83cc789557e_7af1ed941c26,tool
SoftEther VPN Client,t13d880900_fcb5b95cb75a_b0d3b4ac2a14,tool
SoftEther VPN Client,t13i880900_fcb5b95cb75a_b0d3b4ac2a14,tool
Unknown Client,t12d520600_b380db6257eb_0a9c83bf8b96,tool
Unknown Client,t12d8008h1_9cedc1f1428b_046e095b7c4a,tool
Unknown Client,t12d350600_9d4c96c0953b_0a9c83bf8b96,tool
`

// EnsureBuiltinSubscriptions 初始化内置订阅（画像库 / JA4 客户端库）：
// 不存在则创建并完成首次同步（替换旧的 seed 数据），已存在则跳过。
func (s *IpListService) EnsureBuiltinSubscriptions() error {
	now := time.Now()
	for _, seed := range []struct {
		name   string
		target string
		data   string
	}{
		{BuiltinProfileSubName, "bot_profile", builtinProfileJSON},
		{BuiltinJa4SubName, "ja4_profile", builtinJa4CSV},
	} {
		var sub model.IpListSubscription
		err := s.db.Where("name = ?", seed.name).First(&sub).Error
		if err == nil {
			continue // 已存在（含旧版内置订阅），保持用户启停状态
		}
		if err != gorm.ErrRecordNotFound {
			return err
		}
		sub = model.IpListSubscription{
			Name: seed.name, Target: seed.target, Data: seed.data,
			IntervalMin: 1440, Enabled: true, CreatedAt: now, UpdatedAt: now,
		}
		if err := s.db.Create(&sub).Error; err != nil {
			return err
		}
		// 首次同步前清理旧的 seed 数据，避免与订阅条目重复：
		// 画像库以订阅为准全量重建；JA4 库仅替换 seed 条目（保留手工新增）。
		switch seed.target {
		case "bot_profile":
			if err := s.db.Session(&gorm.Session{AllowGlobalUpdate: true}).
				Delete(&model.BotProfile{}).Error; err != nil {
				return err
			}
		case "ja4_profile":
			if err := s.db.Where("source = ?", "seed").Delete(&model.Ja4Profile{}).Error; err != nil {
				return err
			}
		}
		if _, err := s.Sync(sub.ID); err != nil {
			return fmt.Errorf("内置订阅[%s]首次同步失败: %w", seed.name, err)
		}
	}
	return nil
}

// builtinSubNames 返回内置订阅名称列表（前端展示"内置"标记）
func builtinSubNames() map[string]bool {
	return map[string]bool{BuiltinProfileSubName: true, BuiltinJa4SubName: true}
}

// isBuiltinName 判断订阅是否为内置订阅
func isBuiltinName(name string) bool {
	n := strings.TrimSpace(name)
	return n == BuiltinProfileSubName || n == BuiltinJa4SubName
}
