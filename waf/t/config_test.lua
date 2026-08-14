-- waf/t/config_test.lua
-- config 默认配置 + config_local 深合并 单测
-- 注意：本文件必须在其它测试之后加载（其它模块先 require 默认 config）。

local t = require "assert"

t.test("默认配置字段完整", function()
    local config = require "config"
    t.eq(config.mode, "active")
    t.ok(config.modules.ip_check)
    t.eq(config.dict.rules, "waf_rule")
    t.eq(config.dict.counter, "waf_counter")
    t.eq(config.redis.host, "127.0.0.1")
    t.eq(config.redis.port, 6379)
    t.eq(config.rule_refresh.version_key, "waf:rule:version")
    t.eq(config.rule_refresh.ruleset_key, "waf:rule:ruleset")
    t.eq(config.rule_refresh.config_data_key, "waf:config:data")
    t.eq(config.rule_refresh.event_key, "waf:event:list")
    t.eq(config.cc.rate, "100/60")
    t.eq(config.cc.ban_duration, 300)
    t.eq(config.challenge.mode, "basic")
    t.eq(config.challenge.cookie_name, "waf_pass")
    t.ok(config.detection.skip_static.ext[1] == ".js")   -- 静态资源剪枝默认开启
    t.eq(config.block.status, 403)
    t.match(config.block.html, "访问被拒绝")
    t.eq(config.log.backend, "file")
    t.eq(config.log.redis_key, "waf:event:list")
    t.eq(config.whitelist.ips[1], "127.0.0.1")
    t.ok(config.upload.deny_ext[1] == "php")    -- 全量流量记录默认
    t.no(config.traffic_log.enabled)
    t.eq(config.traffic_log.retention_days, 7)
    t.eq(config.traffic_log.redis_key, "waf:traffic:list")end)

t.test("config_local 深合并：覆盖字段且保留其余", function()
    -- 通过 package.preload 模拟部署时生成的 config_local.lua
    local orig = package.loaded["config"]
    package.loaded["config"] = nil
    package.loaded["config_local"] = nil
    package.preload["config_local"] = function()
        return {
            redis = { host = "10.0.0.99" },
            mode = "detect",
            cc = { rate = "5/10" },
        }
    end
    local cfg = require "config"
    -- 覆盖生效
    t.eq(cfg.redis.host, "10.0.0.99")
    t.eq(cfg.mode, "detect")
    t.eq(cfg.cc.rate, "5/10")
    -- 未覆盖字段保留默认
    t.eq(cfg.redis.port, 6379)
    t.eq(cfg.dict.rules, "waf_rule")
    t.eq(cfg.block.status, 403)
    t.eq(cfg.cc.ban_duration, 300)
    -- 恢复
    package.loaded["config"] = orig
    package.loaded["config_local"] = nil
    package.preload["config_local"] = nil
end)

t.test("config_local 深合并：嵌套表字段级覆盖", function()
    local orig = package.loaded["config"]
    package.loaded["config"] = nil
    package.loaded["config_local"] = nil
    package.preload["config_local"] = function()
        return {
            log = { redis_key = "custom:event" },
            whitelist = { urls = { "/health" } },
        }
    end
    local cfg = require "config"
    t.eq(cfg.log.redis_key, "custom:event")
    -- log.enabled 等兄弟字段保留
    t.ok(cfg.log.enabled)
    t.eq(cfg.log.backend, "file")
    -- whitelist.urls 整体替换
    t.eq(#cfg.whitelist.urls, 1)
    t.eq(cfg.whitelist.urls[1], "/health")
    -- whitelist.ips 保留
    t.eq(cfg.whitelist.ips[1], "127.0.0.1")
    package.loaded["config"] = orig
    package.loaded["config_local"] = nil
    package.preload["config_local"] = nil
end)
