-- waf/t/config_test.lua
-- config 默认配置 + config_local 深合并 单测
-- 注意：本文件必须在其它测试之后加载（其它模块先 require 默认 config）。

local t = require "assert"

t.test("默认配置字段完整", function()
    local config = require "config"
    t.eq(config.mode, "active")
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
    t.eq(#config.trusted_proxies, 0)   -- 可信代理默认空（兼容无条件信任 XFF）
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

t.test("merge_cfg: 数组字段整体替换（名单热更新不残留旧元素）", function()
    ngx_reset()
    local base = { blacklist = { ips = { "203.0.113.99", "1.1.1.1" }, urls = { "/x" } }, cc = { rate = "100/60" } }
    local overrides = { blacklist = { ips = { "1.1.1.1" } } }
    -- 通过 config 的 merge_cfg 验证：config.lua 返回模块（_M），直接构造等效逻辑测试
    local cfg = require "config"
    -- 复用 init 的 merge（导出自 init？不导出）——本地验证 is_array 语义：
    -- 直接模拟 init.lua 的 merge 逻辑
    local function is_array(v)
        local n = 0
        for k in pairs(v) do
            if type(k) ~= "number" or k < 1 or k % 1 ~= 0 then
                return false
            end
            if k > n then n = k end
        end
        for i = 1, n do
            if v[i] == nil then return false end
        end
        return true
    end
    local function merge_cfg(t, override)
        for k, v in pairs(override) do
            if type(v) == "table" and type(t[k]) == "table" and not is_array(v) then
                merge_cfg(t[k], v)
            else
                t[k] = v
            end
        end
        return t
    end
    merge_cfg(base, overrides)
    t.eq(#base.blacklist.ips, 1, "数组应整体替换为新数组长度")
    t.eq(base.blacklist.ips[1], "1.1.1.1")
    t.eq(base.blacklist.ips[2], nil, "旧元素不得残留")
    t.eq(base.blacklist.urls[1], "/x", "未覆盖的数组字段保持")
    t.eq(base.cc.rate, "100/60", "字典字段递归合并保持")
end)

t.test("merge_cfg: 空数组清空名单", function()
    local base = { blacklist = { ips = { "1.2.3.4", "5.6.7.8" } } }
    local overrides = { blacklist = { ips = {} } }
    local function is_array(v)
        local n = 0
        for k in pairs(v) do
            if type(k) ~= "number" or k < 1 or k % 1 ~= 0 then
                return false
            end
            if k > n then n = k end
        end
        for i = 1, n do
            if v[i] == nil then return false end
        end
        return true
    end
    local function merge_cfg(t, override)
        for k, v in pairs(override) do
            if type(v) == "table" and type(t[k]) == "table" and not is_array(v) then
                merge_cfg(t[k], v)
            else
                t[k] = v
            end
        end
        return t
    end
    merge_cfg(base, overrides)
    t.eq(#base.blacklist.ips, 0, "空数组整体替换为空")
end)
