-- init.lua
-- WAF 初始化入口：init_by_lua_file 与 init_worker_by_lua_file 共用同一文件，
-- 按当前阶段自动分发。

-- nginx.conf 示例：
--   lua_package_path "/opt/waf/?.lua;;";
--   lua_shared_dict waf_rule    20m;
--   lua_shared_dict waf_counter 50m;
--   init_by_lua_file          /opt/waf/init.lua;
--   init_worker_by_lua_file   /opt/waf/init.lua;

local config  = require "config"
local storage = require "storage"
local builtin = require "ruleset.builtin"

local _M = {}

local RULES_KEY       = "active_ruleset"   -- 当前生效规则集（JSON 字符串）
local VERSION_KEY     = "ruleset_version"  -- 当前生效版本号
local CONFIG_KEY      = "active_config"    -- 当前生效配置（JSON 字符串）
local CFG_VERSION_KEY = "config_version"   -- 配置版本号
local CC_RULES_KEY    = "active_cc_rules"  -- 当前生效 CC 规则集（JSON 字符串）
local CC_VERSION_KEY  = "cc_rules_version" -- CC 规则版本号

local function log(level, msg)
    ngx.log(level, "[waf] ", msg)
end

-- 将当前配置广播到共享内存（供各阶段模块读取，避免重复 require 各自持有旧值）
local function publish_config()
    local ok, err = storage.set_shared(config.dict.rules, CONFIG_KEY,
                                      storage.encode(config))
    if not ok then
        log(ngx.WARN, "发布配置到共享内存失败: " .. tostring(err))
    end
end

-- 深合并：override 覆盖 t（表递归），返回 t
local function merge_cfg(t, override)
    for k, v in pairs(override or {}) do
        if type(v) == "table" and type(t[k]) == "table" then
            merge_cfg(t[k], v)
        else
            t[k] = v
        end
    end
    return t
end

-- 从 Redis 拉取规则集并原子切换
-- 原子性：先写 ruleset，再写 version；读取方以 version 为准，不会读到中间态。
local function refresh_rules()
    local version, err = storage.redis_get(config.rule_refresh.version_key)
    if err then
        log(ngx.WARN, "读取规则版本失败: " .. tostring(err))
        return
    end
    if not version then
        return  -- Redis 中尚无规则，保持内置集
    end

    local current = storage.get_shared(config.dict.rules, VERSION_KEY)
    if current == version then
        return  -- 版本未变化
    end

    local body, err2 = storage.redis_get(config.rule_refresh.ruleset_key)
    if err2 or not body then
        log(ngx.WARN, "读取规则集失败: " .. tostring(err2))
        return
    end

    local ruleset = storage.decode(body)
    if type(ruleset) ~= "table" then
        log(ngx.WARN, "Redis 返回的规则集非法，忽略本次更新")
        return
    end

    local ok1 = storage.set_shared(config.dict.rules, RULES_KEY, body)
    local ok2 = storage.set_shared(config.dict.rules, VERSION_KEY, version)
    if ok1 and ok2 then
        log(ngx.INFO, "规则集已热更新至版本: " .. tostring(version))
    else
        log(ngx.WARN, "规则集热更新写入失败: " .. tostring(ok1) .. "/" .. tostring(ok2))
    end
end

-- 从 Redis 拉取后台下发的运行配置并热更新生效配置
-- 后台配置深合并到当前生效配置（未下发字段保留默认，如 redis 连接）
local function refresh_config()
    local version, err = storage.redis_get(config.rule_refresh.config_version_key)
    if err then
        log(ngx.WARN, "读取配置版本失败: " .. tostring(err))
        return
    end
    if not version then
        return  -- 后台尚未下发配置
    end

    local current = storage.get_shared(config.dict.rules, CFG_VERSION_KEY)
    if current == version then
        return  -- 版本未变化
    end

    local body, err2 = storage.redis_get(config.rule_refresh.config_data_key)
    if err2 or not body then
        log(ngx.WARN, "读取配置失败: " .. tostring(err2))
        return
    end
    local overrides = storage.decode(body)
    if type(overrides) ~= "table" then
        log(ngx.WARN, "Redis 返回的配置非法，忽略本次更新")
        return
    end

    -- 基于当前生效配置深合并，避免覆盖未下发字段（redis 连接等）
    local raw = storage.get_shared(config.dict.rules, CONFIG_KEY)
    local base = storage.decode(raw) or config
    local merged = merge_cfg(base, overrides)

    local ok1 = storage.set_shared(config.dict.rules, CONFIG_KEY, storage.encode(merged))
    local ok2 = storage.set_shared(config.dict.rules, CFG_VERSION_KEY, version)
    if ok1 and ok2 then
        log(ngx.INFO, "配置已热更新至版本: " .. tostring(version))
    else
        log(ngx.WARN, "配置热更新写入失败: " .. tostring(ok1) .. "/" .. tostring(ok2))
    end
end

-- 从 Redis 拉取 CC 防刷规则集并热切换（host/path 精细化阈值）
local function refresh_cc_rules()
    local version, err = storage.redis_get(config.rule_refresh.cc_version_key)
    if err then
        log(ngx.WARN, "读取 CC 规则版本失败: " .. tostring(err))
        return
    end
    if not version then
        return  -- 尚未发布 CC 规则
    end

    local current = storage.get_shared(config.dict.rules, CC_VERSION_KEY)
    if current == version then
        return
    end

    local body, err2 = storage.redis_get(config.rule_refresh.cc_rules_key)
    if err2 or not body then
        log(ngx.WARN, "读取 CC 规则集失败: " .. tostring(err2))
        return
    end

    local rs = storage.decode(body)
    if type(rs) ~= "table" then
        log(ngx.WARN, "Redis 返回的 CC 规则集非法，忽略本次更新")
        return
    end

    local ok1 = storage.set_shared(config.dict.rules, CC_RULES_KEY, body)
    local ok2 = storage.set_shared(config.dict.rules, CC_VERSION_KEY, version)
    if ok1 and ok2 then
        log(ngx.INFO, "CC 规则集已热更新至版本: " .. tostring(version))
    else
        log(ngx.WARN, "CC 规则集热更新写入失败: " .. tostring(ok1) .. "/" .. tostring(ok2))
    end
end

-- worker 定时器主回调：规则 + 运行配置 + CC 规则热更新
local function refresh_from_redis(premature)
    if premature then return end
    refresh_rules()
    refresh_config()
    refresh_cc_rules()
end

-- init 阶段：加载配置与内置规则
function _M.init()
    publish_config()

    -- IP 地理信息库（可选：/opt/waf/ip2region.xdb 缺失时优雅降级，不阻断启动）
    pcall(function()
        local ip_region = require "ip_region"
        ip_region.init()
    end)

    local ok, err = storage.set_shared(config.dict.rules, RULES_KEY,
                                      storage.encode(builtin))
    if not ok then
        log(ngx.ERR, "加载内置规则集失败: " .. tostring(err))
        return
    end
    storage.set_shared(config.dict.rules, VERSION_KEY, builtin.version)

    -- 初始空 CC 规则集（后台发布后热更新覆盖；无规则时引擎回退全局默认）
    storage.set_shared(config.dict.rules, CC_RULES_KEY,
                       storage.encode({ version = "", rules = {} }))
    storage.set_shared(config.dict.rules, CC_VERSION_KEY, "")

    log(ngx.INFO, "WAF 初始化完成，内置规则集: " .. tostring(builtin.version))
end

-- init_worker 阶段：启动规则热更新轮询
function _M.init_worker()
    if not config.rule_refresh.enabled then
        return
    end
    local ok, err = ngx.timer.every(config.rule_refresh.interval, refresh_from_redis)
    if not ok then
        log(ngx.ERR, "启动规则热更新定时器失败: " .. tostring(err))
    end
end

-- 脚本入口：按当前阶段分发
local phase = ngx.get_phase()
if phase == "init" then
    _M.init()
elseif phase == "init_worker" then
    _M.init_worker()
end

return _M
