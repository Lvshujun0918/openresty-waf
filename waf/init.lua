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
local errlog  = require "errlog"

local _M = {}

local RULES_KEY       = "active_ruleset"   -- 当前生效规则集（JSON 字符串）
local VERSION_KEY     = "ruleset_version"  -- 当前生效版本号
local CANARY_RULES_KEY   = "canary_ruleset"   -- 当前灰度规则集（JSON 字符串）
local CANARY_VERSION_KEY = "canary_version"   -- 当前灰度版本号（不存在/空=未启用）
local CANARY_CFG_KEY     = "canary_cfg"       -- 当前灰度配置（JSON 字符串）
local CONFIG_KEY      = "active_config"    -- 当前生效配置（JSON 字符串）
local CFG_VERSION_KEY = "config_version"   -- 配置版本号
local TRIGGER_RULES_KEY   = "active_trigger_rules"  -- 当前生效触发规则集
local TRIGGER_VERSION_KEY = "trigger_rules_version" -- 触发规则版本号

local function log(level, msg)
    ngx.log(level, "[waf] ", msg)
    -- ERR/WARN 级同步上报后台「报错汇总」（INFO 仅本地日志；report 内部自带防洪）
    if level == ngx.ERR then
        errlog.report("error", "init", msg)
    elseif level == ngx.WARN then
        errlog.report("warn", "init", msg)
    end
end

-- 版本号合法性：必须是纯数字（后台 INCR 生成）且严格大于当前版本。
-- 当前版本为空（规则集未就绪，非数字）时接受首个数字版本。
-- 拒绝非法/回退版本：防 Redis 版本键被误写导致规则降级或旧版本回放。
function _M.version_newer(current, incoming)
    local iv = tonumber(incoming)
    if not iv then
        return false
    end
    local cv = tonumber(current)
    if not cv then
        return true
    end
    return iv > cv
end

-- 规则集结构校验：rules 为非空数组且每条含非空 id 字符串。
-- 不通过则拒绝加载，保持当前生效规则集（热更回滚保护）。
function _M.validate_ruleset(ruleset)
    if type(ruleset) ~= "table" or type(ruleset.rules) ~= "table" then
        return false
    end
    local n = 0
    for _, r in ipairs(ruleset.rules) do
        if type(r) ~= "table" or type(r.id) ~= "string" or r.id == "" then
            return false
        end
        n = n + 1
    end
    return n > 0
end

-- 将当前配置广播到共享内存（供各阶段模块读取，避免重复 require 各自持有旧值）
-- 写入失败重试 3 次（间隔 100ms，init 阶段可用 ngx.sleep）；仍失败仅告警，
-- 各阶段模块会回退读取 config.lua 默认值，不影响业务。
local function publish_config()
    for attempt = 1, 3 do
        local ok, err = storage.set_shared(config.dict.rules, CONFIG_KEY,
                                          storage.encode(config))
        if ok then
            return
        end
        if attempt < 3 then
            log(ngx.WARN, "发布配置到共享内存失败（第 " .. attempt .. " 次）: "
                .. tostring(err) .. "，100ms 后重试")
            ngx.sleep(0.1)
        else
            log(ngx.ERR, "发布配置到共享内存失败: " .. tostring(err))
        end
    end
end

-- 深合并：override 覆盖 t（表递归），返回 t
-- 数组判断：连续整数 key（含空表）。数组字段整体替换，防止名单热更新残留旧元素。
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
    for k, v in pairs(override or {}) do
        if type(v) == "table" and type(t[k]) == "table" and not is_array(v) then
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
        return  -- Redis 中尚无规则，保持空规则集（access 阶段 fail-closed 拦截）
    end

    local current = storage.get_shared(config.dict.rules, VERSION_KEY)
    if current == version then
        return  -- 版本未变化
    end
    if not _M.version_newer(current, version) then
        log(ngx.WARN, "规则版本非法或回退，忽略本次更新: " .. tostring(version))
        return
    end

    local body, err2 = storage.redis_get(config.rule_refresh.ruleset_key)
    if err2 or not body then
        log(ngx.WARN, "读取规则集失败: " .. tostring(err2))
        return
    end

    local ruleset = storage.decode(body)
    if not _M.validate_ruleset(ruleset) then
        -- 热更回滚保护：结构非法时保持当前规则集继续生效
        log(ngx.ERR, "Redis 规则集结构非法，拒绝加载（保持当前规则集）")
        return
    end

    local ok1 = storage.set_shared(config.dict.rules, RULES_KEY, body)
    local ok2 = storage.set_shared(config.dict.rules, VERSION_KEY, version)
    if ok1 and ok2 then
        log(ngx.INFO, "规则集已热更新至版本: " .. tostring(version))
    else
        -- 版本键未写入成功 → 下个轮询周期自动重试（写入顺序保证不会读到中间态）
        log(ngx.WARN, "规则集热更新写入失败: " .. tostring(ok1) .. "/" .. tostring(ok2)
            .. "，将在下个轮询周期重试")
    end
end

local function clear_canary()
    storage.set_shared(config.dict.rules, CANARY_RULES_KEY, nil)
    storage.set_shared(config.dict.rules, CANARY_CFG_KEY, nil)
    storage.set_shared(config.dict.rules, CANARY_VERSION_KEY, nil)
end

-- 从 Redis 拉取灰度规则集并热切换。灰度版本键不存在时清理本地灰度态，
-- 之后全部请求回到稳定规则集；灰度版本允许重新从 1 开始（Abort 后重新发布）。
local function refresh_canary()
    local version, err = storage.redis_get(config.rule_refresh.canary_version_key)
    if err then
        log(ngx.WARN, "读取灰度规则版本失败: " .. tostring(err))
        return
    end
    if not version then
        if storage.get_shared(config.dict.rules, CANARY_VERSION_KEY) then
            clear_canary()
            log(ngx.INFO, "灰度规则集已清除")
        end
        return
    end

    local current = storage.get_shared(config.dict.rules, CANARY_VERSION_KEY)
    if current == version then
        return
    end

    local body, err2 = storage.redis_get(config.rule_refresh.canary_ruleset_key)
    if err2 or not body then
        log(ngx.WARN, "读取灰度规则集失败: " .. tostring(err2))
        return
    end
    local cfg_body, err3 = storage.redis_get(config.rule_refresh.canary_cfg_key)
    if err3 or not cfg_body then
        log(ngx.WARN, "读取灰度配置失败: " .. tostring(err3))
        return
    end

    local ruleset = storage.decode(body)
    if not _M.validate_ruleset(ruleset) then
        log(ngx.ERR, "Redis 灰度规则集结构非法，拒绝加载（保持当前灰度规则集）")
        return
    end
    local cfg = storage.decode(cfg_body)
    local percent = cfg and tonumber(cfg.percent)
    if type(cfg) ~= "table" or percent == nil or percent < 0 or percent > 100 then
        log(ngx.WARN, "Redis 灰度配置非法，忽略本次更新")
        return
    end

    local ok1 = storage.set_shared(config.dict.rules, CANARY_RULES_KEY, body)
    local ok2 = storage.set_shared(config.dict.rules, CANARY_CFG_KEY, cfg_body)
    local ok3 = storage.set_shared(config.dict.rules, CANARY_VERSION_KEY, version)
    if ok1 and ok2 and ok3 then
        log(ngx.INFO, "灰度规则集已热更新至版本: " .. tostring(version))
    else
        log(ngx.WARN, "灰度规则集热更新写入失败: " .. tostring(ok1) .. "/" .. tostring(ok2)
            .. "/" .. tostring(ok3) .. "，将在下个轮询周期重试")
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
    if not _M.version_newer(current, version) then
        log(ngx.WARN, "配置版本非法或回退，忽略本次更新: " .. tostring(version))
        return
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
        log(ngx.WARN, "配置热更新写入失败: " .. tostring(ok1) .. "/" .. tostring(ok2)
            .. "，将在下个轮询周期重试")
    end
end

-- 从 Redis 拉取触发规则集并热切换（host/UA/请求头/IP 等条件筛选，
-- 命中执行人机验证/豁免/CC）
local function refresh_trigger_rules()
    local version, err = storage.redis_get(config.rule_refresh.trigger_version_key)
    if err then
        log(ngx.WARN, "读取触发规则版本失败: " .. tostring(err))
        return
    end
    if not version then
        return  -- 尚未发布触发规则
    end

    local current = storage.get_shared(config.dict.rules, TRIGGER_VERSION_KEY)
    if current == version then
        return
    end
    if not _M.version_newer(current, version) then
        log(ngx.WARN, "触发规则版本非法或回退，忽略本次更新: " .. tostring(version))
        return
    end

    local body, err2 = storage.redis_get(config.rule_refresh.trigger_rules_key)
    if err2 or not body then
        log(ngx.WARN, "读取触发规则集失败: " .. tostring(err2))
        return
    end

    local rs = storage.decode(body)
    if type(rs) ~= "table" then
        log(ngx.WARN, "Redis 返回的触发规则集非法，忽略本次更新")
        return
    end

    local ok1 = storage.set_shared(config.dict.rules, TRIGGER_RULES_KEY, body)
    local ok2 = storage.set_shared(config.dict.rules, TRIGGER_VERSION_KEY, version)
    if ok1 and ok2 then
        log(ngx.INFO, "触发规则集已热更新至版本: " .. tostring(version))
    else
        log(ngx.WARN, "触发规则集热更新写入失败: " .. tostring(ok1) .. "/" .. tostring(ok2)
            .. "，将在下个轮询周期重试")
    end
end

-- ============================================================================
-- 引擎健康心跳：周期写 Redis（含版本号），后台判断在线状态与规则加载进度
-- ============================================================================
local function heartbeat(premature)
    if premature then return end
    -- 字段名与后台 EngineStatus JSON tag 对齐（last_seen/engine_version/...）
    local payload = storage.encode({
        last_seen        = ngx.time(),
        pid              = ngx.worker.pid(),
        engine_version   = config.version or "",
        ruleset_version  = storage.get_shared(config.dict.rules, VERSION_KEY) or "",
        canary_version   = storage.get_shared(config.dict.rules, CANARY_VERSION_KEY) or "",
        config_version   = storage.get_shared(config.dict.rules, CFG_VERSION_KEY) or "",
        trigger_version  = storage.get_shared(config.dict.rules, TRIGGER_VERSION_KEY) or "",
    })
    local key = (config.heartbeat.key_prefix or "waf:heartbeat:") .. ngx.worker.pid()
    local ok, err = storage.redis_set(key, payload, config.heartbeat.ttl or 30)
    if not ok then
        log(ngx.WARN, "心跳上报失败: " .. tostring(err))
    end
end

-- ============================================================================
-- 实时统计聚合：把共享内存中的秒级窗口计数取走并追加到 Redis 列表
-- （多 worker 同时 flush 同一窗口时用 incr(-n) 原子取走，容忍微小误差）
-- ============================================================================
local function flush_stats(premature)
    if premature then return end
    local sec = os.time() - 1  -- 上一秒窗口（当前秒仍在写入中）
    local tkey, bkey = "st:" .. sec, "stb:" .. sec
    local total = storage.get_shared(config.dict.counter, tkey) or 0
    if not total or total <= 0 then return end
    storage.incr_shared(config.dict.counter, tkey, -total, 0, 2)
    local attack = storage.get_shared(config.dict.counter, bkey) or 0
    if attack and attack > 0 then
        storage.incr_shared(config.dict.counter, bkey, -attack, 0, 2)
    end
    local payload = storage.encode({ ts = sec, total = total, attack = attack or 0 })
    local ok, err = storage.redis_rpush_trim(
        config.stats.live_key or "waf:stats:live", payload, config.stats.retention or 3600)
    if not ok then
        log(ngx.WARN, "实时统计上报失败: " .. tostring(err))
    end
end

-- 从 Redis 拉取爬虫画像库并热切换（UA + IP 段验证；bot.lua 版本化缓存读取）
local function refresh_bot_profiles()
    local version, err = storage.redis_get(config.rule_refresh.bot_profiles_version_key)
    if err then
        log(ngx.WARN, "读取爬虫画像版本失败: " .. tostring(err))
        return
    end
    if not version then
        return  -- 尚未发布，引擎使用内置画像
    end
    local current = storage.get_shared(config.dict.rules, "bot_profiles_version")
    if current == version then
        return
    end
    local body, err2 = storage.redis_get(config.rule_refresh.bot_profiles_key)
    if err2 or not body then
        log(ngx.WARN, "读取爬虫画像库失败: " .. tostring(err2))
        return
    end
    local ok1 = storage.set_shared(config.dict.rules, "active_bot_profiles", body)
    local ok2 = storage.set_shared(config.dict.rules, "bot_profiles_version", version)
    if ok1 and ok2 then
        log(ngx.INFO, "爬虫画像库已热更新至版本: " .. tostring(version))
    else
        log(ngx.WARN, "爬虫画像库热更新写入失败，将在下个轮询周期重试")
    end
end

-- worker 定时器主回调：规则 + 运行配置 + 触发规则热更新
local function refresh_from_redis(premature)
    if premature then return end
    refresh_rules()
    refresh_canary()
    refresh_config()
    refresh_trigger_rules()
    refresh_bot_profiles()
end

-- init 阶段：加载配置（规则集完全由 Redis 下发，此处不加载任何内置规则）
function _M.init()
    publish_config()

    -- IP 地理信息库（可选：/opt/waf/ip2region.xdb 缺失时优雅降级，不阻断启动）
    pcall(function()
        local ip_region = require "ip_region"
        ip_region.init()
    end)

    -- 初始空规则集：Redis 尚未下发规则时引擎无可执行规则，
    -- access 阶段检测到空规则集即 fail-closed 拦截（无规则 = 无保护）。
    storage.set_shared(config.dict.rules, RULES_KEY,
                       storage.encode({ version = "", rules = {} }))
    storage.set_shared(config.dict.rules, VERSION_KEY, "")
    clear_canary()

    -- 初始空触发规则集（后台发布后热更新覆盖）
    storage.set_shared(config.dict.rules, TRIGGER_RULES_KEY,
                       storage.encode({ version = "", rules = {} }))
    storage.set_shared(config.dict.rules, TRIGGER_VERSION_KEY, "")

    log(ngx.INFO, "WAF 初始化完成（规则集待 Redis 下发）")
end

-- init_worker 阶段：启动规则热更新轮询 + 心跳 + 实时统计聚合
function _M.init_worker()
    if config.heartbeat and config.heartbeat.enabled ~= false then
        ngx.timer.every(config.heartbeat.interval or 10, heartbeat)
    end
    if config.stats and config.stats.enabled ~= false then
        ngx.timer.every(config.stats.flush_interval or 1, flush_stats)
    end
    -- 规则耗时画像定时上报（rule_perf.lua 内部判断 enabled）
    require("rule_perf").start_timer()
    if not config.rule_refresh.enabled then
        return
    end
    local ok, err = ngx.timer.every(config.rule_refresh.interval, refresh_from_redis)
    if not ok then
        log(ngx.ERR, "启动规则热更新定时器失败: " .. tostring(err))
    end
end

-- 脚本入口：按当前阶段分发（测试环境无 get_phase 时仅加载模块）
if ngx.get_phase then
    local phase = ngx.get_phase()
    if phase == "init" then
        _M.init()
    elseif phase == "init_worker" then
        _M.init_worker()
    end
end

return _M
