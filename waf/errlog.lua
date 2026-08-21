-- errlog.lua
-- 引擎错误汇总上报：在 ngx.log 之外，将 ERR/WARN 级错误异步推送到 Redis 队列
-- （默认 waf:error:list），由管理后台消费落库，在「报错汇总」页统一查看，
-- 免去逐台翻 nginx error.log 的烦恼。
-- 防洪设计（worker 本地，不加锁）：
--   1) 同签名去重：相同 level|source|message 在 dedup_window 秒内只上报一次；
--   2) 限速：每分钟最多 max_per_min 条，超出丢弃（本地 ngx.log 不受影响）；
--   3) 上报走 ngx.timer.at 异步，不阻塞请求处理；Redis 失败静默（不影响业务）。

local config = require "config"
local cjson  = require "cjson"

local _M = {}

local KEY         = (config.errlog and config.errlog.redis_key) or "waf:error:list"
local MAX_MSG_LEN = 2000

-- 判定是否应上报（纯逻辑，独立出来便于单测）
-- st: 状态表 {window_start, window_count, seen}；opts: {enabled, max_per_min, dedup_window}
function _M.should_report(st, opts, now, sig)
    if not opts.enabled then
        return false
    end
    local last = st.seen[sig]
    if last and (now - last) < opts.dedup_window then
        return false
    end
    if now - st.window_start >= 60 then
        st.window_start = now
        st.window_count = 0
        -- 惰性清理去重表（保留最近 5 分钟签名，防长驻 worker 内存膨胀）
        for k, v in pairs(st.seen) do
            if now - v > 300 then
                st.seen[k] = nil
            end
        end
    end
    if st.window_count >= opts.max_per_min then
        return false
    end
    return true
end

-- 组装上报记录（时间带本地时区偏移，与攻击事件格式一致）
function _M.build_record(level, source, msg, extra)
    local now  = os.time()
    local utc  = os.time(os.date("!*t", now))
    local diff = os.difftime(now, utc)
    local sign = diff < 0 and "-" or "+"
    local a    = math.abs(diff)
    local tz   = string.format("%s%02d:%02d", sign, math.floor(a / 3600), math.floor((a % 3600) / 60))

    msg = tostring(msg or "")
    if #msg > MAX_MSG_LEN then
        msg = msg:sub(1, MAX_MSG_LEN)
    end
    extra = extra or {}
    return {
        time           = os.date("%Y-%m-%dT%H:%M:%S") .. tz,
        level          = level,
        source         = source or "",
        message        = msg,
        req_id         = extra.req_id or "",
        client_ip      = extra.client_ip or "",
        host           = extra.host or "",
        uri            = extra.uri or "",
        engine_version = config.version or "",
    }
end

-- worker 本地状态与配置快照
local st   = { window_start = 0, window_count = 0, seen = {} }
local opts = {
    enabled      = not (config.errlog and config.errlog.enabled == false),
    max_per_min  = (config.errlog and config.errlog.max_per_min) or 60,
    dedup_window = (config.errlog and config.errlog.dedup_window) or 10,
}

-- 上报一条错误（level: "error" | "warn"）
function _M.report(level, source, msg, extra)
    if not opts.enabled then
        return
    end
    local sig = level .. "|" .. (source or "") .. "|" .. tostring(msg)
    local now = ngx.now()
    if not _M.should_report(st, opts, now, sig) then
        return
    end
    st.seen[sig]       = now
    st.window_count    = st.window_count + 1

    local rec = _M.build_record(level, source, msg, extra)
    -- pcall 保护：init_by_lua 阶段 timer 不可用时不抛错（仅放弃上报）
    local ok, err = pcall(ngx.timer.at, 0, function(premature)
        if premature then return end
        local storage = require "storage"
        storage.redis_lpush(KEY, cjson.encode(rec))
    end)
    if not ok then
        -- timer 不可用（如 init_by_lua 阶段）仅放弃上报，本地日志不受影响
        ngx.log(ngx.ERR, "[waf] 错误上报调度失败: ", tostring(err))
    end
end

-- 便捷入口：本地日志 + 上报（各模块以 errlog.err("access", "...") 替代裸 ngx.log）
function _M.err(source, msg, extra)
    ngx.log(ngx.ERR, "[waf] ", msg)
    _M.report("error", source, msg, extra)
end

function _M.warn(source, msg, extra)
    ngx.log(ngx.WARN, "[waf] ", msg)
    _M.report("warn", source, msg, extra)
end

return _M
