-- rule_perf.lua
-- 规则耗时画像：worker 内聚合每条规则的评估次数与耗时（µs），
-- 定时批量 LPUSH 到 Redis（默认 waf:ruleperf:list），由管理后台消费聚合落库。
--
-- 时钟：优先 FFI clock_gettime(CLOCK_MONOTONIC)（µs 精度）；
-- FFI 不可用时回退 ngx.now()（ms 精度，单次读数误差 ≤1ms，累计均值仍具相对参考价值）。

local _M = {}

local config  = require "config"
local storage = require "storage"
local cjson   = require "cjson.safe"

local now_us
do
    local ok, ffi = pcall(require, "ffi")
    if ok and ffi then
        local ok2 = pcall(ffi.cdef, [[
            typedef struct { long tv_sec; long tv_nsec; } waf_timespec;
            int clock_gettime(int clk_id, waf_timespec *tp);
        ]])
        if ok2 then
            local ts = ffi.new("waf_timespec")
            -- Linux CLOCK_MONOTONIC = 1
            now_us = function()
                if ffi.C.clock_gettime(1, ts) == 0 then
                    return tonumber(ts.tv_sec) * 1000000 + tonumber(ts.tv_nsec) / 1000
                end
                return ngx.now() * 1000000
            end
        end
    end
end
if not now_us then
    now_us = function()
        return ngx.now() * 1000000
    end
end
_M.now_us = now_us

-- worker 本地聚合：rule_id -> { n, total_us, max_us }
local stats = {}

-- 记录一次规则评估耗时（µs）
function _M.record(rule_id, cost_us)
    if not rule_id or not cost_us or cost_us < 0 then
        return
    end
    local s = stats[rule_id]
    if not s then
        s = { n = 0, total_us = 0, max_us = 0 }
        stats[rule_id] = s
    end
    s.n = s.n + 1
    s.total_us = s.total_us + cost_us
    if cost_us > s.max_us then
        s.max_us = cost_us
    end
end

-- 当前聚合快照（测试用）
function _M.pending()
    return stats
end

-- 清空聚合（测试用）
function _M.reset()
    stats = {}
end

-- 定时上报回调：整体快照后打包为一条 JSON 数组 LPUSH（单次连接开销）
local function flush(premature)
    if premature then
        return
    end
    local snapshot = stats
    stats = {}
    local arr = {}
    local ts = ngx.time()
    for rule_id, s in pairs(snapshot) do
        arr[#arr + 1] = {
            id       = tostring(rule_id),
            n        = s.n,
            total_us = math.floor(s.total_us),
            max_us   = math.floor(s.max_us),
            time     = ts,
        }
    end
    if #arr == 0 then
        return
    end
    local payload = cjson.encode(arr)
    if payload then
        storage.redis_lpush(config.rule_perf.redis_key, payload)
    end
end

-- init_worker 阶段启动定时上报
function _M.start_timer()
    if not config.rule_perf or config.rule_perf.enabled == false then
        return
    end
    local interval = config.rule_perf.interval or 60
    local ok, err = ngx.timer.every(interval, flush)
    if not ok then
        ngx.log(ngx.ERR, "[waf] 启动规则耗时上报定时器失败: " .. tostring(err))
    end
end

return _M
