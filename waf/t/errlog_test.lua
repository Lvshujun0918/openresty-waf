-- waf/t/errlog_test.lua
-- 错误汇总上报：限速/去重判定 / 记录组装 / 开关

local t      = require "assert"
local errlog = require "errlog"

-- ---------------------------------------------------------------------------
-- should_report：开关 / 去重 / 限速
-- ---------------------------------------------------------------------------

t.test("should_report: 禁用开关直接拒绝", function()
    local st   = { window_start = 0, window_count = 0, seen = {} }
    local opts = { enabled = false, max_per_min = 10, dedup_window = 5 }
    t.no(errlog.should_report(st, opts, 100, "s1"))
end)

t.test("should_report: 同签名去重窗口内拒绝", function()
    local st   = { window_start = 0, window_count = 0, seen = { s1 = 95 } }
    local opts = { enabled = true, max_per_min = 10, dedup_window = 10 }
    t.no(errlog.should_report(st, opts, 100, "s1"))   -- 距上次 5s < 10s
    t.ok(errlog.should_report(st, opts, 106, "s1"))   -- 距上次 11s，窗口已过
end)

t.test("should_report: 不同签名互不影响", function()
    local st   = { window_start = 0, window_count = 0, seen = { s1 = 95 } }
    local opts = { enabled = true, max_per_min = 10, dedup_window = 10 }
    t.ok(errlog.should_report(st, opts, 100, "s2"))
end)

t.test("should_report: 每分钟限速", function()
    local st   = { window_start = 0, window_count = 60, seen = {} }
    local opts = { enabled = true, max_per_min = 60, dedup_window = 10 }
    t.no(errlog.should_report(st, opts, 30, "sx"))
end)

t.test("should_report: 窗口滚动重置计数并清理过期签名", function()
    local st   = { window_start = 0, window_count = 60, seen = { old = 1 } }
    local opts = { enabled = true, max_per_min = 60, dedup_window = 10 }
    -- now=61：距 window_start 61s >= 60 → 重置窗口；old 签名(=1) 距今 60s > 300? 否，保留
    t.ok(errlog.should_report(st, opts, 61, "sy"))
    t.eq(st.window_count, 0)
    t.notnil(st.seen.old)
    -- now=400：old(=1) 距今 399s > 300 → 清理
    local st2   = { window_start = 0, window_count = 60, seen = { old = 1 } }
    t.ok(errlog.should_report(st2, opts, 400, "sz"))
    t.isnil(st2.seen.old)
end)

-- ---------------------------------------------------------------------------
-- build_record：字段组装 / 截断
-- ---------------------------------------------------------------------------

t.test("build_record: 基本字段与 extra 透传", function()
    local rec = errlog.build_record("error", "access", "规则引擎执行异常 fail-open",
        { req_id = "1-2-3-4", host = "a.com", uri = "/x?y=1" })
    t.eq(rec.level, "error")
    t.eq(rec.source, "access")
    t.eq(rec.message, "规则引擎执行异常 fail-open")
    t.eq(rec.req_id, "1-2-3-4")
    t.eq(rec.host, "a.com")
    t.eq(rec.uri, "/x?y=1")
    t.match(rec.time, "^%d%d%d%d%-%d%d%-%d%dT%d%d:%d%d:%d%d[+-]%d%d:%d%d$")
    t.eq(type(rec.engine_version), "string")
end)

t.test("build_record: 缺省 extra 为空串", function()
    local rec = errlog.build_record("warn", "upload", "读取上传临时文件失败")
    t.eq(rec.req_id, "")
    t.eq(rec.host, "")
    t.eq(rec.uri, "")
end)

t.test("build_record: 超长消息截断到 2000", function()
    local big = string.rep("x", 3000)
    local rec = errlog.build_record("error", "engine", big)
    t.eq(#rec.message, 2000)
end)

t.test("build_record: 非字符串消息转字符串", function()
    local rec = errlog.build_record("warn", "cc", 12345)
    t.eq(rec.message, "12345")
end)
