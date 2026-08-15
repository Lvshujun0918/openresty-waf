-- header_filter.lua
-- header_filter_by_lua 响应阶段检测（可选）。
--
-- nginx.conf:
--   header_filter_by_lua_file /opt/waf/header_filter.lua;
--
-- 说明：响应阶段的变量集合（RESPONSE_HEADERS / RESPONSE_BODY 等）尚未实现，
-- 当前仅执行 header_filter 阶段规则作为骨架；规则命中信息继续写入 ctx.matched，
-- 由 log 阶段统一落盘。

local engine = require "rule_engine.engine"

local ctx = ngx.ctx.waf_ctx
if not ctx then
    ctx = {
        mode    = "active",
        score   = 0,
        matched = {},
    }
    ngx.ctx.waf_ctx = ctx
end

local phase_rules = engine.get_phase_rules("header_filter")
if phase_rules and #phase_rules > 0 then
    -- fail-open：检测异常不阻断响应，记录错误后继续
    local ok, err = pcall(engine.run, { rules = phase_rules }, "header_filter", ctx)
    if not ok and not ctx._exited then
        ngx.log(ngx.ERR, "[waf] header_filter 检测异常，fail-open: ", tostring(err))
    end
end
