-- body_filter.lua
-- body_filter_by_lua 响应体阶段入口：
--   1) header_filter 阶段已判定拦截 → 替换响应体为拦截页/清空并截断；
--   2) 累积响应体（上限 8KB），EOF 时运行 body_filter 阶段规则（响应体检测）。
--
-- nginx.conf:
--   body_filter_by_lua_file /opt/waf/body_filter.lua;

local engine = require "rule_engine.engine"

local ctx = ngx.ctx.waf_ctx
if not ctx then
    return
end

-- access 阶段已拦截（BLOCK 的 ngx.exit 被 pcall 捕获后 nginx 仍会走 body_filter）：
-- 响应体就是拦截页本身，跳过检测。
if ctx._exited then
    return
end

-- 1. header_filter/body_filter 阶段判定拦截：首个 chunk 替换为拦截页（空串则清空），
--    后续 chunk 截断
if ctx.response_block ~= nil then
    if not ctx._resp_block_sent then
        ctx._resp_block_sent = true
        ngx.arg[1] = ctx.response_block
    else
        ngx.arg[1] = nil
    end
    return
end

-- 2. 累积响应体（截断到 8KB，防大响应撑爆内存）
local chunk = ngx.arg[1]
if chunk and #chunk > 0 then
    ctx.resp_body = (ctx.resp_body or "") .. chunk
    if #ctx.resp_body > 8192 then
        ctx.resp_body = ctx.resp_body:sub(1, 8192)
    end
end

-- EOF：运行 body_filter 阶段规则（一次），命中则替换最后 chunk 为拦截页
if ngx.arg[2] and not ctx._resp_detected then
    ctx._resp_detected = true
    local host = (ctx.request and ctx.request.host or ""):gsub(":%d+$", "")
    local ruleset = engine.get_rules_for_host(host)
    if ruleset then
        -- fail-open：响应体检测异常不影响业务，记录错误后原样返回
        local ok, result = pcall(engine.run, ruleset, "body_filter", ctx)
        if not ok then
            ngx.log(ngx.ERR, "[waf] 响应体检测异常，fail-open: ", tostring(result))
        elseif result == "blocked" and ctx.response_block ~= nil then
            ngx.arg[1] = ctx.response_block
        end
    end
end
