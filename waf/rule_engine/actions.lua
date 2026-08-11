-- rule_engine/actions.lua
-- 动作执行：BLOCK / DROP / ACCEPT / REDIRECT / SCORE / LOG_ONLY

local _M = {}

-- 读取当前生效配置（共享内存），失败则回退到模块默认配置
local function get_config()
    local config = require "config"
    local storage = require "storage"
    local body = storage.get_shared(config.dict.rules, "active_config")
    local cfg = storage.decode(body)
    if type(cfg) == "table" then
        return cfg
    end
    return config
end

-- 执行动作，返回结果标记：
--   "blocked"  已阻断（响应已发出）
--   "accepted" 放行并跳过后续规则
--   "score"    累加异常分
--   "logged"   监控模式仅记录
--   nil        无阻断动作
function _M.execute(waf_ctx, action, rule)
    local disrupt = action.disrupt
    if not disrupt then
        return nil
    end

    local mode = waf_ctx.mode or "active"

    if disrupt == "BLOCK" then
        if mode == "active" then
            local status = tonumber(action.status) or 403
            if status == 444 then
                -- 444: 直接关闭连接
                ngx.exit(444)
            end
            local cfg = get_config()
            ngx.status = status
            ngx.header.content_type = "text/html; charset=utf-8"
            ngx.say(cfg.block and cfg.block.html or "Forbidden")
            ngx.exit(status)
        end
        return "logged"

    elseif disrupt == "DROP" then
        if mode == "active" then
            ngx.exit(444)
        end
        return "logged"

    elseif disrupt == "ACCEPT" then
        return "accepted"

    elseif disrupt == "ALLOW" then
        -- 放行：不拦截（配合高 salience 可覆盖低优先级拦截规则）
        return "accepted"

    elseif disrupt == "REDIRECT" then
        if mode == "active" then
            ngx.redirect(action.location or "/", ngx.HTTP_MOVED_TEMPORARILY)
        end
        return "logged"

    elseif disrupt == "SCORE" then
        waf_ctx.score = (waf_ctx.score or 0) + (tonumber(action.value) or 1)
        return "score"
    end

    return nil
end

return _M
