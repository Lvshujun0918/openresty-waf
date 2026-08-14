-- rule_engine/actions.lua
-- 动作执行：BLOCK / DROP / ACCEPT / REDIRECT / SCORE / LOG_ONLY

local _M = {}

-- 读取当前生效配置：
-- 优先复用规则引擎的版本化配置缓存（攻击场景每次拦截都要取拦截页配置，
-- 直接解码 JSON 代价高）；引擎未加载（单独使用本模块）时回退共享内存直读。
-- 注意：不能用 require "rule_engine.engine"（引擎加载本模块时会造成循环加载），
-- 通过 package.loaded 在运行时查找已加载的引擎。
local function get_config()
    local engine = package.loaded["rule_engine.engine"]
    if engine and engine.get_active_config then
        return engine.get_active_config()
    end
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
                -- 444: 直接关闭连接（标记已 exit，供外层 fail-open 区分拦截与异常）
                waf_ctx._exited = true
                ngx.exit(444)
            end
            local cfg = get_config()
            ngx.status = status
            ngx.header.content_type = "text/html; charset=utf-8"
            ngx.say(cfg.block and cfg.block.html or "Forbidden")
            waf_ctx._exited = true
            ngx.exit(status)
        end
        return "logged"

    elseif disrupt == "DROP" then
        if mode == "active" then
            waf_ctx._exited = true
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
