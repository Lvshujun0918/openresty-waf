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
--   "blocked"  已阻断（access：响应已发出；header_filter：状态码已改待 body_filter 替换响应体）
--   "accepted" 放行并跳过后续规则
--   "score"    累加异常分
--   "logged"   监控模式仅记录
--   nil        无阻断动作
-- phase: access / header_filter / body_filter。
--   header_filter 阶段禁用 ngx.exit：BLOCK 改为改状态码 + response_block 标记；
--   body_filter 阶段响应头已发送：BLOCK 仅标记 response_block（body_filter.lua 替换响应体）。
function _M.execute(waf_ctx, action, rule, phase)
    local disrupt = action.disrupt
    if not disrupt then
        return nil
    end

    local mode = waf_ctx.mode or "active"

    if disrupt == "BLOCK" then
        if mode == "active" then
            local status = tonumber(action.status) or 403
            local cfg = get_config()
            local html = cfg.block and cfg.block.html or "Forbidden"
            if status == 444 then
                -- 444：直接关闭连接（响应阶段无法关闭，仅标记清空响应体）
                if phase == "access" then
                    waf_ctx._exited = true
                    ngx.exit(444)
                end
                waf_ctx.response_block = ""
                return "blocked"
            end
            if phase == "access" then
                ngx.status = status
                ngx.header.content_type = "text/html; charset=utf-8"
                ngx.say(html)
                waf_ctx._exited = true
                ngx.exit(status)
            elseif phase == "header_filter" then
                -- 改响应状态码，去掉 Content-Length（响应体将被替换，长度变化）
                ngx.status = status
                ngx.header.content_type = "text/html; charset=utf-8"
                ngx.header.content_length = nil
                waf_ctx.response_block = html
            else
                -- body_filter：响应头已发出，仅替换响应体
                waf_ctx.response_block = html
            end
            return "blocked"
        end
        return "logged"

    elseif disrupt == "DROP" then
        if mode == "active" then
            if phase == "access" then
                waf_ctx._exited = true
                ngx.exit(444)
            end
            -- 响应阶段：清空响应体
            waf_ctx.response_block = ""
        end
        return "logged"

    elseif disrupt == "ACCEPT" then
        return "accepted"

    elseif disrupt == "ALLOW" then
        -- 放行：不拦截（配合高 salience 可覆盖低优先级拦截规则）
        return "accepted"

    elseif disrupt == "REDIRECT" then
        -- ngx.redirect 仅 access 阶段可用
        if mode == "active" and phase == "access" then
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
