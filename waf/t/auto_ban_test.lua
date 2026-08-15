-- waf/t/auto_ban_test.lua
-- detectors/auto_ban 高频攻击自动封禁单测

local t = require "assert"
local auto_ban = require "detectors.auto_ban"

local function base_cfg(over)
    local c = {
        auto_ban = {
            enabled = true, threshold = 3, window = 60, duration = 300,
            ban_key_prefix = "waf:ab:ban:", counter_prefix = "waf:ab:cnt:",
        },
    }
    if over then
        for k, v in pairs(over) do
            c.auto_ban[k] = v
        end
    end
    return c
end

t.test("未启用返回 false 且不计数", function()
    ngx_reset()
    local c = base_cfg({ enabled = false })
    t.no(auto_ban.is_banned(c, "1.2.3.4"))
    t.no(auto_ban.record_hit(c, "1.2.3.4"))
end)

t.test("阈值内不封禁", function()
    ngx_reset()
    local c = base_cfg()
    t.no(auto_ban.record_hit(c, "1.2.3.4"))
    t.no(auto_ban.record_hit(c, "1.2.3.4"))
    t.no(auto_ban.is_banned(c, "1.2.3.4"))
end)

t.test("达到阈值触发封禁", function()
    ngx_reset()
    local c = base_cfg()
    auto_ban.record_hit(c, "1.2.3.4")
    auto_ban.record_hit(c, "1.2.3.4")
    t.ok(auto_ban.record_hit(c, "1.2.3.4"), "第 3 次触发封禁")
    t.ok(auto_ban.is_banned(c, "1.2.3.4"), "封禁期内 is_banned 为 true")
    t.no(auto_ban.is_banned(c, "9.9.9.9"), "其他 IP 不受影响")
end)

t.test("不同 IP 独立计数", function()
    ngx_reset()
    local c = base_cfg()
    auto_ban.record_hit(c, "1.2.3.4")
    auto_ban.record_hit(c, "5.6.7.8")
    t.no(auto_ban.is_banned(c, "1.2.3.4"))
    t.no(auto_ban.is_banned(c, "5.6.7.8"))
end)

t.test("封禁到期后自动解除", function()
    ngx_reset()
    local c = base_cfg()
    auto_ban.record_hit(c, "1.2.3.4")
    auto_ban.record_hit(c, "1.2.3.4")
    auto_ban.record_hit(c, "1.2.3.4")
    t.ok(auto_ban.is_banned(c, "1.2.3.4"))
    -- 模拟封禁键过期
    ngx.shared.waf_counter:_expire_at("waf:ab:ban:1.2.3.4", 0)
    t.no(auto_ban.is_banned(c, "1.2.3.4"), "过期后解除")
end)

t.test("无 ip 不计数不封禁", function()
    ngx_reset()
    local c = base_cfg()
    t.no(auto_ban.record_hit(c, ""))
    t.no(auto_ban.is_banned(c, ""))
end)

t.test("无配置安全返回", function()
    ngx_reset()
    t.no(auto_ban.record_hit({}, "1.2.3.4"))
    t.no(auto_ban.is_banned({}, "1.2.3.4"))
end)
