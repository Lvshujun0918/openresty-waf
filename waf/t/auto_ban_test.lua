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

t.test("auto_ban: 第3次封禁升级为 IP+UA 条目", function()
    ngx_reset()
    ngx.var.http_user_agent = "python-requests/2.31"
    local cfg = { auto_ban = { enabled = true, threshold = 1, window = 60, duration = 600,
        ban_key_prefix = "waf:ab:ban:", counter_prefix = "waf:ab:cnt:" } }
    local ab = auto_ban
    -- 3 次触发（不 reset shared dict，保证封禁次数累积）
    for i = 1, 3 do
        ab.record_hit(cfg, "10.1.1.1")
    end
    local val = ngx.shared.waf_counter:get("waf:ab:ban:10.1.1.1")
    t.notnil(val)
    local ip, ua, ts = tostring(val):match("^([^|]+)|([^|]+)|(%d+)$")
    t.notnil(ip, "升级条目格式 ip|ua|ts: " .. tostring(val))
    t.eq(ip, "10.1.1.1")
    t.eq(ua, "python-requests/2.31")
    -- 白名单/免升级：UA 含 | 时保持 IP 级
end)

t.test("auto_ban: 第1次封禁为 IP 级", function()
    ngx_reset()
    ngx.var.http_user_agent = "curl/8.5.0"
    local cfg = { auto_ban = { enabled = true, threshold = 1, window = 60, duration = 600,
        ban_key_prefix = "waf:ab:ban:", counter_prefix = "waf:ab:cnt:" } }
    local ab = auto_ban
    ab.record_hit(cfg, "10.1.1.2")
    local val = ngx.shared.waf_counter:get("waf:ab:ban:10.1.1.2")
    t.notnil(val)
    local ip, ts = tostring(val):match("^([^|]+)|(%d+)$")
    t.eq(ip, "10.1.1.2")
end)
