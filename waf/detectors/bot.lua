-- detectors/bot.lua
-- 爬虫识别：UA 画像库 + 搜索引擎 IP 段验证，判定真实/虚假爬虫。
--
-- 画像结构（内置 + 后台发布，后台可覆盖）：
--   { name, ua（PCRE 正则）, ips = { "cidr" }, engine（true=搜索引擎类，需 IP 段验证） }
-- 判定：
--   - UA 命中 engine 类画像：client_ip 命中 ips → 真实爬虫；不命中 → 虚假爬虫（伪造）
--   - UA 命中工具类画像（curl/requests 等）：直接判定为爬虫（工具爬虫）
--   - 未命中：非爬虫
--
-- 后台发布：waf:bot:profiles + waf:bot:version（init.lua 轮询热更新，同触发规则机制）。

local _M = {}

local operators = require "rule_engine.operators"

-- 内置爬虫画像（搜索引擎类带 IP 段验证；工具类直接识别）。
-- IP 段为公开常用段，生产环境建议在后台画像库补充完整。
local builtin_profiles = {
    -- 搜索引擎类（IP 段验证）
    { name = "Googlebot", ua = [[Googlebot|Google-InspectionTool|Mediapartners-Google]], engine = true,
      ips = { "66.249.64.0/19", "64.233.160.0/19", "66.249.80.0/20", "216.58.192.0/19" } },
    { name = "Bingbot", ua = [[bingbot|adidxbot]], engine = true,
      ips = { "40.77.0.0/16", "157.55.0.0/16", "13.64.0.0/16", "52.160.0.0/11" } },
    { name = "Baiduspider", ua = [[Baiduspider]], engine = true,
      ips = { "220.181.108.0/24", "119.63.192.0/21", "123.125.68.0/24", "180.76.15.0/24", "116.179.32.0/19" } },
    { name = "Sogou", ua = [[Sogou.*spider|Sogou web spider]], engine = true,
      ips = { "61.135.162.0/24", "220.181.0.0/16" } },
    { name = "360Spider", ua = [[360Spider|haosouSpider]], engine = true,
      ips = { "60.191.0.0/16", "221.200.0.0/16", "180.163.220.0/24" } },
    { name = "YandexBot", ua = [[YandexBot|YandexImages|YaDirectFetcher]], engine = true,
      ips = { "77.88.0.0/18", "5.255.192.0/18", "213.180.192.0/19" } },
    { name = "bytespider", ua = [[bytespider]], engine = true,
      ips = { "108.160.160.0/19", "8.39.224.0/24" } },
    { name = "facebookexternalhit", ua = [[facebookexternalhit|Facebot]], engine = true,
      ips = { "69.171.224.0/19", "31.13.24.0/21" } },
    -- 工具/采集类（直接识别）
    { name = "curl", ua = [[^curl/]], engine = false },
    { name = "python-requests", ua = [[^python-requests/]], engine = false },
    { name = "Go-http-client", ua = [[^Go-http-client/]], engine = false },
    { name = "Java/OkHttp", ua = [[^Java/|OkHttp/]], engine = false },
    { name = "Scrapy", ua = [[Scrapy]], engine = false },
    { name = "Wget", ua = [[^Wget/]], engine = false },
    { name = "libwww-perl", ua = [[libwww-perl]], engine = false },
    { name = "AhrefsBot", ua = [[AhrefsBot]], engine = false },
    { name = "SemrushBot", ua = [[SemrushBot]], engine = false },
    { name = "MJ12bot", ua = [[MJ12bot]], engine = false },
    { name = "PetalBot", ua = [[PetalBot]], engine = false },
    { name = "Dataprovider", ua = [[Dataprovider]], engine = false },
    { name = "DuckDuckBot", ua = [[DuckDuckBot]], engine = false },
    { name = "exabot", ua = [[exabot]], engine = false },
}

-- 画像集：版本化缓存（后台发布 waf:bot:profiles，未发布时用内置表）
local profile_cache = { version = false, value = nil }

local function get_profiles()
    local storage = require "storage"
    local config = require "config"
    local version = storage.get_shared(config.dict.rules, "bot_profiles_version")
    if version == profile_cache.version and profile_cache.value ~= nil then
        return profile_cache.value
    end
    local body = storage.get_shared(config.dict.rules, "active_bot_profiles")
    local rs = storage.decode(body)
    if type(rs) == "table" and type(rs.profiles) == "table" then
        profile_cache.version = version
        profile_cache.value = rs.profiles
    else
        profile_cache.version = version
        profile_cache.value = builtin_profiles
    end
    return profile_cache.value
end

-- 判定请求是否为爬虫（及真实性）。
-- 返回 nil（非爬虫）或 { profile, engine, fake }。
-- fake=true 表示"虚假爬虫"：UA 声称搜索引擎但来源 IP 不在其公开网段。
function _M.classify(ctx)
    local ua = ngx.var.http_user_agent or ""
    if ua == "" then
        return nil
    end
    local ip = ctx and ctx.client_ip or ""
    local profiles = get_profiles()
    for _, p in ipairs(profiles) do
        if type(p) == "table" and type(p.ua) == "string" and p.ua ~= "" then
            local ok, res = pcall(ngx.re.find, ua, p.ua, "joi")
            if ok and res then
                if p.engine then
                    -- 搜索引擎类：校验来源 IP 段
                    local ip_hit = false
                    if type(p.ips) == "table" then
                        for _, cidr in ipairs(p.ips) do
                            if operators.eval("CIDR", ip, cidr) then
                                ip_hit = true
                                break
                            end
                        end
                    end
                    return { profile = p.name or "UnknownBot", engine = true, fake = not ip_hit }
                end
                return { profile = p.name or "UnknownBot", engine = false, fake = false }
            end
        end
    end
    return nil
end

-- 客户端 IP 是否命中恶意 IP 库（配置 blacklist.ips，含订阅合并）。
-- 供爬虫记录标记恶意来源。
function _M.is_malicious_ip(ctx)
    local ip = ctx and ctx.client_ip or ""
    if ip == "" then return false end
    local engine = require "rule_engine.engine"
    local cfg = engine.get_active_config()
    local bl = cfg and cfg.blacklist and cfg.blacklist.ips
    if type(bl) ~= "table" then return false end
    for _, entry in ipairs(bl) do
        local addr = tostring(entry):match("^([^|]+)")
        if addr and addr ~= "" and operators.eval("CIDR", ip, addr) then
            return true
        end
    end
    return false
end

return _M
