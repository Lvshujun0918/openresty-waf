-- waf/t/ip_region_test.lua
-- ip_region 纯 Lua xdb 解析器单测（合成 xdb 文件验证完整解析链路）

local t = require "assert"
local ip_region = require "ip_region"

-- ---- 合成 xdb 生成器 ----
local function be16(v)
    return string.char(math.floor(v / 0x100) % 0x100, v % 0x100)
end
local function be32(v)
    return string.char(
        math.floor(v / 0x1000000) % 0x100,
        math.floor(v / 0x10000) % 0x100,
        math.floor(v / 0x100) % 0x100,
        v % 0x100)
end
local function ip2u(ip)
    local a, b, c, d = ip:match("^(%d+)%.(%d+)%.(%d+)%.(%d+)$")
    return a * 0x1000000 + b * 0x10000 + c * 0x100 + d
end
-- segs: {{start_ip, end_ip, region}, ...}
local function build_xdb(segs)
    table.sort(segs, function(a, b) return ip2u(a[1]) < ip2u(b[1]) end)
    local VEC = 256 * 256
    local vec_len = VEC * 8
    local seg_start = 16 + vec_len
    local n = #segs
    local segs_buf, data_buf, dsum = {}, {}, 0
    for i, sg in ipairs(segs) do
        local dptr = seg_start + n * 14 + dsum
        segs_buf[i] = be32(ip2u(sg[1])) .. be32(ip2u(sg[2])) .. be16(#sg[3]) .. be32(dptr)
        data_buf[i] = sg[3]
        dsum = dsum + #sg[3]
    end
    -- vector index：全部指向完整 segment 区（功能正确，测试不模拟分段优化）
    local vec = {}
    local s, e = seg_start, seg_start + n * 14 - 14
    for i = 1, VEC do
        vec[i] = be32(s) .. be32(e)
    end
    local header = be32(2) .. be32(1) .. be32(0) .. be32(vec_len)
    return header .. table.concat(vec) .. table.concat(segs_buf) .. table.concat(data_buf)
end

local tmp = "/tmp/test_ip2region.xdb"
local xdb = build_xdb({
    { "8.8.8.0",   "8.8.8.255",   "美国|0|0|0|Level3" },
    { "1.0.0.0",   "1.0.0.255",   "中国|0|北京|北京|电信" },
    { "223.5.5.0", "223.5.5.255", "中国|0|浙江|杭州|阿里云" },
})
local f = io.open(tmp, "wb")
f:write(xdb)
f:close()

t.test("init 加载合成 xdb", function()
    t.ok(ip_region.init(tmp))
    t.ok(ip_region.available())
end)

t.test("lookup: 命中国外段", function()
    local g = ip_region.lookup("8.8.8.8")
    t.ok(g, "应返回归属")
    t.eq(g.country, "美国")
    t.eq(g.province, "")
end)

t.test("lookup: 命中国内段（含省市）", function()
    local g = ip_region.lookup("223.5.5.66")
    t.ok(g)
    t.eq(g.country, "中国")
    t.eq(g.province, "浙江")
    t.eq(g.city, "杭州")
end)

t.test("lookup: 另一国内段", function()
    local g = ip_region.lookup("1.0.0.1")
    t.ok(g)
    t.eq(g.country, "中国")
    t.eq(g.province, "北京")
end)

t.test("lookup: 未覆盖 IP 返回 nil", function()
    t.isnil(ip_region.lookup("9.9.9.9"))
    t.isnil(ip_region.lookup("100.100.100.100"))
end)

t.test("lookup: 非法输入返回 nil", function()
    t.isnil(ip_region.lookup("not-an-ip"))
    t.isnil(ip_region.lookup(""))
    t.isnil(ip_region.lookup(nil))
    t.isnil(ip_region.lookup("1.2.3"))
    t.isnil(ip_region.lookup("999.1.1.1"))
end)

t.test("文件缺失时优雅降级", function()
    local ok = ip_region.init("/tmp/definitely_no_such.xdb")
    t.no(ok)
    t.no(ip_region.available())
    t.isnil(ip_region.lookup("8.8.8.8"))
    t.notnil(ip_region.load_error())
end)
