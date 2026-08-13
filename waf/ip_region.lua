-- ip_region.lua
-- IP 地理位置查询（ip2region xdb，纯 Lua 实现，无需外部 .so）。
--
-- 兼容 xdb v2 / v3 两种结构（官方新版文件名为 ip2region_v4.xdb / ip2region_v6.xdb）：
--   v2: Header 16B，version=2，ptr_bytes=4
--   v3: Header 256B，version=3，@16=ip_version(u16 LE)，@18=runtime_ptr_bytes(u16 LE)
--   Vector index: 固定 256*256 项 x 8B（小端），每项 [start_ptr, end_ptr] 指向 segment 区间
--   Segment index: start_ip(LE 4B)+end_ip(LE 4B)+data_len(LE 2B)+data_ptr(ptr_bytes LE)
--   Data: 国家|省份|城市|ISP|iso-alpha2-code （v3 官方数据格式）
-- 注意：文件内 IP 与指针均为小端序。
--
-- 数据文件：容器内固定路径（不随 /opt/waf 下发，避免多节点下发配置复杂）
-- 部署：将 ip2region_v4.xdb 放入引擎容器该路径（docker cp）；容器重建后需重新放置

local _M = {}

local IP_REGION_FILE = "/usr/local/openresty/nginx/conf/ip2region_v4.xdb"

local _raw        = nil   -- 文件全部字节
local _header_len = 0     -- 16 (v2) / 256 (v3)
local _ptr_bytes  = 4     -- 指针字节数（v3 可能 8）
local _loaded     = false
local _load_err   = nil

-- 读小端 u16/u32（off 为 1-based 起始）
local function read_u16_le(s, off)
    local b1, b2 = s:byte(off), s:byte(off + 1)
    if not (b1 and b2) then return nil end
    return b1 + b2 * 0x100
end

local function read_u32_le(s, off)
    local b1, b2, b3, b4 = s:byte(off), s:byte(off + 1), s:byte(off + 2), s:byte(off + 3)
    if not (b1 and b2 and b3 and b4) then return nil end
    return b1 + b2 * 0x100 + b3 * 0x10000 + b4 * 0x1000000
end

-- 读小端 IP（4 字节）并转换为大端数值（用于与 ip_to_uint32 比较）
local function read_ip_le(s, off)
    local b1, b2, b3, b4 = s:byte(off), s:byte(off + 1), s:byte(off + 2), s:byte(off + 3)
    if not (b1 and b2 and b3 and b4) then return nil end
    return b4 * 0x1000000 + b3 * 0x10000 + b2 * 0x100 + b1
end

-- 读 data_ptr（按 ptr_bytes，小端）
local function read_ptr(s, off, n)
    local v = 0
    for i = 0, n - 1 do
        local b = s:byte(off + i)
        if not b then return nil end
        v = v + b * (0x100 ^ i)
    end
    return v
end

-- IPv4 字符串 -> 大端 uint32
local function ip_to_uint32(ip)
    if type(ip) ~= "string" then return nil end
    local a, b, c, d = ip:match("^(%d+)%.(%d+)%.(%d+)%.(%d+)$")
    if not a then return nil end
    a, b, c, d = tonumber(a), tonumber(b), tonumber(c), tonumber(d)
    if a and b and c and d and a <= 255 and b <= 255 and c <= 255 and d <= 255 then
        return a * 0x1000000 + b * 0x10000 + c * 0x100 + d
    end
    return nil
end

-- 加载 xdb 文件（init 阶段调用）
local function load(path)
    local f, err = io.open(path, "rb")
    if not f then
        _load_err = "无法打开 " .. path .. ": " .. tostring(err)
        return false
    end
    local data = f:read("*a")
    f:close()
    if not data or #data < 32 then
        _load_err = "ip2region xdb 文件过小或为空"
        return false
    end

    local version = read_u16_le(data, 1)  -- @0
    if version == 2 then
        _header_len = 16
        _ptr_bytes  = 4
    elseif version == 3 then
        _header_len = 256
        local pb = read_u16_le(data, 19)  -- @18 runtime_ptr_bytes
        if pb == 4 or pb == 8 then
            _ptr_bytes = pb
        else
            _load_err = "ip2region xdb 指针字节数异常: " .. tostring(pb)
            return false
        end
    else
        _load_err = "ip2region xdb 结构版本不受支持: " .. tostring(version)
        return false
    end

    -- vector index 起始 = header 长度；固定 256*256*8 字节
    if _header_len + 256 * 256 * 8 + 14 > #data then
        _load_err = "ip2region xdb 缺少 vector/segment index"
        return false
    end

    _raw = data
    _loaded = true
    return true
end

-- 在 segment index 二分查找（l/r 为 0-based 绝对偏移，步长 = 4+4+2+ptr_bytes）
local function search(ip_uint)
    local s = _raw
    local step = 4 + 4 + 2 + _ptr_bytes
    local il0 = math.floor(ip_uint / 0x1000000)          -- 第一段
    local il1 = math.floor((ip_uint / 0x10000) % 0x100)  -- 第二段
    local idx = il0 * 256 + il1
    local vpos = _header_len + idx * 8                    -- vector entry 0-based 偏移
    local sPtr = read_u32_le(s, vpos + 1)
    local ePtr = read_u32_le(s, vpos + 5)
    if not sPtr or not ePtr or (sPtr == 0 and ePtr == 0) then
        return nil
    end

    local l, r = sPtr, ePtr
    while l <= r do
        local mid = math.floor((l + r) / 2)
        local mid_ptr = mid - (mid - sPtr) % step         -- 对齐 segment 起始
        if mid_ptr < sPtr then mid_ptr = sPtr end

        local s_ip = read_ip_le(s, mid_ptr + 1)
        local e_ip = read_ip_le(s, mid_ptr + 5)
        local dlen = read_u16_le(s, mid_ptr + 9)
        local dptr = read_ptr(s, mid_ptr + 11, _ptr_bytes)

        if s_ip and e_ip and ip_uint >= s_ip and ip_uint <= e_ip then
            if dptr and dlen and dlen > 0 and dptr + dlen <= #s then
                return s:sub(dptr + 1, dptr + dlen)
            end
            return nil
        elseif s_ip and ip_uint < s_ip then
            r = mid_ptr - step
        else
            l = mid_ptr + step
        end
    end
    return nil
end

-- 解析 region：v3 = 国家|省份|城市|ISP|iso-alpha2-code；v2 legacy = 国家|区域|省份|城市|ISP
local function parse_region(region)
    if not region or region == "" then return nil end
    local parts = {}
    for p in region:gmatch("[^|]+") do
        parts[#parts + 1] = p
    end
    local function clean(v)
        v = v or ""
        if v == "0" or v == "" then return "" end
        return v
    end
    local country = clean(parts[1])
    local province, city = "", ""
    local p2, p3 = clean(parts[2]), clean(parts[3])
    if p2 ~= "" and p2 ~= country then
        province = p2  -- v3 省份
        city = p3
    else
        city = p2 or p3  -- v2 legacy：跳过区域段
    end
    return {
        country  = country,
        province = province,
        city     = city,
        isp      = clean(parts[4]),
    }
end

-- 查询 IP 归属；返回 {country, province, city, isp}；不可用/失败返回 nil
function _M.lookup(ip)
    if not _loaded then return nil end
    local u = ip_to_uint32(ip)
    if not u then return nil end
    local region = search(u)
    if not region then return nil end
    return parse_region(region)
end

-- 数据是否已加载可用
function _M.available()
    return _loaded
end

-- 加载失败原因（调试用）
function _M.load_error()
    return _load_err
end

-- init 阶段加载（nginx init_by_lua 调用；失败不阻断启动）
function _M.init(path)
    _loaded = load(path or IP_REGION_FILE)
    return _loaded
end

return _M
