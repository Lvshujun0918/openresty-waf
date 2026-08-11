-- ip_region.lua
-- IP 地理位置查询（ip2region xdb v2，纯 Lua 实现，无需外部 .so）。
--
-- 数据文件：/opt/waf/ip2region.xdb（由用户/安装脚本放置；缺失时 available=false 优雅降级）
-- 加载时机：init 阶段调用 _M.init()，文件整体读入内存（buffer 模式，约 11MB）。
-- 查询：microsecond 级（vector index 定位 + 二分），在 log 阶段使用不影响请求转发。
--
-- xdb v2 格式（big-endian）：
--   Header(16B): version(4) | index_policy(4) | created_at(4) | vector_index_len(4)
--   Vector index: 256*256 项 x 8B，每项 [start_ptr(4), end_ptr(4)] 指向 segment 区间
--   Segment index: 每项 14B = start_ip(4)+end_ip(4)+data_len(2)+data_ptr(4)
--   Data: 国家|区域|省份|城市|ISP  （legacy 格式）

local _M = {}

local IP_REGION_DEFAULT_FILE = "/opt/waf/ip2region.xdb"

local _raw       = nil   -- 文件全部字节
local _vec_start = 16
local _vec_len   = 0
local _seg_start = 0
local _loaded    = false
local _load_err  = nil

-- 读大端 u32（off 为 1-based 起始）
local function read_u32(s, off)
    local b1 = s:byte(off)
    local b2 = s:byte(off + 1)
    local b3 = s:byte(off + 2)
    local b4 = s:byte(off + 3)
    if not (b1 and b2 and b3 and b4) then return nil end
    return b1 * 0x1000000 + b2 * 0x10000 + b3 * 0x100 + b4
end

-- IPv4 字符串 -> uint32
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

-- 加载 xdb 文件（init 阶段调用；path 缺省用默认文件）
local function load(path)
    local f, err = io.open(path, "rb")
    if not f then
        _load_err = "无法打开 " .. path .. ": " .. tostring(err)
        return false
    end
    local data = f:read("*a")
    f:close()
    if not data or #data < 16 then
        _load_err = "ip2region.xdb 文件过小或为空"
        return false
    end
    local vec_len = read_u32(data, 13)
    if not vec_len or vec_len <= 0 then
        _load_err = "ip2region.xdb 头部解析失败"
        return false
    end
    _raw       = data
    _vec_len   = vec_len
    _seg_start = _vec_start + vec_len
    if _seg_start + 14 > #data then
        _load_err = "ip2region.xdb 缺少 segment index"
        return false
    end
    _loaded = true
    return true
end

-- 在 segment index 二分查找
local function search(ip_uint)
    local s = _raw
    local il0 = math.floor(ip_uint / 0x1000000)          -- 第一段
    local il1 = math.floor((ip_uint / 0x10000) % 0x100)  -- 第二段
    local vidx = il0 * 256 + il1
    local vpos = _vec_start + vidx * 8
    if vpos + 8 > _seg_start then return nil end
    local start_ptr = read_u32(s, vpos + 1)
    local end_ptr   = read_u32(s, vpos + 5)
    if not start_ptr or not end_ptr or (start_ptr == 0 and end_ptr == 0) then
        return nil
    end

    local l, r = start_ptr, end_ptr
    while l <= r do
        local mid = math.floor((l + r) / 2)
        local mid_ptr = mid - (mid - start_ptr) % 14  -- 对齐到 segment 起始（14B）
        if mid_ptr < start_ptr then mid_ptr = start_ptr end

        local s_ip = read_u32(s, mid_ptr + 1)
        local e_ip = read_u32(s, mid_ptr + 5)
        local dlen = (s:byte(mid_ptr + 9) or 0) * 0x100 + (s:byte(mid_ptr + 10) or 0)
        local dptr = read_u32(s, mid_ptr + 11)

        if s_ip and e_ip and ip_uint >= s_ip and ip_uint <= e_ip then
            if dptr and dlen > 0 and dptr + dlen <= #s then
                return s:sub(dptr + 1, dptr + dlen)
            end
            return nil
        elseif s_ip and ip_uint < s_ip then
            r = mid_ptr - 14
        else
            l = mid_ptr + 14
        end
    end
    return nil
end

-- 解析 region：legacy = 国家|区域|省份|城市|ISP
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
    return {
        country  = clean(parts[1]),
        province = clean(parts[3]),
        city     = clean(parts[4]),
        isp      = clean(parts[5]),
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
    _loaded = load(path or IP_REGION_DEFAULT_FILE)
    return _loaded
end

return _M
