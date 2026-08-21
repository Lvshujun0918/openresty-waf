-- waf/t/run.lua
-- WAF Lua 引擎单元测试入口
-- 用法（OpenResty 容器内）：
--   docker run --rm -v $PWD/waf:/waf openresty/openresty:alpine \
--     luajit /waf/t/run.lua

-- 模块查找路径：WAF 源码 + OpenResty lualib（cjson/resty.redis）
package.path = "/waf/?.lua;/waf/?/init.lua;/waf/t/?.lua;" .. package.path
package.path = "/usr/local/openresty/lualib/?.lua;/usr/local/openresty/lualib/?/init.lua;" .. package.path
-- C 模块（cjson.so 等）
package.cpath = "/usr/local/openresty/lualib/?.so;/usr/local/openresty/lualib/?.so.*;" .. package.cpath

-- 必须先加载 mock（建立全局 ngx），再加载被测模块
require "mock"
local t = require "assert"

dofile "/waf/t/operators_test.lua"
dofile "/waf/t/transforms_test.lua"
dofile "/waf/t/variables_test.lua"
dofile "/waf/t/util_test.lua"
dofile "/waf/t/ip_region_test.lua"
dofile "/waf/t/engine_test.lua"
dofile "/waf/t/rule_perf_test.lua"
dofile "/waf/t/hit_cache_test.lua"
dofile "/waf/t/canary_test.lua"
dofile "/waf/t/trigger_test.lua"
dofile "/waf/t/bot_test.lua"
dofile "/waf/t/cc_test.lua"
dofile "/waf/t/auto_ban_test.lua"
dofile "/waf/t/upload_test.lua"
dofile "/waf/t/challenge_test.lua"
dofile "/waf/t/storage_test.lua"
dofile "/waf/t/init_test.lua"
-- config 测试最后加载（依赖其它模块先 require 默认 config）
dofile "/waf/t/config_test.lua"

local ok = t.summary()
if not ok then
    print("\n有一些测试失败，请查看上方 [FAIL] 输出。")
end
os.exit(ok and 0 or 1)
